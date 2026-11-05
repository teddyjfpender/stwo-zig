//! Source-owned whole native CPU class before its first device allocation.
//! No proof, challenge, coefficient payload or receipt supplies this geometry.
//! Host estimates remain unknown; the explicit GPU-only policy records that.
const std = @import("std");
const core = @import("stwo_core");
const CPU = @import("stwo_riscv_cpu_integration");
const D = CPU.rv64_device_pcs;
const A = @import("global_admission.zig");
const Progress = @import("admission_progress.zig");
const SourceCost = @import("native_source_cost_adapter.zig");
const SourcePlan = @import("native_source_cost.zig");
const RC = @import("resident_composition.zig");
const Joined = @import("joined_codegen.zig");
const Authority = Joined.Authority;
const Export = @import("pcs_request_export.zig");
const CostTC = @import("trace_commit_cost.zig");
const O = D.O;
pub const Context = struct {
    service: *@import("pcs_native.zig").Context,
    projection: *@import("cpu_projection.zig").Context,
    trace: *@import("trace_commit.zig").Context,
    gkr: *@import("gkr_stage.zig").Backend,
    global: *@import("global_stage.zig").Context,
    composition: *RC.Context,
    pub fn registerCpu(self: *Context, allocator: std.mem.Allocator, request: CPU.rv64_device_source_stage.Request) !SourcePlan.Plan {
        const config = request.pcs_config orelse return error.MissingNativeClassPcsConfiguration;
        if (request.admission_replay_required) return error.NativeGkrReplayAdmissionUnavailable;
        if (self.gkr.binding_runtime == null) return error.MissingNativeClassDeviceBinding;
        try CPU.rv64_gkr_worker_protocol.validateCandidateConfig(config);
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const compact = if (std.posix.getenv("STWO_RV64_CPU_COMPACT_INGRESS")) |v| !std.mem.eql(u8, v, "0") else false;
        const tc_options = self.trace.allocationOptions(config.fri_config.log_blowup_factor);
        const source = try SourceCost.init(a, request, .{ .compact_ingress = compact, .retain_ledgers = self.projection.retain_ledgers, .commit = .{ .beta = tc_options.beta, .separate_coefficients = tc_options.separate_coefficients, .stream_budget = tc_options.stream_budget, .exact_prefix_banks = tc_options.exact_prefix_banks } });
        const components = try CPU.rv64_gkr_cpu_components.Plan.init(a, request.setup);
        const fixed_logs = try request.setup.logs(a, 0);
        const main_logs = try request.setup.logs(a, 1);
        const inter_logs = try components.interLogs(a);
        const logs = [3][]const u32{ fixed_logs, main_logs, inter_logs };
        const classes = try a.alloc(RC.ClassRole, components.slots.len);
        var max_log: u32 = 0;
        var constraints: usize = 0;
        var fixed_words: u64 = 0;
        for (fixed_logs) |log| fixed_words = try std.math.add(u64, fixed_words, @as(u64, 1) << @intCast(log));
        const descriptors = @import("joined_fixture_support.zig").descriptors();
        for (components.slots, classes) |slot, *class| {
            const mode = slot.origin == .core and (slot.origin.core == .cpu or slot.origin.core == .and_table);
            const descriptor = Joined.Source.Descriptor{ .origin = slot.origin, .cpu_u8_pairs = mode and request.setup.materials.geometry.cpu_u8_pairs, .cpu_compact_decode = slot.origin == .core and slot.origin.core == .cpu and request.setup.materials.geometry.cpu_compact_decode };
            const id = for (descriptors, 0..) |candidate, i| {
                if (std.meta.eql(candidate, descriptor)) break i;
            } else return error.UnsupportedNativeClassRole;
            const artifact = &self.composition.artifacts[id];
            const shape = try Authority.shape(descriptor);
            const local = slot.binding_index != null;
            if (local != Authority.hasLocal(descriptor)) return error.NativeClassBindingMismatch;
            const count = shape.constraints + (if (local) @as(usize, Authority.Binding.CONSTRAINTS) else 0) + Authority.Global.layout(slot.origin).constraints();
            if (count != artifact.program.roots.len) return error.NativeClassConstraintMismatch;
            class.* = .{ .namespace = .cpu, .id = @intCast(id), .artifact = artifact, .trace_log = slot.log, .eval_log = slot.log + 1, .widths = .{ shape.fixed, shape.main, (if (local) @as(usize, 16) else 0) + Authority.Global.layout(slot.origin).width() }, .offsets = .{ slot.fixed_offset, slot.main_offset, slot.inter_offset }, .auxiliary = if (local) .hc else .none };
            constraints = try std.math.add(usize, constraints, count);
            max_log = @max(max_log, slot.log);
        }
        const numerical = try self.gkr.classAllocationPlan(a, request.setup);
        const interaction = try self.global.cpuClassAllocationPlan(a, request.setup);
        var inter_options = tc_options;
        inter_options.logs = inter_logs;
        const inter_tc = try CostTC.init(a, inter_options);
        var composition = try self.composition.classAllocationPlan(a, classes, logs, max_log + 1, 1, constraints, config.fri_config.log_blowup_factor, fixed_words, false);
        defer composition.deinit(a);
        const pcs_request = try cpuPcsGeometry(a, request, &components, logs, max_log);
        var pcs = try @import("pcs_native.zig").classAllocationPlanWithFixed(a, pcs_request, self.service.wide_pcs_framing, try self.service.classAllocationOptions(pcs_request.lifting_log_size), fixed_words);
        defer pcs.deinit(a);
        const main_tc = try A.Footprint.allocations(source.trace.bytes());
        const main_owner = try A.Footprint.allocation(try std.math.mul(u64, source.trace.coefficient_words, 4));
        const inter_commit = try A.Footprint.allocations(inter_tc.bytes());
        const inter_owner = try A.Footprint.allocation(try std.math.mul(u64, inter_tc.coefficient_words, 4));
        const after_inter = composition.additional_peak.max(try composition.retained_after.add(pcs.additional_upper));
        const retained_inter = try interaction.outputs.add(numerical.binding.coefficient_owner);
        const later = inter_commit.max(try inter_owner.add(after_inter));
        const after_global = (try interaction.generation_peak.add(numerical.binding.projection_owner)).max(try (try interaction.outputs.add(numerical.binding.finalize)).add(numerical.binding.projection_owner)).max(try retained_inter.add(later));
        const after_numerical = numerical.binding.project.max(after_global);
        const after_main = numerical.numerical.peak.max(try numerical.numerical.retained.add(after_numerical));
        var plan = Progress.Plan{ .identity = undefined, .gpu_costs_known = true, .after = undefined };
        plan.after[@intFromEnum(Progress.Step.source)] = main_tc.max(try main_owner.add(after_main));
        plan.after[@intFromEnum(Progress.Step.main_commit)] = after_main;
        plan.after[@intFromEnum(Progress.Step.native_gkr)] = after_numerical;
        plan.after[@intFromEnum(Progress.Step.interaction)] = after_global;
        plan.after[@intFromEnum(Progress.Step.inter_commit)] = after_inter;
        plan.after[@intFromEnum(Progress.Step.composition)] = pcs.additional_upper;
        // The physical proof has no later GPU consumer in this native scope.
        plan.after[@intFromEnum(Progress.Step.pcs)] = .{};
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64/native-cpu-gpu-progress/v1\x00");
        h.update(@embedFile("native_progress.zig"));
        h.update(&source.identity);
        const envelope = try std.json.Stringify.valueAlloc(a, plan.after, .{});
        h.update(envelope);
        plan.identity = h.finalResult();
        try self.service.registerAdmissionProgress(request.scope, plan);
        return source;
    }
};

/// The very same mask rules as RoleGeometry.masks, expressed with its shared
/// source authorities. The arbitrary valid anchor is never a proof challenge;
/// Export.allocationPlan omits payloads so this request cannot be submitted.
fn cpuPcsGeometry(a: std.mem.Allocator, request: CPU.rv64_device_source_stage.Request, components: *const CPU.rv64_gkr_cpu_components.Plan, logs: [3][]const u32, max_log: u32) !D.Request {
    const config = request.pcs_config orelse return error.MissingNativeClassPcsConfiguration;
    const seed = O.fromM31Array(.{ D.M.fromCanonical(7), D.M.fromCanonical(11), D.M.fromCanonical(13), D.M.fromCanonical(17), D.M.fromCanonical(19), D.M.fromCanonical(23), D.M.fromCanonical(29), D.M.fromCanonical(31) });
    const probe = try core.circle.secureFieldPointFromRandomSeedCheckedFor(O, seed);
    const step = core.poly.circle.canonic.CanonicCoset.new(max_log).coset().step.double();
    const next2 = probe.add(.{ .x = O.fromBase(step.x), .y = O.fromBase(step.y) });
    const prior = @import("stwo_riscv_frontend").rv64_air.geometry.previousPointFor(O, probe, max_log);
    const trees = try a.alloc(D.Tree, 4);
    const points = try a.alloc([][]D.Point, 4);
    for (0..3) |tree| {
        const columns = try a.alloc(D.Column, logs[tree].len);
        for (columns, logs[tree]) |*column, log| column.* = .{ .log_size = log };
        trees[tree] = .{ .root = @splat(0), .columns = columns };
        points[tree] = try a.alloc([]D.Point, columns.len);
        if (tree == 0) {
            // CoreAir.Components.maskPointsImpl(..., include_all_preprocessed
            // = true) REPLACES the concatenated component FIXED masks with one
            // probe for EVERY original preprocessed column, including columns
            // unused by projected arithmetic. FIXED aliases therefore have the
            // same single-probe recipe and are not duplicate role coverage.
            for (points[tree]) |*column| column.* = try a.dupe(D.Point, &.{probe});
        } else @memset(points[tree], &.{});
    }
    for (components.slots) |slot| {
        const mode = slot.origin == .core and (slot.origin.core == .cpu or slot.origin.core == .and_table);
        const descriptor = Joined.Source.Descriptor{ .origin = slot.origin, .cpu_u8_pairs = mode and request.setup.materials.geometry.cpu_u8_pairs, .cpu_compact_decode = slot.origin == .core and slot.origin.core == .cpu and request.setup.materials.geometry.cpu_compact_decode };
        const shape = try Authority.shape(descriptor);
        const local_width: usize = if (slot.binding_index != null) 16 else 0;
        const global = Authority.Global.layout(slot.origin);
        const widths = [_]usize{ shape.fixed, shape.main, local_width + global.width() };
        const offsets = [_]usize{ slot.fixed_offset, slot.main_offset, slot.inter_offset };
        for (widths, offsets, 0..) |width, offset, tree| for (0..width) |c| {
            if (offset + c >= points[tree].len) return error.NativeClassMaskGeometry;
            if (tree == 0) continue;
            // MAIN and INTER retain the exact source component concatenation;
            // a gap or overlap here is a class-authority mismatch, not padding.
            if (points[tree][offset + c].len != 0) return error.NativeClassMaskGeometry;
            points[tree][offset + c] = if (tree == 2 and local_width != 0 and c < 8)
                try a.dupe(D.Point, &.{ probe, next2 })
            else if (tree == 2 and ((local_width != 0 and c < 16) or (c >= local_width and global.previous(c - local_width))))
                try a.dupe(D.Point, &.{ probe, prior })
            else if (tree == 1 and Authority.previousMain(descriptor, c))
                try a.dupe(D.Point, &.{ probe, prior })
            else
                try a.dupe(D.Point, &.{probe});
        };
    }
    for (points[0..3]) |tree| for (tree) |column| if (column.len == 0) return error.NativeClassMaskGeometry;
    const count = core.verifier_types.compositionColumnCount(1, 8) orelse return error.NativeClassMaskGeometry;
    const columns = try a.alloc(D.Column, count);
    for (columns) |*column| column.* = .{ .log_size = max_log };
    trees[3] = .{ .root = @splat(0), .columns = columns };
    points[3] = try a.alloc([]D.Point, count);
    for (points[3]) |*column| column.* = try a.dupe(D.Point, &.{probe});
    return .{ .scope = request.scope, .config = config, .lifting_log_size = try std.math.add(u32, max_log, config.fri_config.log_blowup_factor), .trees = trees, .points = core.pcs.TreeVec([][]D.Point).initOwned(points) };
}
