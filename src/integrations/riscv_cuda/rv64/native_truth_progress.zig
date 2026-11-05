//! Source-owned native TRUTH class. Geometry is derived before first CUDA work;
//! neither challenges nor proof payloads supply widths, offsets or masks.
const std = @import("std");
const core = @import("stwo_core");
const CPU = @import("stwo_riscv_cpu_integration");
const T = @import("truth_codegen.zig");
const D = CPU.rv64_device_pcs;
const Truth = @FieldType(CPU.rv64_gkr_truth_device_source.Prepare, "truth");
const A = @import("global_admission.zig");
const Progress = @import("admission_progress.zig");
const TC = @import("trace_commit_cost.zig");
const RC = @import("resident_composition.zig");
const IC = @import("native_interaction_cost.zig");
const O = D.O;
pub const Role = struct {
    id: u32,
    log: u32,
    split: u32,
    widths: [3]usize,
    offsets: [3]usize,
    constraints: usize,
    classic: ?T.Role.Shape = null,
    byte_batches: usize = 0,
    wire_batches: usize = 0,
    pub fn shifts(self: *const Role, tree: usize, col: usize) []const i32 {
        if (self.classic) |shape| return shape.shifts(tree, col);
        if (tree == 1 and col == 0) return &.{ 0, -1 };
        if (tree == 2) {
            const batch = col / 8;
            if ((self.byte_batches > 0 and batch == self.byte_batches - 1) or batch == self.byte_batches + self.wire_batches - 1) return &.{ 0, -1 };
        }
        return &.{0};
    }
};
pub fn rolesFor(a: std.mem.Allocator, truth: Truth) ![]Role {
    if (truth == .keccak) {
        const policy = truth.keccak.setup.policy;
        try @import("stwo_riscv_frontend").rv64_air.crypto.keccak.layout.validateGeometryFor(policy.geometry(), truth.count(), truth.first(), truth.keccak.setup.log);
        const out = try a.alloc(Role, 3);
        var offsets: [3]usize = @splat(0);
        const base = try T.classicKernelId(policy, .keccak);
        for (out, 0..) |*r, i| {
            const shape = T.Role.Shape{ .kind = if (i == 0) .keccak else if (i == 1) .chi else .xor5, .log_size = if (i == 0) truth.keccak.setup.log else policy.tableLog(if (i == 1) .chi else .xor5), .keccak_policy = policy };
            r.* = .{ .id = base + @as(u32, @intCast(i)), .log = shape.log_size, .split = 2, .widths = shape.widths(), .offsets = offsets, .constraints = shape.nConstraints(), .classic = shape };
            for (&offsets, r.widths) |*offset, width| offset.* = try std.math.add(usize, offset.*, width);
        }
        return out;
    }
    const desc = try T.V3Catalog.descriptor(truth);
    const id: u32 = switch (truth) {
        .sha256 => 3,
        .arith256_mod => 4,
        .secp_row => |v| if (v.setup.kind == .add) 5 else 6,
        .curve => |v| try T.curveKernelId(v.setup.op),
        else => return error.UnsupportedDeviceTruthFamily,
    };
    const out = try a.alloc(Role, 1);
    out[0] = .{ .id = id, .log = desc.log_size, .split = if (desc.shape.degree > 3) 2 else 1, .widths = desc.widths(), .offsets = @splat(0), .constraints = desc.nConstraints(), .byte_batches = desc.shape.byte_batches, .wire_batches = desc.shape.wire_batches };
    return out;
}
pub const Source = struct {
    peak: A.Footprint,
    retained: A.Footprint,
};
pub const Plan = struct {
    initial: Source,
    replay: Source,
    progress: Progress.Plan,
};
fn allocation(words: u64) !A.Footprint {
    return A.Footprint.allocation(try std.math.mul(u64, words, 4));
}
fn coefficientWords(logs: []const u32) !u64 {
    var total: u64 = 0;
    for (logs) |log| total = try std.math.add(u64, total, @as(u64, 1) << @intCast(log));
    return total;
}
/// Every actual MainJob allocation is individually rounded. Cold immutable
/// FIXED is one forest allocation on replay, independently of raw MAIN owners.
pub fn sourcePlan(truth: Truth, compact_words: usize, compact_present: bool, fixed_words: u64) !Source {
    const log = if (truth == .keccak) truth.keccak.setup.log else try T.V3Catalog.logSize(truth);
    if (log < 5 or log > 22 or compact_words == 0) return error.InvalidDeviceTruthGeometry;
    const width = if (truth == .keccak) @import("stwo_riscv_frontend").rv64_air.crypto.keccak.layout.MAIN else (try T.V3Catalog.shape(truth)).main;
    var retained: A.Footprint = .{};
    if (!compact_present) retained = try retained.add(try allocation(compact_words));
    retained = try retained.add(try allocation(try std.math.mul(u64, width, @as(u64, 1) << @intCast(log))));
    if (truth == .keccak) {
        retained = try retained.add(try allocation(@as(u64, 1) << @intCast(truth.keccak.setup.policy.tableLog(.chi))));
        retained = try retained.add(try allocation(@as(u64, 1) << @intCast(truth.keccak.setup.policy.tableLog(.xor5))));
    } else if (truth == .arith256_mod or truth == .secp_row or truth == .curve) retained = try retained.add(try allocation(256));
    // Immutable FIXED remains owned by the Service, not by this source Owner.
    if (fixed_words != 0) retained = try retained.add(try allocation(fixed_words));
    return .{ .retained = retained, .peak = try retained.add(try allocation(1)) };
}
pub fn init(allocator: std.mem.Allocator, service: *@import("pcs_native.zig").Context, trace: *@import("trace_commit.zig").Context, composition: *RC.Context, truth: Truth, scope: D.Scope, config: core.pcs.PcsConfig, compact_words: usize, replay: bool) !Plan {
    // Only value-sized bounds/identity escape this calculation. Its mask,
    // column and diagnostic JSON geometry must not escape into the request
    // budget as leaked temporary allocations, on success or on refusal.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try CPU.rv64_gkr_worker_protocol.validateCandidateConfig(config);
    if (try CPU.rv64_gkr_truth_device_source.compactInputBytes(truth) != try std.math.mul(usize, compact_words, 4)) return error.NativeTruthCompactGeometryMismatch;
    const roles = try rolesFor(a, truth);
    _ = try composition.truthStage();
    var logs: [3][]const u32 = undefined;
    for (&logs, 0..) |*l, t| {
        var count: usize = 0;
        for (roles) |r| count = try std.math.add(usize, count, r.widths[t]);
        const list = try a.alloc(u32, count);
        var offset: usize = 0;
        for (roles) |r| {
            @memset(list[offset..][0..r.widths[t]], r.log);
            offset += r.widths[t];
        }
        l.* = list;
    }
    const classes = try a.alloc(RC.ClassRole, roles.len);
    var generation: A.Footprint = .{};
    var outputs: A.Footprint = .{};
    var max_log: u32 = 0;
    var split: u32 = 1;
    var total: usize = 0;
    for (roles, classes) |r, *class| {
        const artifact = &(composition.truth_artifacts[r.id] orelse return error.TruthCompositionNotInitialized);
        if (artifact.program.roots.len != r.constraints) return error.NativeTruthClassConstraintMismatch;
        class.* = .{ .namespace = .truth, .id = r.id, .artifact = &composition.truth_artifacts[r.id].?, .trace_log = r.log, .eval_log = r.log + r.split, .widths = r.widths, .offsets = r.offsets, .auxiliary = if (r.classic != null) .last else .none };
        max_log = @max(max_log, r.log);
        split = @max(split, r.split);
        total = try std.math.add(usize, total, r.constraints);
        var raw = try @import("truth_interaction_codegen.zig").record(a, r.id);
        defer raw.deinit();
        const cost = try IC.init(.{ .log = r.log, .fixed_columns = r.widths[0], .main_columns = r.widths[1], .host_fixed_columns = r.widths[0], .parameters = raw.parameter_slots.len, .pairs = try std.math.add(usize, raw.groups[0], raw.groups[1]), .groups = 1 + @as(usize, @intFromBool(raw.groups[1] != 0)) });
        generation = generation.max(try outputs.add(cost.temporary));
        outputs = try outputs.add(cost.output);
    }
    const fixed_words = try coefficientWords(logs[0]);
    var composition_plan = try composition.classAllocationPlan(a, classes, logs, max_log + split, split, total, config.fri_config.log_blowup_factor, fixed_words, false);
    defer composition_plan.deinit(a);
    const geometry = try pcsGeometry(a, roles, logs, scope, config, max_log, split);
    var pcs = try @import("pcs_native.zig").classAllocationPlanWithFixed(a, geometry, service.wide_pcs_framing, try service.classAllocationOptions(geometry.lifting_log_size), fixed_words);
    defer pcs.deinit(a);
    var options = trace.allocationOptions(config.fri_config.log_blowup_factor);
    options.logs = logs[1];
    const main_tc = try TC.init(a, options);
    options.logs = logs[2];
    const inter_tc = try TC.init(a, options);
    const main_commit = try main_tc.footprint();
    const main_owner = try allocation(main_tc.coefficient_words);
    const after_inter = composition_plan.additional_peak.max(try composition_plan.retained_after.add(pcs.additional_upper));
    const later = (try inter_tc.footprint()).max(try (try allocation(inter_tc.coefficient_words)).add(after_inter));
    const downstream = generation.max(try outputs.add(later));
    const initial = try sourcePlan(truth, compact_words, false, 0);
    const replay_source = try sourcePlan(truth, compact_words, true, fixed_words);
    // Post-global replay is admitted at runMain itself. Once that MAIN commit
    // finishes, it cannot recursively require another copy of its own replay.
    const after_main = downstream;
    var progress = Progress.Plan{ .identity = undefined, .gpu_costs_known = true, .after = undefined };
    progress.after[@intFromEnum(Progress.Step.source)] = main_commit.max(try main_owner.add(after_main));
    progress.after[@intFromEnum(Progress.Step.main_commit)] = after_main;
    progress.after[@intFromEnum(Progress.Step.native_gkr)] = downstream;
    progress.after[@intFromEnum(Progress.Step.interaction)] = generation.max(try outputs.add(later));
    progress.after[@intFromEnum(Progress.Step.inter_commit)] = after_inter;
    progress.after[@intFromEnum(Progress.Step.composition)] = pcs.additional_upper;
    progress.after[@intFromEnum(Progress.Step.pcs)] = .{};
    // Stage one seals MAIN, then retires raw MAIN and (with replay) cached
    // coefficients. Its compact owner is still charged as observed live bytes.
    var pre: Progress.After = @splat(.{});
    pre[@intFromEnum(Progress.Step.source)] = main_commit.max(main_owner);
    progress.pre_global_after = pre;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64/native-truth-gpu-progress/v1\x00");
    h.update(@embedFile("native_truth_progress.zig"));
    h.update(try std.json.Stringify.valueAlloc(a, roles, .{}));
    h.update(try std.json.Stringify.valueAlloc(a, .{ config, compact_words, replay, progress.after, progress.pre_global_after }, .{}));
    progress.identity = h.finalResult();
    try service.registerAdmissionProgress(scope, progress);
    return .{ .initial = initial, .replay = replay_source, .progress = progress };
}
fn pcsGeometry(a: std.mem.Allocator, roles: []const Role, logs: [3][]const u32, scope: D.Scope, config: core.pcs.PcsConfig, max_log: u32, split: u32) !D.Request {
    const seed = O.fromM31Array(.{ D.M.fromCanonical(7), D.M.fromCanonical(11), D.M.fromCanonical(13), D.M.fromCanonical(17), D.M.fromCanonical(19), D.M.fromCanonical(23), D.M.fromCanonical(29), D.M.fromCanonical(31) });
    const probe = try core.circle.secureFieldPointFromRandomSeedCheckedFor(O, seed);
    const step = core.poly.circle.canonic.CanonicCoset.new(max_log).coset().step;
    const lift = D.Point{ .x = O.fromBase(step.x), .y = O.fromBase(step.y) };
    const prior = @import("stwo_riscv_frontend").rv64_air.geometry.previousPointFor(O, probe, max_log);
    const trees = try a.alloc(D.Tree, 4);
    const points = try a.alloc([][]D.Point, 4);
    for (0..3) |tree| {
        const columns = try a.alloc(D.Column, logs[tree].len);
        for (columns, logs[tree]) |*column, log| column.* = .{ .log_size = log };
        trees[tree] = .{ .root = @splat(0), .columns = columns };
        points[tree] = try a.alloc([]D.Point, columns.len);
        @memset(points[tree], &.{});
    }
    for (roles) |r| for (r.widths, r.offsets, 0..) |width, offset, tree| for (0..width) |c| {
        if (offset + c >= points[tree].len or points[tree][offset + c].len != 0) return error.NativeTruthClassMaskGeometry;
        const shifts = r.shifts(tree, c);
        const column = try a.alloc(D.Point, shifts.len);
        for (column, shifts) |*p, shift| p.* = if (r.classic != null) probe.add(lift.mulSigned(shift)) else if (shift == -1) prior else probe;
        points[tree][offset + c] = column;
    };
    for (points[0..3]) |tree| for (tree) |column| if (column.len == 0) return error.NativeTruthClassMaskGeometry;
    const count = core.verifier_types.compositionColumnCount(split, 8) orelse return error.NativeTruthClassMaskGeometry;
    const columns = try a.alloc(D.Column, count);
    for (columns) |*c| c.* = .{ .log_size = max_log };
    trees[3] = .{ .root = @splat(0), .columns = columns };
    points[3] = try a.alloc([]D.Point, count);
    for (points[3]) |*c| c.* = try a.dupe(D.Point, &.{probe});
    return .{ .scope = scope, .config = config, .lifting_log_size = try std.math.add(u32, max_log, config.fri_config.log_blowup_factor), .trees = trees, .points = core.pcs.TreeVec([][]D.Point).initOwned(points) };
}

test "truth source allocations preserve ABI and distinguish cold compact from replay" {
    const TruthSetup = @typeInfo(@FieldType(@FieldType(Truth, "curve"), "setup")).pointer.child;
    var setup: TruthSetup = undefined;
    setup.op = .bn254_g1_add;
    setup.log = 8;
    const truth = Truth{ .curve = .{ .setup = &setup, .first_id = 1, .calls = 3 } };
    const words = (try CPU.rv64_gkr_truth_device_source.compactInputBytes(truth)) / 4;
    const cold = try sourcePlan(truth, words, false, 0);
    const warm = try sourcePlan(truth, words, true, 0);
    const compact = try allocation(words);
    try std.testing.expectEqual(try warm.retained.add(compact), cold.retained);
    try std.testing.expectEqual(try warm.peak.add(compact), cold.peak);
    const forest = try sourcePlan(truth, words, true, 4 * 256);
    try std.testing.expectEqual(try warm.retained.add(try allocation(4 * 256)), forest.retained);
    try std.testing.expectEqual(try forest.retained.add(try allocation(1)), forest.peak);
    setup.log = 23;
    try std.testing.expectError(error.InvalidDeviceTruthGeometry, sourcePlan(truth, words, false, 0));
}
test "truth roster uses policy-specific source IDs and full OM31 interaction geometry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const Setup = @typeInfo(@FieldType(@FieldType(Truth, "keccak"), "setup")).pointer.child;
    var setup: Setup = undefined;
    setup.log = 18;
    inline for ([_]@FieldType(Setup, "policy"){ .throughput_r27, .triple_v2 }) |policy| {
        setup.policy = policy;
        const truth = Truth{ .keccak = .{ .setup = &setup, .first_id = 1, .calls = 1 } };
        const roles = try rolesFor(a, truth);
        try std.testing.expectEqual(@as(usize, 3), roles.len);
        const base = try T.classicKernelId(policy, .keccak);
        for (roles, 0..) |r, i| {
            try std.testing.expectEqual(base + @as(u32, @intCast(i)), r.id);
            try std.testing.expectEqual(r.classic.?.widths(), r.widths);
            try std.testing.expectEqual(r.classic.?.nConstraints(), r.constraints);
            try std.testing.expectEqual(@as(u32, 2), r.split);
            if (i > 0) try std.testing.expectEqual(policy.tableLog(if (i == 1) .chi else .xor5), r.log);
        }
        try std.testing.expectEqualSlices(i32, &.{ 0, -2, -1, 1, 2 }, roles[0].shifts(1, 0));
        try std.testing.expectEqualSlices(i32, &.{ 0, -1 }, roles[2].shifts(2, roles[2].widths[2] - 1));
    }
}
test "truth progress typed production constructor is analyzed" {
    const Init = *const @TypeOf(init);
    const p: Init = &init;
    try std.testing.expect(@intFromPtr(p) != 0);
}
