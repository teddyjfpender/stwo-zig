//! Whole recursion class, registered before its first device allocation.
//! Geometry comes from the bound AIR and the same allocation calculators as
//! execution. The probe point supplies only relative mask offsets, never a
//! transcript challenge or a proof payload.
const std = @import("std");
const core = @import("stwo_core");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const A = @import("global_admission.zig");
const Progress = @import("admission_progress.zig");
const RC = @import("resident_composition.zig");
const O = D.O;

pub fn register(owner: *@import("outer_source.zig").Owner) !void {
    const service = owner.backend.service;
    if (service.admission == null) return;
    var arena = std.heap.ArenaAllocator.init(owner.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key = owner.key;
    const config = try Outer.protocol.targetConfig();
    const beta = config.fri_config.log_blowup_factor;
    const logs = [3][]const u32{ try key.treeLogs(a, 0), try key.treeLogs(a, 1), try key.treeLogs(a, 2) };
    var source = try owner.mainAllocationPlan();
    defer source.deinit(owner.allocator);
    var interaction = try owner.interactionAllocationPlan();
    defer interaction.deinit(owner.allocator);
    var tc_options = owner.backend.trace_commit.allocationOptions(beta);
    tc_options.logs = logs[1];
    const main_tc = try @import("trace_commit_cost.zig").init(a, tc_options);
    tc_options.logs = logs[2];
    const inter_tc = try @import("trace_commit_cost.zig").init(a, tc_options);
    const classes = try a.alloc(RC.ClassRole, owner.backend.entries.items.len);
    for (owner.backend.entries.items, classes) |*entry, *out| {
        const c = &key.bound.components[entry.group.component];
        const main = try Outer.geometry.span(c.*, 1);
        const inter = try Outer.geometry.span(c.*, 2);
        out.* = .{ .namespace = .outer, .id = entry.group.component, .artifact = &entry.metadata, .trace_log = c.trace_log_size, .eval_log = c.evaluation_log_size, .widths = .{ c.preprocessed_indices.len, main.end - main.start, inter.end - inter.start }, .offsets = .{ 0, main.start, inter.start }, .fixed_indices = c.preprocessed_indices };
    }
    var fixed_words: u64 = 0;
    for (logs[0]) |log| fixed_words = try std.math.add(u64, fixed_words, @as(u64, 1) << @intCast(log));
    // The precommitted FIXED coefficient forest is already a physical owner
    // in the arena snapshot. prepare_from_circuit checked that this exact PP
    // and root belong to its live precommit. RC and PCS consume those device
    // columns directly, just as their execution preflights do; neither makes
    // another cold coefficient-cache copy. Raw FIXED evaluation misses in
    // Source remain charged, because their immutable entries are not pinned.
    const fixed_cold_words = if (key.device_fixed) 0 else fixed_words;
    const log = key.bound.max_evaluation_log_size;
    const shared = if (std.posix.getenv("STWO_RV64_RC_ROLE_WORKSPACE")) |v| std.mem.eql(u8, v, "1") else false;
    var rc = try owner.backend.composition.classAllocationPlan(a, classes, logs, log, 1, key.bound.total_constraints, beta, fixed_cold_words, shared);
    defer rc.deinit(a);
    const request = try pcsGeometry(a, owner, config, logs, log - 1);
    var pcs = try @import("pcs_native.zig").classAllocationPlanWithFixed(a, request, service.wide_pcs_framing, try service.classAllocationOptions(request.lifting_log_size), fixed_cold_words);
    defer pcs.deinit(a);
    const main_owner = try A.Footprint.allocation(try std.math.mul(u64, main_tc.coefficient_words, 4));
    const inter_owner = try A.Footprint.allocation(try std.math.mul(u64, inter_tc.coefficient_words, 4));
    var plan = Progress.Plan{ .identity = undefined, .gpu_costs_known = true, .after = undefined };
    const main_peak = try A.Footprint.allocations(main_tc.bytes());
    const inter_peak = try A.Footprint.allocations(inter_tc.bytes());
    var main_evaluations: A.Footprint = .{};
    for (source.events.items) |event| if (event.kind == .main) {
        main_evaluations = try main_evaluations.add(try A.Footprint.allocation(event.bytes));
    };
    var inter_evaluations: A.Footprint = .{};
    for (interaction.events.items) |event| if (event.kind == .inter) {
        inter_evaluations = try inter_evaluations.add(try A.Footprint.allocation(event.bytes));
    };
    if (beta == 1) {
        // Both discounts are backed by checked, joined input destruction.
        // Source and TC MUST raise the authorized future before releasing the
        // corresponding old owner; the registry rejects missing publications.
        const future = try @import("outer_progress_cost.zig").init(.{
            .main_evaluations = main_evaluations,
            .inter_evaluations = inter_evaluations,
            .main_commit_peak = main_peak,
            .main_coefficients = main_owner,
            .interaction_peak = interaction.additional_peak,
            .inter_commit_peak = inter_peak,
            .inter_coefficients = inter_owner,
            .composition_peak = rc.additional_peak,
            .composition_retained = rc.retained_after,
            .pcs_peak = pcs.additional_upper,
        });
        plan.after[@intFromEnum(Progress.Step.source)] = future.after_source;
        plan.after[@intFromEnum(Progress.Step.main_commit)] = future.after_main;
        plan.after[@intFromEnum(Progress.Step.native_gkr)] = future.after_main;
        plan.after[@intFromEnum(Progress.Step.interaction)] = future.after_interaction;
        plan.after[@intFromEnum(Progress.Step.inter_commit)] = future.after_inter_commit;
        plan.retirement_after[@intFromEnum(Progress.Step.interaction)] = future.interaction_after_release;
        plan.retirement_after[@intFromEnum(Progress.Step.inter_commit)] = future.inter_commit_after_release;
    } else {
        // No retirement discount for a TC mode without its input-release hook.
        const tail = rc.additional_peak.max(try rc.retained_after.add(pcs.additional_upper));
        const after_interaction = inter_peak.max(try inter_owner.add(tail));
        const after_main = interaction.additional_peak.max(try interaction.retained_after.add(after_interaction));
        plan.after[@intFromEnum(Progress.Step.source)] = main_peak.max(try main_owner.add(after_main));
        plan.after[@intFromEnum(Progress.Step.main_commit)] = after_main;
        plan.after[@intFromEnum(Progress.Step.native_gkr)] = after_main;
        plan.after[@intFromEnum(Progress.Step.interaction)] = after_interaction;
        plan.after[@intFromEnum(Progress.Step.inter_commit)] = tail;
    }
    plan.after[@intFromEnum(Progress.Step.composition)] = pcs.additional_upper;
    plan.after[@intFromEnum(Progress.Step.pcs)] = .{};
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64/outer-gpu-progress/v2-retirement\x00");
    h.update(@embedFile("outer_progress.zig"));
    h.update(&key.identity);
    h.update(try std.json.Stringify.valueAlloc(a, plan.after, .{}));
    h.update(try std.json.Stringify.valueAlloc(a, plan.retirement_after, .{}));
    plan.identity = h.finalResult();
    std.debug.print("OUTER_CLASS_PROGRESS ordinal={} beta={} main_eval_large={} inter_eval_large={} main_coeff_large={} inter_coeff_large={} main_tc_large={} interaction_large={} inter_tc_large={} rc_large={} rc_retained_large={} pcs_large={} source_future_large={} interaction_future_large={} inter_tc_future_large={}\n", .{ owner.initial_scope.ordinal, beta, main_evaluations.large, inter_evaluations.large, main_owner.large, inter_owner.large, main_peak.large, interaction.additional_peak.large, inter_peak.large, rc.additional_peak.large, rc.retained_after.large, pcs.additional_upper.large, plan.after[@intFromEnum(Progress.Step.source)].large, plan.after[@intFromEnum(Progress.Step.interaction)].large, plan.after[@intFromEnum(Progress.Step.inter_commit)].large });
    try service.registerAdmissionProgress(owner.initial_scope, plan);
}

fn pcsGeometry(a: std.mem.Allocator, owner: *@import("outer_source.zig").Owner, config: core.pcs.ForField(O).PcsConfig, logs: [3][]const u32, max_log: u32) !D.Request {
    const Air = core.air.components.ForField(O);
    const components = try a.alloc(Outer.component.Component, owner.key.bound.components.len);
    const erased = try a.alloc(Air.Component, components.len);
    for (owner.key.bound.components, components, erased) |*captured, *component, *out| {
        component.* = .{ .allocator = a, .captured = captured, .preprocessed_logs = logs[0], .z = O.one(), .alpha = O.one(), .claim = O.zero() };
        out.* = component.asVerifierComponent();
    }
    const air = Air.Components{ .components = erased, .n_preprocessed_columns = logs[0].len };
    const seed = O.fromM31Array(.{ D.M.fromCanonical(7), D.M.fromCanonical(11), D.M.fromCanonical(13), D.M.fromCanonical(17), D.M.fromCanonical(19), D.M.fromCanonical(23), D.M.fromCanonical(29), D.M.fromCanonical(31) });
    const probe = try core.circle.secureFieldPointFromRandomSeedCheckedFor(O, seed);
    // P.Engine.prove uses the default include_all_preprocessed_columns=false.
    const masks = try air.maskPoints(a, probe, max_log, false);
    if (masks.items.len != 3) return error.InvalidOuterClassMaskTrees;
    const trees = try a.alloc(D.Tree, 4);
    const points = try a.alloc([][]D.Point, 4);
    @memcpy(points[0..3], masks.items);
    for (logs, 0..) |tree_logs, tree| {
        const columns = try a.alloc(D.Column, tree_logs.len);
        for (columns, tree_logs) |*column, log| column.* = .{ .log_size = log };
        trees[tree] = .{ .root = @splat(0), .columns = columns };
    }
    const count = core.verifier_types.compositionColumnCount(1, 8) orelse return error.InvalidOuterClassMaskTrees;
    const columns = try a.alloc(D.Column, count);
    for (columns) |*column| column.* = .{ .log_size = max_log };
    trees[3] = .{ .root = @splat(0), .columns = columns };
    points[3] = try a.alloc([]D.Point, count);
    for (points[3]) |*column| column.* = try a.dupe(D.Point, &.{probe});
    return .{ .scope = owner.initial_scope, .config = config, .lifting_log_size = try std.math.add(u32, max_log, config.fri_config.log_blowup_factor), .trees = trees, .points = core.pcs.TreeVec([][]D.Point).initOwned(points) };
}
