//! Original active-caller equation kernels in a joined proof's sample map.
//! Arithmetic and fused relation order, detailed-claim checks and the global
//! Horner state are shared with the original standalone caller compiler.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const G = @import("composition_graph_recorder.zig");
const S = G.Scalar;
const Family = @import("../block_v7_caller_family_v1.zig").Active;
const Admission = Family.Admission;
const Compiler = Family.Composition;
const Multi = @import("../../prover/block_v7_multi_union_proof_v1.zig").ForMode(true);
const Profile = @import("../block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Arithmetic = @import("block_v5_caller_arithmetic_composition_v1.zig");
const Fused = @import("block_v5_caller_fused_composition_v1.zig");
pub fn publicValues(a: std.mem.Allocator, profile: *const Profile.Owned, index: usize, claims: *const Multi.CallerClaims) ![]Q {
    const i = profile.statement.input;
    var admitted = try Admission.Prepared.init(a, i.callers[index], i.epoch, i.entries, .{});
    defer admitted.deinit();
    var values: std.ArrayList(Q) = .empty;
    errdefer values.deinit(a);
    for (claims.arithmetic.componentClaims()) |view| {
        try values.appendSlice(a, view.detailed);
        if (view.has_batch_frame) try values.append(a, view.total);
    }
    try values.append(a, claims.arithmetic.componentSum());
    const fused = try Fused.publicInputsForSchedule(a, &admitted.relations.schedule, admitted.relations.frame, claims.relations);
    defer a.free(fused);
    try values.appendSlice(a, fused);
    return values.toOwnedSlice(a);
}
pub fn record(a: std.mem.Allocator, builder: *G.Builder, profile: *const Profile.Owned, index: usize, claims: *const Multi.CallerClaims, mapped: anytype, union_points: *const core.air.components.MaskPoints, public: []const S, draws: []const [2]S, random: S, point: core.circle.CirclePoint(S), accumulated: *S) !usize {
    const i = profile.statement.input;
    var admitted = try Admission.Prepared.init(a, i.callers[index], i.epoch, i.entries, .{});
    defer admitted.deinit();
    const equations = try Admission.EquationOwner.create(a, &admitted, &claims.arithmetic, &claims.relations);
    defer equations.destroy();
    const mask_log = profile.shape.mask_log;
    const concrete_point = core.circle.SECURE_FIELD_CIRCLE_GEN;
    const step = core.poly.circle.canonic.CanonicCoset.new(mask_log).step();
    const previous = concrete_point.sub(.{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) });
    var arithmetic_points = try (core.air.components.Components{ .components = equations.arithmetic.active(), .n_preprocessed_columns = admitted.logs()[0].len }).maskPoints(a, concrete_point, mask_log, false);
    defer arithmetic_points.deinitDeep(a);
    var fused_points = try (core.air.components.Components{ .components = equations.handles, .n_preprocessed_columns = admitted.logs()[0].len }).maskPoints(a, concrete_point, mask_log, false);
    defer fused_points.deinitDeep(a);
    var local_points: [6][][]core.circle.CirclePointQM31 = @splat(&.{});
    var offsets: [6][]usize = @splat(&.{});
    if (mapped.map.len != 5 or mapped.fixed_count != admitted.logs()[0].len) return error.InvalidUnionCallerPlacement;
    for (mapped.map, 0..) |tree, local| {
        local_points[local] = if (local == 0) union_points.items[tree][mapped.fixed_start..][0..mapped.fixed_count] else union_points.items[tree];
        offsets[local] = if (local == 0) mapped.samples.offsets[tree][mapped.fixed_start..][0..mapped.fixed_count] else mapped.samples.offsets[tree];
    }
    const arithmetic_map = try Compiler.mapSamples(a, &arithmetic_points, &.{ 0, 1, 3 }, &local_points, offsets, mapped.samples.values);
    const fused_map = try Compiler.mapSamples(a, &fused_points, &.{ 0, 1, 2, 4 }, &local_points, offsets, mapped.samples.values);
    var arithmetic = Arithmetic.Samples{ .offsets = .{ arithmetic_map.offsets[0], arithmetic_map.offsets[1], arithmetic_map.offsets[2], &.{} }, .layouts = undefined, .values = arithmetic_map.symbols };
    for (arithmetic_points.items, 0..) |columns, tree| {
        arithmetic.layouts[tree] = try a.alloc(@import("../sample_point_layout.zig").Layout, columns.len);
        for (columns, arithmetic.layouts[tree]) |points, *layout| layout.* = try @import("../sample_point_layout.zig").classifyColumn(points, concrete_point, previous);
    }
    arithmetic.layouts[3] = &.{};
    const fused = Fused.Samples{ .offsets = .{ fused_map.offsets[0], fused_map.offsets[1], fused_map.offsets[2], fused_map.offsets[3], &.{} }, .lengths = .{ fused_map.lengths[0], fused_map.lengths[1], fused_map.lengths[2], fused_map.lengths[3], &.{} }, .values = fused_map.symbols };
    var details: std.ArrayList(S) = .empty;
    var totals: [19]S = undefined;
    var cursor: usize = 0;
    for (claims.arithmetic.componentClaims(), &totals) |view, *total| {
        if (cursor > public.len or view.detailed.len > public.len - cursor) return error.InvalidUnionCallerPublic;
        try details.appendSlice(a, public[cursor..][0..view.detailed.len]);
        cursor += view.detailed.len;
        if (view.has_batch_frame) {
            if (cursor == public.len) return error.InvalidUnionCallerPublic;
            total.* = public[cursor];
            cursor += 1;
        } else {
            if (details.items.len == 0) return error.InvalidUnionCallerPublic;
            total.* = details.items[details.items.len - 1];
        }
    }
    if (cursor == public.len) return error.InvalidUnionCallerPublic;
    const open = public[cursor];
    cursor += 1;
    const count = try Fused.publicCount(admitted.relations.schedule.program.len, admitted.relations.schedule.tables.len, admitted.relations.schedule.memory.len);
    if (cursor > public.len or count > public.len - cursor or draws.len < 53 + 14 * (index + 1)) return error.InvalidUnionCallerPublic;
    var word: [10]S = undefined;
    for (draws[47..52], 0..) |pair, j| @memcpy(word[2 * j ..][0..2], &pair);
    try Compiler.recordComponents(builder, &admitted, equations, &claims.arithmetic, arithmetic, fused, .{ .details = details.items, .totals = totals, .open_sum = open, .fused = public[cursor..][0..count] }, draws[0..47].*, draws[53 + 14 * index ..][0..14].*, word, random, point, mask_log, accumulated);
    return cursor + count;
}
