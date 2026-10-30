//! Typed caller equations over the enclosing Mixed14 openings. Arithmetic,
//! original program/state/table projections, actual RAM current/+27 tuples,
//! and per-access first-halt guards share one Horner accumulation.
const std = @import("std");
const core = @import("stwo_core");
const G = @import("composition_graph_recorder.zig");
const S = G.Scalar;
const Field = @import("block_v5_ram_lanes_composition_v1.zig").Field;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Profile = @import("../block_v8_endpoint_mixed_profile_v1.zig");
const H = @import("block_v8_endpoint_recursive_composition_v1.zig").For(.local_open);
const Arithmetic = @import("block_v5_caller_arithmetic_composition_v1.zig");
const Fused = @import("block_v5_caller_fused_composition_v1.zig");
const Geometry = @import("../block_v7_caller_family_v1.zig").Active.Admission.Arithmetic;
const Access = @import("../../prover/block_v8_caller_ram_component_v1.zig");
const Ram = @import("../../prover/block_v8_caller_ram_projection_v1.zig");
const Halt = @import("../../prover/block_v8_caller_halt_policy_v1.zig");
const Adapter = struct {
    pub const Scalar = S;
    pub const accumulate = G.accumulate;
    pub const quotientDenominator = G.quotientDenominator;
    pub fn diagnosticCheckpoint(_: []const u8, _: usize, _: u32, _: S) void {}
};
pub fn publicValues(a: std.mem.Allocator, p: *const Profile.Owned) ![]Q {
    var values: std.ArrayList(Q) = .empty;
    errdefer values.deinit(a);
    for (p.claims.caller_arithmetic.componentClaims()) |view| {
        try values.appendSlice(a, view.detailed);
        if (view.has_batch_frame) try values.append(a, view.total);
    }
    try values.append(a, p.claims.caller_arithmetic.componentSum());
    var schedule = p.scope.caller_plan.schedule;
    schedule.memory = &.{};
    schedule.rw_events = 0;
    const basic = try Fused.publicInputsForSchedule(a, &schedule, p.statement.input.frame, p.claims.caller_basic);
    defer a.free(basic);
    try values.appendSlice(a, basic);
    try values.appendSlice(a, p.claims.caller_ram);
    return values.toOwnedSlice(a);
}
/// Reproduce the exact original component's sample ordering from the enclosing
/// union. No prefix/ordinal assumption is made about a current/+27 opening.
fn mapped(a: std.mem.Allocator, expected: *const core.air.components.MaskPoints, map: []const usize, global: *const core.air.components.MaskPoints, samples: H.Samples, fixed_start: usize) !struct { offsets: [][]usize, lengths: [][]usize, values: []S } {
    const offsets = try a.alloc([]usize, map.len);
    const lengths = try a.alloc([]usize, map.len);
    var values: std.ArrayList(S) = .empty;
    for (expected.items, map, offsets, lengths) |columns, tree, *starts, *sizes| {
        starts.* = try a.alloc(usize, columns.len);
        sizes.* = try a.alloc(usize, columns.len);
        for (columns, starts.*, sizes.*, 0..) |points, *start, *size, c| {
            const col = c + if (tree == 0) fixed_start else @as(usize, 0);
            if (tree >= global.items.len or col >= global.items[tree].len) return error.InvalidMixedCallerOpening;
            start.* = values.items.len;
            size.* = points.len;
            for (points) |point| {
                var found = false;
                for (global.items[tree][col], 0..) |candidate, ordinal| if (candidate.eql(point)) {
                    try values.append(a, try samples.at(tree, col, ordinal));
                    found = true;
                    break;
                };
                if (!found) return error.MissingMixedCallerOpening;
            }
        }
    }
    return .{ .offsets = offsets, .lengths = lengths, .values = try values.toOwnedSlice(a) };
}
const SharedSamples = struct {
    original: H.Mapped,
    points: *const core.air.components.MaskPoints,
    current: core.circle.CirclePointQM31,
    output: core.circle.CirclePointQM31,
    pub fn at(self: @This(), tree: usize, column: usize, ordinal: usize) !Field {
        if (tree > 1 or ordinal > 1) return error.InvalidMixedCallerSharedOpening;
        const global_tree = self.original.map[tree];
        const col = column + if (tree == 0) self.original.fixed_start else @as(usize, 0);
        if (global_tree >= self.points.items.len or col >= self.points.items[global_tree].len) return error.InvalidMixedCallerSharedOpening;
        const wanted = if (ordinal == 0) self.current else self.output;
        for (self.points.items[global_tree][col], 0..) |point, index| if (point.eql(wanted)) return .{ .symbol = try self.original.at(tree, column, index) };
        return error.MissingMixedCallerSharedOpening;
    }
};
pub fn record(a: std.mem.Allocator, builder: *G.Builder, p: *const Profile.Owned, samples: H.Samples, fixed_start: usize, public: []const S, draws: [67][2]S, random: S, seed: S, accumulated: *S) !usize {
    const ctx = p.context.caller.?;
    const plan = &p.scope.caller_plan;
    const all = core.air.components.Components{ .components = p.context.combined.?.handles, .n_preprocessed_columns = p.shape.columns[0].len };
    const concrete = core.circle.SECURE_FIELD_CIRCLE_GEN;
    const step = core.poly.circle.canonic.CanonicCoset.new(p.shape.mask_log).step();
    const previous = concrete.sub(.{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) });
    var points = try all.maskPoints(a, concrete, p.shape.mask_log, false);
    defer points.deinitDeep(a);
    var ap = try (core.air.components.Components{ .components = ctx.arithmetic.active(), .n_preprocessed_columns = plan.schedule.fixed.len }).maskPoints(a, concrete, p.shape.mask_log, false);
    defer ap.deinitDeep(a);
    const am = try mapped(a, &ap, &.{ 0, 6, 12 }, &points, samples, fixed_start);
    var arithmetic = Arithmetic.Samples{ .offsets = .{ am.offsets[0], am.offsets[1], am.offsets[2], &.{} }, .layouts = undefined, .values = am.values };
    for (ap.items, 0..) |columns, tree| {
        arithmetic.layouts[tree] = try a.alloc(@import("../sample_point_layout.zig").Layout, columns.len);
        for (columns, arithmetic.layouts[tree]) |column, *layout| layout.* = try @import("../sample_point_layout.zig").classifyColumn(column, concrete, previous);
    }
    arithmetic.layouts[3] = &.{};
    var details: std.ArrayList(S) = .empty;
    var totals: [19]S = undefined;
    var at: usize = 0;
    for (p.claims.caller_arithmetic.componentClaims(), &totals) |view, *total| {
        if (at > public.len or view.detailed.len > public.len - at) return error.InvalidMixedCallerClaims;
        try details.appendSlice(a, public[at..][0..view.detailed.len]);
        at += view.detailed.len;
        if (view.has_batch_frame) {
            if (at == public.len) return error.InvalidMixedCallerClaims;
            total.* = public[at];
            at += 1;
        } else total.* = details.items[details.items.len - 1];
    }
    if (at == public.len) return error.InvalidMixedCallerClaims;
    const open = public[at];
    at += 1;
    var geometry = try Geometry.init(a, plan.statement, plan.steps, p.statement.trusted.config, p.context.relations, 1 << 16);
    defer geometry.deinit();
    const base_challenges = try G.ChallengeSet.init(draws[0..47].*);
    const base = @import("blake3_execution_composition_native.zig").relations(&base_challenges);
    const R = @import("../ethereum_composition_relations_v2.zig").ForScalar(S, @TypeOf(base)).Bundle;
    const relations = R.fromBase(base, draws[53..66].*);
    var cache: G.DenominatorCache = @splat(null);
    const point = G.pointFromSeed(seed);
    const eth = try @import("block_v5_caller_arithmetic_record_v1.zig").ForRecorder(Adapter, Arithmetic.Samples, R).recordSelected(&geometry, &arithmetic, details.items[0 .. details.items.len - 5], &relations, point, random, p.shape.mask_log, &cache, accumulated.*, builder);
    accumulated.* = eth.accumulation;
    var count: usize = eth.instruction_count;
    if (ctx.arithmetic.sha_owner) |owner| {
        var sha_draws = draws[0..47].*;
        sha_draws[@intFromEnum(@import("../../air/lang/relation.zig").Domain.recursion_wire)] = draws[66];
        const sha = try G.ChallengeSet.init(sha_draws);
        const Sha = @import("../../air/guest_precompile/sha256_component_profile.zig");
        inline for (Sha.AirsForRecipe(false), 0..) |Air, index| {
            const c = geometry.components[14 + index];
            const Runtime = @import("universal_relation_binding.zig").Binding(Air).Runtime;
            var row: [Runtime.LOGICAL_INPUT_COUNT]S = undefined;
            for (row[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], 0..) |*v, col| v.* = try arithmetic.at(1, c.spans[1].offset + col, 0);
            for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], 0..) |*v, col| v.* = try arithmetic.at(0, c.spans[0].offset + col, 0);
            var current: [Runtime.BATCH_COUNT]S = undefined;
            for (&current, 0..) |*v, batch| v.* = try arithmetic.secure(c.spans[2].offset + 4 * batch, 0);
            const prior = try arithmetic.secure(c.spans[2].offset + 4 * (Runtime.BATCH_COUNT - 1), -1);
            const shift = totals[14 + index].mul(S.fromBase(try M.fromU64(@as(u64, 1) << @intCast(c.log_size)).inv()));
            count += try G.recordComponent(Runtime, &owner.components[index], row, current, prior, shift, &sha, random, try G.quotientDenominator(c.log_size, p.shape.mask_log, point, &cache), accumulated);
        }
    }
    if (count != geometry.air_instruction_count) return error.InvalidMixedCallerArithmeticCensus;
    var detail: usize = 0;
    var total_sum = S.zero();
    for (p.claims.caller_arithmetic.componentClaims(), totals, 0..) |view, total, index| {
        if (!geometry.selected[index]) try builder.constrainZero(total);
        if (view.has_batch_frame) {
            var sum = S.zero();
            for (details.items[detail..][0..view.detailed.len]) |v| sum = sum.add(v);
            try builder.constrainZero(total.sub(sum));
        }
        detail += view.detailed.len;
        total_sum = total_sum.add(total);
    }
    try builder.constrainZero(open.sub(total_sum));
    const basic_count = try Fused.publicCount(plan.schedule.program.len, plan.schedule.tables.len, 0);
    if (at > public.len or basic_count + plan.ram.descriptors.len != public.len - at) return error.InvalidMixedCallerClaims;
    const basic_public = public[at..][0..basic_count];
    const ram_public = public[at + basic_count ..];
    // Original caller owner evaluates arithmetic, then RAM, then program/state/
    // table components. Keep this exact order in the enclosing Horner chain.
    const access_samples = SharedSamples{ .original = .{ .samples = samples, .map = &.{ 0, 6, 13 }, .fixed_start = fixed_start, .fixed_count = plan.schedule.fixed.len }, .points = &points, .current = concrete, .output = concrete.add(@import("../../air/logup.zig").liftPoint(core.poly.circle.canonic.CanonicCoset.new(p.shape.mask_log).coset_value.step).mulSigned(27)) };
    const memory = base_challenges.get(.memory_access);
    var memory_relation = @import("../../prover/block_v7_memory_relations_v1.zig").Relation(Field, 7){ .z = .{ .symbol = memory.z }, .powers = undefined };
    for (&memory_relation.powers, memory.alpha_powers[0..7]) |*v, scalar| v.* = .{ .symbol = scalar };
    const basic_width = plan.offsets.ram - plan.offsets.program;
    for (plan.ram.descriptors, ram_public, 0..) |d, sum, index| {
        const access = try Access.accessFromSamplesAs(Field, d, access_samples);
        const projected = try Ram.fromPair(Field, access.pair, memory_relation);
        var current: [4]Field = undefined;
        var prior: [4]Field = undefined;
        for (&current, &prior, 0..) |*now, *before, limb| {
            now.* = .{ .symbol = try samples.at(13, basic_width + 4 * index + limb, 0) };
            before.* = .{ .symbol = try samples.at(13, basic_width + 4 * index + limb, 1) };
        }
        const normalize = S.fromBase(try M.fromU64(@as(u64, 1) << @intCast(d.log_size)).inv());
        const denominator = try G.quotientDenominator(d.log_size, p.shape.mask_log, point, &cache);
        for (Ram.equations(Field, projected, current, prior, .{ .symbol = sum.mul(normalize) })) |eq| G.accumulate(accumulated, random, eq.symbol, denominator);
        count += 4;
    }
    var fp = try (core.air.components.Components{ .components = ctx.context.relation_masks, .n_preprocessed_columns = plan.schedule.fixed.len }).maskPoints(a, concrete, p.shape.mask_log, false);
    defer fp.deinitDeep(a);
    const fm = try mapped(a, &fp, &.{ 0, 6, 14, 13 }, &points, samples, fixed_start);
    const fused = Fused.Samples{ .offsets = .{ fm.offsets[0], fm.offsets[1], fm.offsets[2], fm.offsets[3], &.{} }, .lengths = .{ fm.lengths[0], fm.lengths[1], fm.lengths[2], fm.lengths[3], &.{} }, .values = fm.values };
    var schedule = plan.schedule;
    schedule.memory = &.{};
    schedule.rw_events = 0;
    const Admission = struct {
        pub const Prepared = struct { schedule: @TypeOf(schedule) };
    };
    count += try Fused.recordConstraintsFor(Admission, &.{ .schedule = schedule }, fused, basic_public, draws[0..47].*, H.flattenWord(draws[0..53].*), random, point, p.shape.mask_log, accumulated);
    for (plan.ram.descriptors, 0..) |d, index| {
        const access = try Access.accessFromSamplesAs(Field, d, access_samples);
        const aux = [2]Field{ .{ .symbol = try samples.at(6, plan.arithmetic_main_columns + 2 * index, 0) }, .{ .symbol = try samples.at(6, plan.arithmetic_main_columns + 2 * index + 1, 0) } };
        for (try Halt.constraints(Field, p.context.caller_guard.policy, access.pair, access.instruction_cycle, aux)) |eq| G.accumulate(accumulated, random, eq.symbol, try G.quotientDenominator(d.log_size, p.shape.mask_log, point, &cache));
        count += Halt.CONSTRAINT_COUNT;
    }
    return count;
}
