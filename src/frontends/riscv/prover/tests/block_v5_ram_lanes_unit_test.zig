//! Bounded nonproving oracle/degree/census/mask fixtures. No STARK or guest
//! execution is performed; generation produces only small witness prefixes.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const P = core.fields.packed_qm31.PackedQM31;
const Protocol = @import("../block_v5_ram_lanes_protocol_v1.zig");
const Air = @import("../../air/block/word_memory_lanes_v1.zig");
const TraceMod = @import("../../air/block/word_memory_lanes_trace_v1.zig");
const Trace = TraceMod.Trace;
const Interaction = @import("../block_v5_ram_lanes_interaction_v1.zig");
const Component = @import("../block_v5_ram_lanes_component_v1.zig");
const Word = @import("../../air/block/word_memory_v5.zig");
const Legacy = @import("../block_v5_word_memory_interaction_v1.zig");
const LegacyTrace = @import("../../air/block/word_memory_trace_v5.zig").Trace;
const Counter = @import("../block_v5_range16_v1.zig").Counter;
const Transition = @import("../../air/block/memory_transition.zig").Transition;
const WordProtocol = @import("../block_v5_word_memory_protocol_v1.zig");
const Placement = @import("../../air/block/memory_component_trace.zig");
const limits = TraceMod.Limits{ .max_row_log = 12, .max_events = 4096, .max_owned_bytes = 8 << 20 };
const events = [_]Transition{
    .{ .space = 1, .address = 0x2000, .clock = (@as(u64, 1) << 48) + 1, .before = 7, .after = 8 },
    .{ .space = 1, .address = 0x2000, .clock = (@as(u64, 1) << 48) + 2, .before = 8, .after = 9 },
    .{ .space = 1, .address = 0x2004, .clock = 1, .before = 11, .after = 12 },
    .{ .space = 1, .address = 0x2004, .clock = std.math.maxInt(u64) - 2, .before = 12, .after = 12 },
    .{ .space = 1, .address = 0x2004, .clock = std.math.maxInt(u64) - 1, .before = 12, .after = 13 },
    .{ .space = 1, .address = 0xffff_fffc, .clock = std.math.maxInt(u64) - 1, .before = 0xffff_0000, .after = 0xffff_ffff },
    .{ .space = 1, .address = 0xffff_fffc, .clock = std.math.maxInt(u64), .before = 0xffff_ffff, .after = 0xeeee_ffff },
};
fn geometry(start: usize, count: u32, row_log: u32) Protocol.Claim {
    return .{ .first_event = start, .total_events = events.len, .events = count, .row_log = row_log, .first = events[start], .last = events[start + count - 1], .preceding = if (start == 0) null else events[start - 1] };
}
fn challenges() Protocol.Challenges {
    return .{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() };
}
fn fraction(weight: Q, denominator: Q) !Q {
    return if (weight.isZero()) Q.zero() else weight.div(denominator);
}
fn oldTerms(ch: *const Protocol.Challenges, endpoints: *const Legacy.Endpoints, fixed: Word.Fixed, row: [Word.Layout.len]Q, previous: [Word.Layout.len]Q) Legacy.Algebra(Q).Terms {
    return Legacy.Algebra(Q).terms(ch, endpoints, fixed, row, previous, Word.rangePoints(fixed, row), true);
}
fn sum(values: []const Q) Q {
    var result = Q.zero();
    for (values) |value| result = result.add(value);
    return result;
}
fn nonzero(equations: anytype) bool {
    for (equations) |equation| if (!equation.isZero()) return true;
    return false;
}
fn prefixes(generated: *const Interaction.Generated, logical: usize, row_log: u32) [Interaction.COLUMN_COUNT]Q {
    const physical = Placement.committedRow(logical, row_log);
    var values: [Interaction.COLUMN_COUNT]Q = undefined;
    for (&values, generated.columns) |*out, column| out.* = Q.fromBase(column[physical]);
    return values;
}

test "block-v5 ram lanes preserves word-v4 row equations fractions counters public partitions and padding" {
    const a = std.testing.allocator;
    const ch = challenges();
    var table = try Interaction.RangeInverses.init(a, ch.range16);
    defer table.deinit();
    var total_link = Q.zero();
    var total_endpoint = Q.zero();
    var total_range: u64 = 0;
    const claims = [_]Protocol.Claim{ geometry(0, 1, 2), geometry(1, 2, 2), geometry(3, 4, 2) };
    try Protocol.admitSequence(&claims, events.len);
    for (claims) |claim| {
        var trace = try Trace.init(a, claim, limits);
        defer trace.deinit();
        var legacy = try LegacyTrace.init(a, claim.legacy());
        defer legacy.deinit();
        for (events[claim.first_event..][0..claim.events]) |event| {
            try trace.append(event);
            try legacy.append(event);
        }
        try trace.seal();
        try legacy.seal();
        var counter = try Counter.init(a);
        defer counter.deinit();
        var old_counter = try Counter.init(a);
        defer old_counter.deinit();
        var generated = try Interaction.generatePrepared(a, &trace, &ch, &counter, &table, 8 << 20);
        defer generated.deinit(a);
        var old_generated = try Legacy.generatePrepared(a, &legacy, &ch, &old_counter, &table);
        defer old_generated.deinit(a);
        try std.testing.expectEqualSlices(u32, old_counter.values, counter.values);
        try std.testing.expectEqual(old_counter.total, counter.total);
        try std.testing.expectEqualDeep(old_generated.claim.transition_sum, generated.claim.transition_sum);
        try std.testing.expectEqualDeep(old_generated.claim.link_sum, generated.claim.link_sum);
        try std.testing.expectEqualDeep(old_generated.claim.initial_sum, generated.claim.initial_sum);
        try std.testing.expectEqualDeep(old_generated.claim.endpoint_sum, generated.claim.endpoint_sum);
        try std.testing.expectEqual(old_generated.claim.endpoint_count, generated.claim.endpoint_count);
        try std.testing.expectEqual(old_generated.claim.range_count, generated.claim.range_count);
        try std.testing.expect(old_generated.claim.register_endpoint_sum.isZero());
        try std.testing.expectEqual(@as(u64, 0), old_generated.claim.register_endpoint_count);
        try std.testing.expectEqualDeep(sum(&old_generated.claim.range_sums), sum(&generated.claim.range_sums));
        const endpoints = try Interaction.publicEndpoints(claim, &ch);
        const shifts = try Interaction.normalize(generated.claim, claim);
        for (0..trace.domainSize()) |logical| {
            const row = trace.rowAt(logical);
            const prior = trace.rowAt(if (logical == 0) trace.domainSize() - 1 else logical - 1);
            const fixed = trace.fixedAt(logical);
            const direct = Air.constraints(claim, fixed, row, prior);
            try std.testing.expect(!nonzero(direct));
            // Exact direct-equation oracle, including the public shard edge.
            try std.testing.expectEqualDeep(Word.constraints(claim.legacy(), fixed[0], row[0], prior[1]), direct[0..Word.DIRECT_COUNT].*);
            try std.testing.expectEqualDeep(Word.constraints(claim.legacy(), fixed[1], row[1], row[0]), direct[Word.DIRECT_COUNT + 1 ..][0..Word.DIRECT_COUNT].*);
            const t = Interaction.terms(&ch, &endpoints, fixed, row, prior);
            const old = [2]Legacy.Algebra(Q).Terms{ oldTerms(&ch, &endpoints.legacy, fixed[0], row[0], prior[1]), oldTerms(&ch, &endpoints.legacy, fixed[1], row[1], row[0]) };
            var old_sums: [4]Q = @splat(Q.zero());
            for (old) |part| {
                old_sums[0] = old_sums[0].add(try fraction(part.weights[0], part.denominators[0]));
                old_sums[1] = old_sums[1].add(try fraction(part.weights[1], part.denominators[1])).add(try fraction(part.weights[2], part.denominators[2]));
                old_sums[2] = old_sums[2].add(try fraction(part.weights[3], part.denominators[3]));
                old_sums[3] = old_sums[3].add(try fraction(part.weights[4], part.denominators[4])).add(part.weights[5]);
            }
            const actual = [4]Q{ (try fraction(t.weights[0], t.denominators[0])).add(try fraction(t.weights[1], t.denominators[1])), (try fraction(t.weights[2], t.denominators[2])).add(try fraction(t.weights[3], t.denominators[3])).add(t.public_link), (try fraction(t.weights[4], t.denominators[4])).add(try fraction(t.weights[5], t.denominators[5])), (try fraction(t.weights[6], t.denominators[6])).add(try fraction(t.weights[7], t.denominators[7])).add(t.public_endpoint) };
            try std.testing.expectEqualDeep(old_sums, actual);
            try std.testing.expectEqualDeep(old[0].endpoint_count.add(old[1].endpoint_count), t.endpoint_count);
            try std.testing.expectEqualDeep(old[0].range_count.add(old[1].range_count), t.range_count);
            var current: [Interaction.COLUMN_COUNT]Q = undefined;
            var previous: [Interaction.COLUMN_COUNT]Q = undefined;
            const physical = Placement.committedRow(logical, claim.row_log);
            const prior_physical = Placement.committedRow(if (logical == 0) trace.domainSize() - 1 else logical - 1, claim.row_log);
            for (&current, &previous, generated.columns) |*out, *before, column| {
                out.* = Q.fromBase(column[physical]);
                before.* = Q.fromBase(column[prior_physical]);
            }
            try std.testing.expect(!nonzero(Interaction.constraintsPrepared(&ch, &endpoints, fixed, row, prior, current, previous, shifts)));
            if (2 * logical >= claim.events) {
                try std.testing.expect(t.range_count.isZero());
                for (actual) |value| try std.testing.expect(value.isZero());
            }
        }
        total_link = total_link.add(generated.claim.link_sum);
        total_endpoint = total_endpoint.add(generated.claim.endpoint_sum);
        total_range += generated.claim.range_count;
    }
    try std.testing.expect(total_link.isZero());
    var expected_endpoint = Q.zero();
    for ([_]usize{ 1, 4, 6 }) |index| expected_endpoint = expected_endpoint.add(try ch.endpoint.combineBase(WordProtocol.endpointTuple(events[index])).inv());
    try std.testing.expectEqualDeep(expected_endpoint, total_endpoint);
    try std.testing.expectEqual(@as(u64, 92), total_range);
    try std.testing.expectEqual(@as(usize, 54), Air.MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 24), Air.FIXED_COLUMNS);
    try std.testing.expectEqual(@as(usize, 92), Interaction.COLUMN_COUNT);
}

test "block-v5 ram lanes rejects value clock order lane permutation register and census mutations" {
    const a = std.testing.allocator;
    const claim = geometry(0, events.len, 3);
    var trace = try Trace.init(a, claim, limits);
    defer trace.deinit();
    for (events) |event| try trace.append(event);
    try trace.seal();
    const first = trace.rowAt(0);
    const previous = trace.rowAt(trace.domainSize() - 1);
    const fixed = trace.fixedAt(0);
    try std.testing.expect(!nonzero(Air.constraints(claim, fixed, first, previous)));
    var changed = first;
    changed[1][Word.Layout.before] = changed[1][Word.Layout.before].add(Q.one());
    try std.testing.expect(nonzero(Air.constraints(claim, fixed, changed, previous)));
    changed = first;
    changed[1][Word.Layout.current_clock + 3] = changed[1][Word.Layout.current_clock + 3].add(Q.one());
    try std.testing.expect(nonzero(Air.constraints(claim, fixed, changed, previous)));
    changed = .{ first[1], first[0] };
    try std.testing.expect(nonzero(Air.constraints(claim, fixed, changed, previous)));
    changed = first;
    changed[1][Word.Layout.current_key + 2] = Q.zero();
    try std.testing.expect(nonzero(Air.constraints(claim, fixed, changed, previous)));
    // Row1/lane0 starts a new address, so use row2/lane0's same-key chain.
    var changed_prior = trace.rowAt(1);
    changed_prior[1][Word.Layout.after] = changed_prior[1][Word.Layout.after].add(Q.one());
    try std.testing.expect(nonzero(Air.constraints(claim, trace.fixedAt(2), trace.rowAt(2), changed_prior)));
    var wrong = claim;
    wrong.register_custody_mode = 0;
    try std.testing.expectError(error.InvalidV5RamLanesGeometry, wrong.validate());
    wrong = claim;
    wrong.first.space = 0;
    try std.testing.expectError(error.InvalidV5RamLanesSpace, wrong.validate());
    wrong = claim;
    wrong.events = 17;
    try std.testing.expectError(error.InvalidV5RamLanesGeometry, wrong.validate());
    const shards = [_]Protocol.Claim{ geometry(0, 1, 2), geometry(1, 2, 2), geometry(3, 4, 2) };
    var reordered = shards;
    std.mem.swap(Protocol.Claim, &reordered[0], &reordered[1]);
    try std.testing.expectError(error.InvalidV5RamLanesCensus, Protocol.admitSequence(&reordered, events.len));
    try std.testing.expectError(error.InvalidV5RamLanesCensus, Protocol.admitSequence(shards[0..2], events.len));
    var predecessor_changed = shards;
    predecessor_changed[1].preceding.?.after ^= 1;
    if (Protocol.admitSequence(&predecessor_changed, events.len)) |_| return error.ExpectedRejection else |_| {}
    try std.testing.expectError(error.V5RamLanesResourceLimit, Trace.init(a, claim, .{ .max_row_log = 3, .max_events = 7, .max_owned_bytes = 1 }));
    const roots: [2][32]u8 = .{ @splat(1), @splat(2) };
    const original_id = try Protocol.instanceId(claim, roots);
    var different = claim;
    different.row_log = 4;
    try std.testing.expect(!std.meta.eql(original_id, try Protocol.instanceId(different, roots)));
    different = claim;
    different.last.after ^= 1;
    try std.testing.expect(!std.meta.eql(original_id, try Protocol.instanceId(different, roots)));
    different = claim;
    different.last.clock -= 1;
    try std.testing.expect(!std.meta.eql(original_id, try Protocol.instanceId(different, roots)));
    var changed_roots = roots;
    changed_roots[1][0] ^= 1;
    try std.testing.expect(!std.meta.eql(original_id, try Protocol.instanceId(claim, changed_roots)));
    try std.testing.expect(!std.meta.eql(Protocol.abiId(), WordProtocol.abiId()));
}

// Independent polynomial-degree semiring: constants0, variables1, sum=max,
// product=sum. It executes the actual generic equations, not a copied count.
const Degree = struct {
    n: u16,
    pub fn zero() Degree {
        return .{ .n = 0 };
    }
    pub fn one() Degree {
        return zero();
    }
    pub fn splat(_: Q) Degree {
        return zero();
    }
    pub fn add(left: Degree, right: Degree) Degree {
        return .{ .n = @max(left.n, right.n) };
    }
    pub fn sub(left: Degree, right: Degree) Degree {
        return left.add(right);
    }
    pub fn mul(left: Degree, right: Degree) Degree {
        return .{ .n = left.n + right.n };
    }
    pub fn neg(value: Degree) Degree {
        return value;
    }
    pub fn fromPartialEvals(values: [4]Degree) Degree {
        var out = zero();
        for (values) |value| out = out.add(value);
        return out;
    }
};
const DegreeRelation = struct {
    pub fn combineSecure(_: DegreeRelation, values: anytype) Degree {
        var out = Degree.zero();
        inline for (values) |value| out = out.add(value);
        return out;
    }
};
test "block-v5 ram lanes every direct and combined two-request plane has explicit degree at most four" {
    const variable = Degree{ .n = 1 };
    const row: Air.Algebra(Degree).Row = @splat(@as([27]Degree, @splat(variable)));
    const previous = row;
    var fixed: Air.Algebra(Degree).Fixed = undefined;
    for (&fixed) |*lane| lane.* = .{ .active = variable, .first = variable, .last = variable, .global_first = variable, .global_last = variable, .domain_last = variable, .ordinal = @splat(variable), .previous_ordinal = @splat(variable) };
    // Lane1 is never the first event in a shard; its independently reconstructed
    // fixed first polynomial is the constant zero, including at OODS.
    fixed[1].first = Degree.zero();
    const constants = Interaction.EndpointConstants(Degree){ .legacy = .{ .prior = @splat(Degree.zero()), .boundary_fraction = @splat(Degree.zero()), .final_fraction = @splat(Degree.zero()), .boundary_count = @splat(Degree.zero()), .final_count = @splat(Degree.zero()) }, .incoming_fraction = Degree.zero() };
    const DegreeChallenges = struct { transition: DegreeRelation = .{}, link: DegreeRelation = .{}, initial: DegreeRelation = .{}, endpoint: DegreeRelation = .{}, range16: DegreeRelation = .{} };
    const ch = DegreeChallenges{};
    const direct = Air.Algebra(Degree).constraints(geometry(0, events.len, 3), fixed, row, previous);
    for (direct, 0..) |value, i| {
        try std.testing.expect(value.n <= try Air.constraintDegree(i));
        try std.testing.expect(value.n <= Protocol.DEGREE);
    }
    const interaction = Interaction.Algebra(Degree).constraintsPrepared(&ch, &constants, fixed, row, previous, @splat(variable), @splat(variable), @splat(Degree.zero()));
    for (interaction, 0..) |value, i| {
        try std.testing.expect(value.n <= try Interaction.constraintDegree(i));
        try std.testing.expect(value.n <= Protocol.DEGREE);
    }
    try std.testing.expectEqual(@as(u16, 4), interaction[1].n);
    try std.testing.expectEqual(@as(u16, 4), interaction[3].n);
}

test "block-v5 ram lanes bounded component masks scalar packed parity and concrete API codegen" {
    const a = std.testing.allocator;
    const claim = geometry(0, events.len, 3);
    const ch = challenges();
    var trace = try Trace.init(a, claim, limits);
    defer trace.deinit();
    for (events) |event| try trace.append(event);
    try trace.seal();
    var table = try Interaction.RangeInverses.init(a, ch.range16);
    defer table.deinit();
    var counter = try Counter.init(a);
    defer counter.deinit();
    var generated = try Interaction.generatePrepared(a, &trace, &ch, &counter, &table, 8 << 20);
    defer generated.deinit(a);
    const spec = Component.Spec{ .claim = claim, .interaction_claim = generated.claim, .challenges = &ch };
    const component = try Component.Component.init(claim.row_log, spec);
    var bounds = try component.traceLogDegreeBounds(a);
    defer bounds.deinitDeep(a);
    try std.testing.expectEqual(@as(usize, 24), bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, 54), bounds.items[1].len);
    try std.testing.expectEqual(@as(usize, 92), bounds.items[2].len);
    const point = core.circle.secureFieldPoint(127);
    var masks = try component.maskPoints(a, point, claim.row_log);
    defer masks.deinitDeep(a);
    var shifts: usize = 0;
    for (masks.items[1], Component.Spec.PREVIOUS_MAIN_MASK) |samples, needed| {
        try std.testing.expectEqual(@as(usize, if (needed) 2 else 1), samples.len);
        shifts += @intFromBool(needed);
    }
    try std.testing.expectEqual(@as(usize, 9), shifts);
    for (masks.items[2]) |samples| try std.testing.expectEqual(@as(usize, 2), samples.len);
    const prepared = try spec.prepareDomain(claim.rowCapacity());
    var fixed: [Component.Spec.FIXED_COUNT]Q = undefined;
    var row: [Component.Spec.MAIN_COUNT]Q = undefined;
    var previous: [Component.Spec.MAIN_COUNT]Q = undefined;
    var current: [Component.Spec.INTERACTION_COUNT]Q = undefined;
    var before: [Component.Spec.INTERACTION_COUNT]Q = undefined;
    for (&fixed, 0..) |*out, i| out.* = Q.fromU32Unchecked(@intCast(3 + i), 7, 11, 13);
    // The reconstructed lane1 first selector is identically zero.
    fixed[TraceMod.FixedLayout.len + TraceMod.FixedLayout.first] = Q.zero();
    for (&row, &previous, 0..) |*out, *prior, i| {
        out.* = Q.fromU32Unchecked(@intCast(17 + i), 19, 23, 29);
        prior.* = Q.fromU32Unchecked(@intCast(31 + i), 37, 41, 43);
    }
    for (&current, &before, 0..) |*out, *prior, i| {
        out.* = Q.fromU32Unchecked(@intCast(47 + i), 53, 59, 61);
        prior.* = Q.fromU32Unchecked(@intCast(67 + i), 71, 73, 79);
    }
    var pfixed: [Component.Spec.FIXED_COUNT]P = undefined;
    var prow: [Component.Spec.MAIN_COUNT]P = undefined;
    var pprevious: [Component.Spec.MAIN_COUNT]P = undefined;
    var pcurrent: [Component.Spec.INTERACTION_COUNT]P = undefined;
    var pbefore: [Component.Spec.INTERACTION_COUNT]P = undefined;
    for (&pfixed, fixed) |*out, value| out.* = P.splat(value);
    for (&prow, row) |*out, value| out.* = P.splat(value);
    for (&pprevious, previous) |*out, value| out.* = P.splat(value);
    for (&pcurrent, current) |*out, value| out.* = P.splat(value);
    for (&pbefore, before) |*out, value| out.* = P.splat(value);
    const scalar = try prepared.evaluate(fixed, row, previous, current, before, claim.rowCapacity());
    const vector = prepared.evaluatePacked(pfixed, prow, pprevious, pcurrent, pbefore);
    for (scalar, vector) |wanted, actual| for (0..core.fields.m31.PACK_WIDTH) |lane| try std.testing.expectEqualDeep(wanted, actual.lane(lane));
    try checkPointDomain(&component);
    var wrong_count = generated.claim;
    wrong_count.event_count -= 1;
    try std.testing.expectError(error.InvalidV5RamLanesInteractionCensus, Interaction.normalize(wrong_count, claim));
    wrong_count = generated.claim;
    wrong_count.range_count = 1;
    try std.testing.expectError(error.InvalidV5RamLanesInteractionCensus, Interaction.normalize(wrong_count, claim));
    const domain: *const @TypeOf(Component.Component.evaluateConstraintQuotientsOnDomain) = &Component.Component.evaluateConstraintQuotientsOnDomain;
    const oods: *const @TypeOf(Component.Component.evaluateConstraintQuotientsAtPoint) = &Component.Component.evaluateConstraintQuotientsAtPoint;
    const proving: *const @TypeOf(Component.Component.asProverComponent) = &Component.Component.asProverComponent;
    std.mem.doNotOptimizeAway(domain);
    std.mem.doNotOptimizeAway(oods);
    std.mem.doNotOptimizeAway(proving);
}

/// Exact component OODS/domain parity on degree-one source polynomials.
/// Transforms and equations only: no commitments, FRI or STARK construction.
fn checkPointDomain(component: *const Component.Component) !void {
    const a = std.testing.allocator;
    const F = Component.Spec.FIXED_COUNT;
    const W = Component.Spec.MAIN_COUNT;
    const I = Component.Spec.INTERACTION_COUNT;
    const N = F + W + I;
    const log = component.inner.log_size;
    // The bounded caller uses row_log3, so all coefficient buffers are exact.
    if (log != 3) return error.InvalidFixtureGeometry;
    var coefficients: [N][8]M = undefined;
    var polys: [N]engine.air.component_prover.Poly = undefined;
    for (&coefficients, &polys, 0..) |*cells, *poly, index| {
        cells.* = @splat(M.zero());
        cells[0] = M.fromCanonical(@intCast(index + 7));
        cells[1] = M.fromCanonical(@intCast(3 * index + 11));
        if (index == TraceMod.FixedLayout.len + TraceMod.FixedLayout.first) cells.* = @splat(M.zero());
        poly.* = .{ .log_size = log, .values = &.{}, .coefficients = try engine.poly.circle.poly.CircleCoefficients.initBorrowed(cells) };
    }
    var poly_trees: [3][]const engine.air.component_prover.Poly = .{ polys[0..F], polys[F..][0..W], polys[F + W ..][0..I] };
    const trace = engine.air.component_prover.Trace{ .polys = core.pcs.TreeVec([]const engine.air.component_prover.Poly).initOwned(&poly_trees) };
    var fixed_storage: [F][1]Q = undefined;
    var main_storage: [W][2]Q = undefined;
    var interaction_storage: [I][2]Q = undefined;
    var fixed_mask: [F][]Q = undefined;
    var main_mask: [W][]Q = undefined;
    var interaction_mask: [I][]Q = undefined;
    for (&fixed_storage, &fixed_mask) |*cell, *view| view.* = cell;
    for (&main_storage, &main_mask, Component.Spec.PREVIOUS_MAIN_MASK) |*cell, *view, shifted| view.* = cell[0..if (shifted) @as(usize, 2) else 1];
    for (&interaction_storage, &interaction_mask) |*cell, *view| view.* = cell;
    var mask_trees: [3][][]Q = .{ &fixed_mask, &main_mask, &interaction_mask };
    const mask = core.air.components.MaskValues{ .items = &mask_trees };
    const alpha = Q.fromU32Unchecked(17, 19, 23, 29);
    const eval_log = log + Component.Spec.EXPANSION_BITS;
    // One domain output bucket folds all117 equations. The accumulator needs
    // a random coefficient for each equation, not merely for that one bucket.
    var accumulator = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, eval_log, component.nConstraints());
    defer accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace, &accumulator);
    const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
    for (0..domain.size()) |physical| {
        const base_point = domain.at(core.utils.bitReverseIndex(physical, eval_log));
        const point = core.circle.CirclePointQM31{ .x = Q.fromBase(base_point.x), .y = Q.fromBase(base_point.y) };
        const prior = @import("../../air/logup.zig").prevRowPoint(log, point);
        for (polys[0..F], &fixed_storage) |poly, *cell| cell.* = .{poly.coefficients.?.evalAtPoint(point)};
        for (polys[F..][0..W], &main_storage) |poly, *cell| cell.* = .{ poly.coefficients.?.evalAtPoint(point), poly.coefficients.?.evalAtPoint(prior) };
        for (polys[F + W ..][0..I], &interaction_storage) |poly, *cell| cell.* = .{ poly.coefficients.?.evalAtPoint(point), poly.coefficients.?.evalAtPoint(prior) };
        var expected = core.air.accumulation.PointEvaluationAccumulator.init(alpha);
        try component.evaluateConstraintQuotientsAtPoint(point, &mask, &expected, log);
        try std.testing.expectEqualDeep(expected.finalize(), accumulator.sub_accumulations[eval_log].?.at(physical));
    }
    // Missing the authenticated shifted lane1 endpoint or a prefix sample
    // must fail preflight rather than silently substituting a zero value.
    var unused = core.air.accumulation.PointEvaluationAccumulator.init(alpha);
    const shifted_column = Air.shiftedColumns[0];
    const saved = main_mask[shifted_column];
    main_mask[shifted_column] = saved[0..1];
    try std.testing.expectError(error.InvalidV5WordMask, component.evaluateConstraintQuotientsAtPoint(core.circle.secureFieldPoint(127), &mask, &unused, log));
    main_mask[shifted_column] = saved;
    interaction_mask[0] = interaction_mask[0][0..1];
    try std.testing.expectError(error.InvalidV5WordMask, component.evaluateConstraintQuotientsAtPoint(core.circle.secureFieldPoint(127), &mask, &unused, log));
}

fn streamingEvent(index: u32) Transition {
    return .{ .space = 1, .address = 0x4000, .clock = @as(u64, index) + 1, .before = index, .after = index + 1 };
}
test "block-v5 ram lanes streams beyond inverse batch boundary preserves odd tail and rejects prefix ordinal tampering" {
    const a = std.testing.allocator;
    const event_count: u32 = 2051;
    const claim = Protocol.Claim{ .first_event = 0, .total_events = event_count, .events = event_count, .row_log = 11, .first = streamingEvent(0), .last = streamingEvent(event_count - 1), .preceding = null };
    var trace = try Trace.init(a, claim, limits);
    defer trace.deinit();
    for (0..event_count) |index| try trace.append(streamingEvent(@intCast(index)));
    try trace.seal();
    const ch = challenges();
    var table = try Interaction.RangeInverses.init(a, ch.range16);
    defer table.deinit();
    var counter = try Counter.init(a);
    defer counter.deinit();
    var generated = try Interaction.generatePrepared(a, &trace, &ch, &counter, &table, 8 << 20);
    defer generated.deinit(a);
    const expected_range: u64 = 14 * @as(u64, event_count) - 4;
    try std.testing.expectEqual(expected_range, generated.claim.range_count);
    try std.testing.expectEqual(expected_range, counter.total);
    try std.testing.expectEqual(@as(u64, event_count), generated.claim.event_count);
    try std.testing.expectEqual(@as(u64, 1), generated.claim.endpoint_count);
    try std.testing.expect(generated.claim.link_sum.isZero());
    const endpoints = try Interaction.publicEndpoints(claim, &ch);
    const shifts = try Interaction.normalize(generated.claim, claim);
    // Exercise full and partial chunks, the odd final event, and wraparound
    // padding. Nothing stores an event-sized input buffer in this fixture.
    for ([_]usize{ 0, 1023, 1024, 1025, 1026, 2047 }) |logical| {
        const prior_logical = if (logical == 0) trace.domainSize() - 1 else logical - 1;
        const fixed = trace.fixedAt(logical);
        const row = trace.rowAt(logical);
        const prior = trace.rowAt(prior_logical);
        const current = prefixes(&generated, logical, claim.row_log);
        const previous = prefixes(&generated, prior_logical, claim.row_log);
        try std.testing.expect(!nonzero(Air.constraints(claim, fixed, row, prior)));
        try std.testing.expect(!nonzero(Interaction.constraintsPrepared(&ch, &endpoints, fixed, row, prior, current, previous, shifts)));
    }
    const logical: usize = 1024;
    const fixed = trace.fixedAt(logical);
    const row = trace.rowAt(logical);
    const prior = trace.rowAt(logical - 1);
    const current = prefixes(&generated, logical, claim.row_log);
    const previous = prefixes(&generated, logical - 1, claim.row_log);
    var changed = current;
    changed[4] = changed[4].add(Q.one()); // link prefix coordinate
    try std.testing.expect(nonzero(Interaction.constraintsPrepared(&ch, &endpoints, fixed, row, prior, changed, previous, shifts)));
    var wrong_fixed = fixed;
    wrong_fixed[0].previous_ordinal[0] = wrong_fixed[0].previous_ordinal[0].add(Q.one());
    try std.testing.expect(nonzero(Interaction.constraintsPrepared(&ch, &endpoints, wrong_fixed, row, prior, current, previous, shifts)));
    var wrong_prior = prior;
    wrong_prior[1][Word.Layout.after] = wrong_prior[1][Word.Layout.after].add(Q.one());
    try std.testing.expect(nonzero(Air.constraints(claim, fixed, row, wrong_prior)));
    const account = try Protocol.accounting(claim);
    try std.testing.expectEqual(@as(u64, 2048), account.row_capacity);
    try std.testing.expectEqual(@as(u64, event_count), account.events);
    try std.testing.expectEqual(@as(u64, 54 * 2048), account.main_cells);
    try std.testing.expectEqual(@as(u64, 24 * 2048), account.fixed_cells);
    try std.testing.expectEqual(@as(u64, 92 * 2048), account.interaction_cells);
    try std.testing.expectEqual(@as(u64, 170 * 2048), account.total_cells);
    try std.testing.expectEqual(@as(u64, 8 * 2048), account.variable_inverse_slots);
    try std.testing.expectError(error.V5RamLanesResourceLimit, Interaction.generatePrepared(a, &trace, &ch, &counter, &table, Interaction.SCRATCH_BYTES));
}
