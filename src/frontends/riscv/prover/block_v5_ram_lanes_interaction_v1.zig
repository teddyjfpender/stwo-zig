//! One prefix per plane for two RAM events. Fractions use the word-v4 buses;
//! intra-row link cancellation and constant public edges keep degree <=4.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Protocol = @import("block_v5_ram_lanes_protocol_v1.zig");
const WordProtocol = @import("block_v5_word_memory_protocol_v1.zig");
const Legacy = @import("block_v5_word_memory_interaction_v1.zig");
const Word = @import("../air/block/word_memory_v5.zig");
const Air = @import("../air/block/word_memory_lanes_v1.zig");
const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig").Trace;
const Placement = @import("../air/block/memory_component_trace.zig");
pub const RangeInverses = @import("block_v5_range16_inverse_table_v1.zig").Table;
pub const RANGE_PLANES = Word.RANGE_COUNT;
pub const PLANES = 6 + RANGE_PLANES;
pub const COLUMN_COUNT = 4 * PLANES;
pub const CONSTRAINT_COUNT = PLANES;
pub const SCRATCH_BYTES = 3 * 1024 * 8 * @sizeOf(Q);
comptime {
    if (COLUMN_COUNT != Protocol.INTERACTION_COLUMNS or CONSTRAINT_COUNT != Protocol.INTERACTION_CONSTRAINTS)
        @compileError("two-event RAM interaction planes disagree with the protocol ABI");
}
pub const Claim = struct {
    event_count: u64,
    transition_sum: Q,
    link_sum: Q,
    initial_sum: Q,
    endpoint_sum: Q,
    endpoint_count: u64,
    range_count: u64,
    range_sums: [RANGE_PLANES]Q,
};
pub const Normalized = [PLANES]Q;
pub fn normalize(claim: Claim, geometry: Protocol.Claim) !Normalized {
    try geometry.validate();
    const bounds = Word.rangeCountBounds(geometry.legacy());
    if (claim.event_count != geometry.events or claim.endpoint_count > claim.event_count or claim.endpoint_count >= core.fields.m31.Modulus or
        claim.range_count < bounds.minimum or claim.range_count > bounds.maximum or claim.range_count >= core.fields.m31.Modulus)
        return error.InvalidV5RamLanesInteractionCensus;
    const sums = [_]Q{ claim.transition_sum, claim.link_sum, claim.initial_sum, claim.endpoint_sum, Q.fromBase(M.fromCanonical(@intCast(claim.endpoint_count))), Q.fromBase(M.fromCanonical(@intCast(claim.range_count))) } ++ claim.range_sums;
    var result: Normalized = undefined;
    for (sums, &result) |sum, *out| {
        if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&sum)) return error.InvalidV5RamLanesInteractionClaim;
        out.* = try sum.divM31(M.fromCanonical(geometry.rowCapacity()));
    }
    return result;
}
pub fn EndpointConstants(comptime S: type) type {
    return struct { legacy: Legacy.EndpointConstants(S), incoming_fraction: S };
}
pub const Endpoints = EndpointConstants(Q);
pub fn publicEndpoints(claim: Protocol.Claim, challenges: *const Protocol.Challenges) !Endpoints {
    try claim.validate();
    var result = Endpoints{ .legacy = try Legacy.publicEndpoints(claim.legacy(), challenges), .incoming_fraction = Q.zero() };
    if (claim.preceding) |prior| result.incoming_fraction = try challenges.link.combineBase(WordProtocol.linkTuple(claim.first_event - 1, prior)).inv();
    return result;
}
pub fn liftEndpoints(comptime S: type, value: Endpoints) EndpointConstants(S) {
    if (S == Q) return value;
    return .{ .legacy = Legacy.liftEndpoints(S, value.legacy), .incoming_fraction = S.splat(value.incoming_fraction) };
}
pub const Terms = Algebra(Q).Terms;
pub const terms = Algebra(Q).terms;
pub const constraintsPrepared = Algebra(Q).constraintsPrepared;
pub fn Algebra(comptime S: type) type {
    return struct {
        const Self = @This();
        const Oracle = Word.Algebra(S);
        pub const Terms = struct {
            denominators: [8]S,
            weights: [8]S,
            public_link: S,
            public_endpoint: S,
            endpoint_count: S,
            range_count: S,
            points: [2][Word.RANGE_COUNT]Oracle.RangePoint,
        };
        pub fn terms(challenges: anytype, endpoints: *const EndpointConstants(S), fixed: Air.Algebra(S).Fixed, row: Air.Algebra(S).Row, previous: Air.Algebra(S).Row) Self.Terms {
            const one = S.one();
            const tuples = [2][WordProtocol.TRANSITION_ARITY]S{ Oracle.tuple(row[0]), Oracle.tuple(row[1]) };
            const ends = [2][WordProtocol.ENDPOINT_ARITY]S{ Oracle.endTuple(row[0]), Oracle.endTuple(row[1]) };
            const incoming = Oracle.endTuple(previous[1]);
            // On every active row, the outgoing event is lane1 if active,
            // otherwise lane0. Selection is an independently fixed selector.
            // emit(lane0) and consume(lane1) have identical tuple+ordinal and
            // cancel; odd partition tails retain lane0's outgoing link.
            var outgoing: [WordProtocol.ENDPOINT_ARITY]S = undefined;
            var outgoing_ordinal: [4]S = undefined;
            for (&outgoing, ends[0], ends[1]) |*out, left, right| out.* = left.add(fixed[1].active.mul(right.sub(left)));
            for (&outgoing_ordinal, fixed[0].ordinal, fixed[1].ordinal) |*out, left, right| out.* = left.add(fixed[1].active.mul(right.sub(left)));
            const gaps = [2]S{ row[0][Word.Layout.active].mul(one.sub(row[0][Word.Layout.same])).mul(one.sub(fixed[0].first)), row[1][Word.Layout.active].mul(one.sub(row[1][Word.Layout.same])).mul(one.sub(fixed[1].first)) };
            var result = Self.Terms{ .denominators = undefined, .weights = undefined, .public_link = fixed[0].first.mul(endpoints.incoming_fraction).neg(), .public_endpoint = S.zero(), .endpoint_count = gaps[0].add(gaps[1]), .range_count = S.zero(), .points = .{ Oracle.rangePoints(fixed[0], row[0]), Oracle.rangePoints(fixed[1], row[1]) } };
            for (0..2) |lane| {
                result.denominators[lane] = challenges.transition.combineSecure(tuples[lane]);
                result.weights[lane] = fixed[lane].active.neg();
                result.denominators[4 + lane] = challenges.initial.combineSecure(tuples[lane][0..3].* ++ tuples[lane][7..9].*);
                result.weights[4 + lane] = fixed[lane].global_first.add(row[lane][Word.Layout.active].mul(one.sub(row[lane][Word.Layout.same]))).neg();
                result.public_endpoint = result.public_endpoint.add(fixed[lane].first.mul(endpoints.legacy.boundary_fraction[0])).add(fixed[lane].global_last.mul(endpoints.legacy.final_fraction[0]));
                result.endpoint_count = result.endpoint_count.add(fixed[lane].first.mul(endpoints.legacy.boundary_count[0])).add(fixed[lane].global_last.mul(endpoints.legacy.final_count[0]));
                for (result.points[lane]) |point| result.range_count = result.range_count.add(point.weight);
            }
            result.denominators[2] = challenges.link.combineSecure(outgoing_ordinal ++ outgoing);
            result.weights[2] = fixed[0].active.sub(fixed[0].global_last).sub(fixed[1].global_last);
            // First-shard consumption is a typed constant fraction, rather
            // than mixing public and shifted cells into another degree2
            // denominator. The interior incoming denominator remains linear.
            result.denominators[3] = challenges.link.combineSecure(fixed[0].previous_ordinal ++ incoming);
            result.weights[3] = fixed[0].active.sub(fixed[0].first).neg();
            result.denominators[6] = challenges.endpoint.combineSecure(incoming);
            result.denominators[7] = challenges.endpoint.combineSecure(ends[0]);
            result.weights[6] = gaps[0];
            result.weights[7] = gaps[1];
            return result;
        }
        pub fn constraintsPrepared(challenges: anytype, endpoints: *const EndpointConstants(S), fixed: Air.Algebra(S).Fixed, row: Air.Algebra(S).Row, previous_row: Air.Algebra(S).Row, current: [COLUMN_COUNT]S, previous: [COLUMN_COUNT]S, normalized: [PLANES]S) [CONSTRAINT_COUNT]S {
            const t = Self.terms(challenges, endpoints, fixed, row, previous_row);
            var out: [CONSTRAINT_COUNT]S = undefined;
            out[0] = pair(delta(current, previous, 0, normalized[0]), t.denominators[0], t.denominators[1], t.weights[0], t.weights[1]);
            out[1] = pair(delta(current, previous, 1, normalized[1]).sub(t.public_link), t.denominators[2], t.denominators[3], t.weights[2], t.weights[3]);
            out[2] = pair(delta(current, previous, 2, normalized[2]), t.denominators[4], t.denominators[5], t.weights[4], t.weights[5]);
            out[3] = pair(delta(current, previous, 3, normalized[3]).sub(t.public_endpoint), t.denominators[6], t.denominators[7], t.weights[6], t.weights[7]);
            out[4] = delta(current, previous, 4, normalized[4]).sub(t.endpoint_count);
            out[5] = delta(current, previous, 5, normalized[5]).sub(t.range_count);
            for (0..RANGE_PLANES) |i| {
                const left = challenges.range16.combineSecure(.{t.points[0][i].value});
                const right = challenges.range16.combineSecure(.{t.points[1][i].value});
                out[6 + i] = pair(delta(current, previous, 6 + i, normalized[6 + i]), left, right, t.points[0][i].weight.neg(), t.points[1][i].weight.neg());
            }
            return out;
        }
        fn pair(change: S, left: S, right: S, wleft: S, wright: S) S {
            return change.mul(left).mul(right).sub(wleft.mul(right)).sub(wright.mul(left));
        }
        fn delta(current: [COLUMN_COUNT]S, previous: [COLUMN_COUNT]S, plane: usize, normalized: S) S {
            return S.fromPartialEvals(current[4 * plane ..][0..4].*).sub(S.fromPartialEvals(previous[4 * plane ..][0..4].*)).add(normalized);
        }
    };
}

/// Symbolic upper bounds, counting independently fixed selectors as degree1.
/// transition/initial/range pair: <=3; link select2 + incoming1 + delta1:4;
/// endpoint gated weight3*opposite denominator1:4; counters <=3/2.
pub fn constraintDegree(index: usize) !u8 {
    if (index >= CONSTRAINT_COUNT) return error.InvalidConstraintIndex;
    return switch (index) {
        0, 2 => 3,
        1, 3 => 4,
        4 => 3,
        5 => 2,
        else => 3,
    };
}
pub const Generated = struct {
    storage: []M,
    columns: [COLUMN_COUNT][]M,
    claim: Claim,
    pub fn deinit(self: *Generated, a: std.mem.Allocator) void {
        a.free(self.storage);
        self.* = undefined;
    }
};
pub fn generatePrepared(a: std.mem.Allocator, trace: *const Trace, challenges: *const Protocol.Challenges, counter: anytype, table: *const RangeInverses, max_bytes: usize) !Generated {
    if (!trace.sealed or trace.domainSize() >= core.fields.m31.Modulus) return error.InvalidV5RamLanesPhase;
    try table.requireRelation(challenges.range16);
    const bytes = try std.math.mul(usize, try std.math.mul(usize, trace.domainSize(), COLUMN_COUNT), @sizeOf(M));
    if (try std.math.add(usize, bytes, SCRATCH_BYTES) > max_bytes) return error.V5RamLanesResourceLimit;
    const endpoints = try publicEndpoints(trace.claim, challenges);
    const size = trace.domainSize();
    const storage = try a.alloc(M, bytes / @sizeOf(M));
    errdefer a.free(storage);
    var columns: [COLUMN_COUNT][]M = undefined;
    for (&columns, 0..) |*column, i| column.* = storage[i * size ..][0..size];
    var totals: [PLANES]Q = @splat(Q.zero());
    var endpoint_count: u64 = 0;
    var range_count: u64 = 0;
    const CHUNK: usize = 1024;
    const TERM_COUNT: usize = 8;
    const denominators = try a.alloc(Q, CHUNK * TERM_COUNT);
    defer a.free(denominators);
    const inverses = try a.alloc(Q, CHUNK * TERM_COUNT);
    defer a.free(inverses);
    const weights = try a.alloc(Q, CHUNK * TERM_COUNT);
    defer a.free(weights);
    var begin: usize = 0;
    while (begin < size) {
        const count: usize = @min(CHUNK, size - begin);
        const n_terms = try std.math.mul(usize, count, TERM_COUNT);
        for (0..count) |i| {
            const logical = begin + i;
            const physical = Placement.committedRow(logical, trace.claim.row_log);
            const t = terms(challenges, &endpoints, trace.fixedAt(logical), trace.rowAt(logical), trace.rowAt(if (logical == 0) size - 1 else logical - 1));
            endpoint_count = try std.math.add(u64, endpoint_count, try natural(t.endpoint_count));
            range_count = try std.math.add(u64, range_count, try natural(t.range_count));
            write(&columns, 1, physical, t.public_link);
            write(&columns, 3, physical, t.public_endpoint);
            write(&columns, 4, physical, t.endpoint_count);
            write(&columns, 5, physical, t.range_count);
            for (0..RANGE_PLANES) |point| {
                var sum = Q.zero();
                for (0..2) |lane| {
                    const query = t.points[lane][point];
                    sum = sum.add(try table.fraction(query.value, query.weight.neg()));
                    if (query.weight.isZero()) continue;
                    if (!query.weight.eql(Q.one())) return error.InvalidV5RamLanesMultiplicity;
                    const limbs = query.value.toM31Array();
                    for (limbs[1..]) |limb| if (!limb.isZero()) return error.InvalidWordRangeValue;
                    try counter.add(limbs[0].toU32());
                }
                write(&columns, 6 + point, physical, sum);
                totals[6 + point] = totals[6 + point].add(sum);
            }
            for (t.denominators, t.weights, 0..) |denominator, weight, at| {
                denominators[i * TERM_COUNT + at] = if (weight.isZero()) Q.one() else denominator;
                weights[i * TERM_COUNT + at] = weight;
            }
        }
        try core.fields.batchInverseInPlace(Q, denominators[0..n_terms], inverses[0..n_terms]);
        for (0..count) |i| {
            const physical = Placement.committedRow(begin + i, trace.claim.row_log);
            var values: [TERM_COUNT]Q = undefined;
            for (&values, 0..) |*out, term| out.* = inverses[i * TERM_COUNT + term].mul(weights[i * TERM_COUNT + term]);
            const row_sums = [_]Q{ values[0].add(values[1]), values[2].add(values[3]).add(read(&columns, 1, physical)), values[4].add(values[5]), values[6].add(values[7]).add(read(&columns, 3, physical)), read(&columns, 4, physical), read(&columns, 5, physical) };
            for (row_sums, 0..) |sum, plane| {
                write(&columns, plane, physical, sum);
                totals[plane] = totals[plane].add(sum);
            }
        }
        begin += count;
    }
    var running: [PLANES]Q = @splat(Q.zero());
    var shifts: [PLANES]Q = undefined;
    for (totals, &shifts) |sum, *out| out.* = try sum.divM31(M.fromCanonical(@intCast(size)));
    for (0..size) |logical| {
        const physical = Placement.committedRow(logical, trace.claim.row_log);
        for (&running, shifts, 0..) |*sum, shift, plane| {
            sum.* = sum.add(read(&columns, plane, physical)).sub(shift);
            write(&columns, plane, physical, sum.*);
        }
    }
    for (running) |sum| if (!sum.isZero()) return error.InvalidV5RamLanesPrefix;
    const claim = Claim{ .event_count = trace.claim.events, .transition_sum = totals[0], .link_sum = totals[1], .initial_sum = totals[2], .endpoint_sum = totals[3], .endpoint_count = endpoint_count, .range_count = range_count, .range_sums = totals[6..].* };
    _ = try normalize(claim, trace.claim);
    return .{ .storage = storage, .columns = columns, .claim = claim };
}
fn natural(value: Q) !u32 {
    const limbs = value.toM31Array();
    for (limbs[1..]) |limb| if (!limb.isZero()) return error.InvalidV5RamLanesMultiplicity;
    return limbs[0].toU32();
}
fn write(columns: *[COLUMN_COUNT][]M, plane: usize, row: usize, value: Q) void {
    for (value.toM31Array(), 0..) |cell, limb| columns[4 * plane + limb][row] = cell;
}
fn read(columns: *const [COLUMN_COUNT][]M, plane: usize, row: usize) Q {
    return Q.fromM31Array(.{ columns[4 * plane][row], columns[4 * plane + 1][row], columns[4 * plane + 2][row], columns[4 * plane + 3][row] });
}
