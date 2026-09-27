//! Packed-word sorted transition/link/initial/endpoint and range16 LogUps.
//! All terms come from the same27 committed main columns used by the AIR.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const air = @import("../air/block/word_memory_v5.zig");
const trace_mod = @import("../air/block/word_memory_trace_v5.zig");
const physical_mod = @import("../air/block/memory_component_trace.zig");
const protocol = @import("block_v5_word_memory_protocol_v1.zig");
pub const RangeInverses = @import("block_v5_range16_inverse_table_v1.zig").Table;
pub const RANGE_BATCHES = (air.RANGE_COUNT + 1) / 2;
pub const COLUMN_COUNT = 32 + 4 * RANGE_BATCHES;
pub const CONSTRAINT_COUNT = 8 + RANGE_BATCHES;
pub const Claim = struct { transition_sum: Q, link_sum: Q, initial_sum: Q, endpoint_sum: Q, endpoint_count: u64, register_endpoint_sum: Q, register_endpoint_count: u64, range_count: u64, range_sums: [RANGE_BATCHES]Q };
pub const Normalized = [COLUMN_COUNT / 4]Q;
pub fn normalize(claim: Claim, size: u32) !Normalized {
    if (size == 0 or size >= core.fields.m31.Modulus or claim.endpoint_count >= core.fields.m31.Modulus or claim.register_endpoint_count >= core.fields.m31.Modulus or claim.range_count >= core.fields.m31.Modulus) return error.InvalidWordMemoryClaim;
    const inverse = try M.fromCanonical(size).inv();
    const sums = [_]Q{ claim.transition_sum, claim.link_sum, claim.initial_sum, claim.endpoint_sum, Q.fromBase(M.fromCanonical(@intCast(claim.endpoint_count))), Q.fromBase(M.fromCanonical(@intCast(claim.range_count))), claim.register_endpoint_sum, Q.fromBase(M.fromCanonical(@intCast(claim.register_endpoint_count))) } ++ claim.range_sums;
    var result: Normalized = undefined;
    for (sums, &result) |sum, *value| value.* = sum.mulM31(inverse);
    return result;
}
pub fn EndpointConstants(comptime S: type) type {
    return struct { prior: [protocol.ENDPOINT_ARITY]S, boundary_fraction: [2]S, final_fraction: [2]S, boundary_count: [2]S, final_count: [2]S };
}
pub const Endpoints = EndpointConstants(Q);
/// Constant public supplies are independently reconstructed from the pinned
/// typed claim. Only an actually used denominator is inverted, so an unused
/// singular public tuple cannot nullify any endpoint recurrence.
pub fn publicEndpoints(claim: @import("../air/block/memory_component.zig").Claim, challenges: *const protocol.Challenges) !Endpoints {
    try air.validatePublicClaim(claim);
    var result = Endpoints{ .prior = @splat(Q.zero()), .boundary_fraction = @splat(Q.zero()), .final_fraction = @splat(Q.zero()), .boundary_count = @splat(Q.zero()), .final_count = @splat(Q.zero()) };
    if (claim.preceding) |prior| {
        _ = try @import("../air/block/memory_transition.zig").adjacency(prior, claim.first);
        const tuple = protocol.endpointTuple(prior);
        for (&result.prior, tuple) |*out, cell| out.* = Q.fromBase(cell);
        if (prior.space != claim.first.space or prior.address != claim.first.address) {
            const part: usize = if (prior.space == 1) 0 else 1;
            result.boundary_fraction[part] = try challenges.endpoint.combineBase(tuple).inv();
            result.boundary_count[part] = Q.one();
        }
    }
    if (claim.first_row + claim.rows == claim.total_rows) {
        const part: usize = if (claim.last.space == 1) 0 else 1;
        result.final_fraction[part] = try challenges.endpoint.combineBase(protocol.endpointTuple(claim.last)).inv();
        result.final_count[part] = Q.one();
    }
    return result;
}
pub fn liftEndpoints(comptime S: type, source: Endpoints) EndpointConstants(S) {
    if (S == Q) return source;
    var result: EndpointConstants(S) = undefined;
    inline for (@typeInfo(Endpoints).@"struct".fields) |field| {
        for (&@field(result, field.name), @field(source, field.name)) |*out, value| out.* = S.splat(value);
    }
    return result;
}
pub fn constraints(challenges: *const protocol.Challenges, endpoints: *const Endpoints, fixed: air.Fixed, row: [air.Layout.len]Q, previous_row: [air.Layout.len]Q, current: [COLUMN_COUNT]Q, previous: [COLUMN_COUNT]Q, claim: Claim, size: u32) ![CONSTRAINT_COUNT]Q {
    return constraintsPrepared(challenges, endpoints, fixed, row, previous_row, current, previous, try normalize(claim, size));
}
fn terms(challenges: *const protocol.Challenges, endpoints: *const Endpoints, fixed: air.Fixed, row: [air.Layout.len]Q, previous_row: [air.Layout.len]Q, points: [air.RANGE_COUNT]air.RangePoint, comptime range_denominators: bool) Algebra(Q).Terms {
    return Algebra(Q).terms(challenges, endpoints, fixed, row, previous_row, points, range_denominators);
}
pub fn constraintsPrepared(challenges: *const protocol.Challenges, endpoints: *const Endpoints, fixed: air.Fixed, row: [air.Layout.len]Q, previous_row: [air.Layout.len]Q, current: [COLUMN_COUNT]Q, previous: [COLUMN_COUNT]Q, normalized: Normalized) [CONSTRAINT_COUNT]Q {
    return Algebra(Q).constraintsPrepared(challenges, endpoints, fixed, row, previous_row, current, previous, normalized);
}
pub fn Algebra(comptime S: type) type {
    return struct {
        const Word = air.Algebra(S);
        pub const Terms = struct { denominators: [8 + air.RANGE_COUNT]S, weights: [8 + air.RANGE_COUNT]S, endpoint_count: S, register_endpoint_count: S, range_count: S };
        pub fn terms(challenges: anytype, endpoints: *const EndpointConstants(S), fixed: Word.Fixed, row: [air.Layout.len]S, previous_row: [air.Layout.len]S, points: [air.RANGE_COUNT]Word.RangePoint, comptime range_denominators: bool) Terms {
            const current = Word.tuple(row);
            const shifted = Word.endTuple(previous_row);
            const previous = Word.predecessor(endpoints.prior, fixed, previous_row);
            const last = Word.endTuple(row);
            const initial = current[0..3].* ++ current[7..9].*;
            var result = Terms{ .denominators = undefined, .weights = undefined, .endpoint_count = S.zero(), .register_endpoint_count = S.zero(), .range_count = S.zero() };
            result.denominators[0] = challenges.transition.combineSecure(current);
            result.weights[0] = fixed.active.neg();
            result.denominators[1] = challenges.link.combineSecure(fixed.ordinal ++ last);
            result.weights[1] = fixed.active.sub(fixed.global_last);
            result.denominators[2] = challenges.link.combineSecure(fixed.previous_ordinal ++ previous);
            result.weights[2] = fixed.active.sub(fixed.global_first).neg();
            result.denominators[3] = challenges.initial.combineSecure(initial);
            result.weights[3] = fixed.global_first.add(row[air.Layout.active].mul(S.one().sub(row[air.Layout.same]))).neg();
            const interior_gate = row[air.Layout.active].mul(S.one().sub(row[air.Layout.same])).mul(S.one().sub(fixed.first));
            result.denominators[4] = challenges.endpoint.combineSecure(shifted);
            result.weights[4] = interior_gate.mul(shifted[0]);
            // Public fractions have constant denominators. Clearing only the
            // interior denominator keeps degree4 and all68 interaction cells.
            result.denominators[5] = S.one();
            result.weights[5] = fixed.first.mul(endpoints.boundary_fraction[0]).add(fixed.global_last.mul(endpoints.final_fraction[0]));
            result.endpoint_count = result.weights[4].add(fixed.first.mul(endpoints.boundary_count[0])).add(fixed.global_last.mul(endpoints.final_count[0]));
            result.denominators[6] = result.denominators[4];
            result.weights[6] = interior_gate.mul(S.one().sub(shifted[0]));
            result.denominators[7] = S.one();
            result.weights[7] = fixed.first.mul(endpoints.boundary_fraction[1]).add(fixed.global_last.mul(endpoints.final_fraction[1]));
            result.register_endpoint_count = result.weights[6].add(fixed.first.mul(endpoints.boundary_count[1])).add(fixed.global_last.mul(endpoints.final_count[1]));
            for (points, 0..) |request, index| {
                if (range_denominators) result.denominators[8 + index] = challenges.range16.combineSecure(.{request.value});
                result.weights[8 + index] = request.weight.neg();
                result.range_count = result.range_count.add(request.weight);
            }
            return result;
        }
        pub fn constraintsPrepared(challenges: anytype, endpoints: *const EndpointConstants(S), fixed: Word.Fixed, row: [air.Layout.len]S, previous_row: [air.Layout.len]S, current: [COLUMN_COUNT]S, previous: [COLUMN_COUNT]S, normalized: [COLUMN_COUNT / 4]S) [CONSTRAINT_COUNT]S {
            @setEvalBranchQuota(200000);
            const t = @This().terms(challenges, endpoints, fixed, row, previous_row, Word.rangePoints(fixed, row), true);
            var result: [CONSTRAINT_COUNT]S = undefined;
            result[0] = delta(current, previous, 0, normalized[0]).mul(t.denominators[0]).sub(t.weights[0]);
            result[1] = pairResidual(delta(current, previous, 4, normalized[1]), t.denominators[1], t.denominators[2], t.weights[1], t.weights[2]);
            result[2] = delta(current, previous, 8, normalized[2]).mul(t.denominators[3]).sub(t.weights[3]);
            result[3] = pairResidual(delta(current, previous, 12, normalized[3]), t.denominators[4], t.denominators[5], t.weights[4], t.weights[5]);
            result[4] = delta(current, previous, 16, normalized[4]).sub(t.endpoint_count);
            result[5] = delta(current, previous, 20, normalized[5]).sub(t.range_count);
            result[6] = pairResidual(delta(current, previous, 24, normalized[6]), t.denominators[6], t.denominators[7], t.weights[6], t.weights[7]);
            result[7] = delta(current, previous, 28, normalized[7]).sub(t.register_endpoint_count);
            for (0..RANGE_BATCHES) |batch| {
                const first = 8 + 2 * batch;
                const second_denominator = if (2 * batch + 1 < air.RANGE_COUNT) t.denominators[first + 1] else S.one();
                const second_weight = if (2 * batch + 1 < air.RANGE_COUNT) t.weights[first + 1] else S.zero();
                result[8 + batch] = pairResidual(delta(current, previous, 32 + 4 * batch, normalized[8 + batch]), t.denominators[first], second_denominator, t.weights[first], second_weight);
            }
            return result;
        }
        fn pairResidual(change: S, left: S, right: S, left_weight: S, right_weight: S) S {
            return change.mul(left).mul(right).sub(left_weight.mul(right)).sub(right_weight.mul(left));
        }
        fn delta(current: [COLUMN_COUNT]S, previous: [COLUMN_COUNT]S, at: usize, normalized: S) S {
            return secure(current, at).sub(secure(previous, at)).add(normalized);
        }
        fn secure(values: [COLUMN_COUNT]S, at: usize) S {
            return S.fromPartialEvals(values[at..][0..4].*);
        }
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
/// The table counter is committed before sealing; replaying interaction may
/// collect into a local counter and require exact digest equality afterward.
pub fn generate(a: std.mem.Allocator, trace: *const trace_mod.Trace, challenges: *const protocol.Challenges, counter: anytype) !Generated {
    var table = try RangeInverses.init(a, challenges.range16);
    defer table.deinit();
    return generatePrepared(a, trace, challenges, counter, &table);
}
pub fn generatePrepared(a: std.mem.Allocator, trace: *const trace_mod.Trace, challenges: *const protocol.Challenges, counter: anytype, table: *const RangeInverses) !Generated {
    if (!trace.sealed or trace.domainSize() >= core.fields.m31.Modulus) return error.InvalidWordMemoryPhase;
    try table.requireRelation(challenges.range16);
    const endpoints = try publicEndpoints(trace.claim, challenges);
    const size = trace.domainSize();
    const storage = try a.alloc(M, size * COLUMN_COUNT);
    errdefer a.free(storage);
    var columns: [COLUMN_COUNT][]M = undefined;
    for (&columns, 0..) |*column, i| column.* = storage[i * size ..][0..size];
    var totals: [COLUMN_COUNT / 4]Q = @splat(Q.zero());
    var endpoint_count: u64 = 0;
    var range_count: u64 = 0;
    var register_endpoint_count: u64 = 0;
    const ROW_TERMS = 8;
    const CHUNK: usize = 1024;
    const denominators = try a.alloc(Q, CHUNK * ROW_TERMS);
    defer a.free(denominators);
    const inverses = try a.alloc(Q, CHUNK * ROW_TERMS);
    defer a.free(inverses);
    const numerators = try a.alloc(Q, CHUNK * ROW_TERMS);
    defer a.free(numerators);
    var begin: usize = 0;
    while (begin < size) {
        // Keep the chunk count usize in ReleaseFast before multiplying.
        const count: usize = @min(CHUNK, size - begin);
        const term_count = try std.math.mul(usize, count, ROW_TERMS);
        for (0..count) |offset| {
            const logical = begin + offset;
            const row = trace.rowAt(logical);
            const fixed = trace.fixedAt(logical);
            const points = air.rangePoints(fixed, row);
            const previous_row = trace.rowAt(if (logical == 0) size - 1 else logical - 1);
            const t = terms(challenges, &endpoints, fixed, row, previous_row, points, false);
            const endpoint_increment = try natural(t.endpoint_count);
            const range_increment = try natural(t.range_count);
            register_endpoint_count = try std.math.add(u64, register_endpoint_count, try natural(t.register_endpoint_count));
            endpoint_count = try std.math.add(u64, endpoint_count, endpoint_increment);
            range_count = try std.math.add(u64, range_count, range_increment);
            var range_values: [air.RANGE_COUNT]Q = undefined;
            for (points, &range_values) |request, *fraction| {
                fraction.* = try table.fraction(request.value, request.weight.neg());
                if (request.weight.isZero()) continue;
                if (!request.weight.eql(Q.one())) return error.InvalidWordRangeMultiplicity;
                const limbs = request.value.toM31Array();
                for (limbs[1..]) |limb| if (!limb.isZero()) return error.InvalidWordRangeValue;
                try counter.add(limbs[0].toU32());
            }
            for (0..RANGE_BATCHES) |batch| {
                const first = 2 * batch;
                const fraction = range_values[first].add(if (first + 1 < air.RANGE_COUNT) range_values[first + 1] else Q.zero());
                write(&columns, 32 + 4 * batch, physical_mod.committedRow(logical, trace.claim.log_size), fraction);
                totals[8 + batch] = totals[8 + batch].add(fraction);
            }
            for (t.denominators[0..ROW_TERMS], t.weights[0..ROW_TERMS], 0..) |denominator, weight, index| {
                denominators[offset * ROW_TERMS + index] = if (weight.isZero()) Q.one() else denominator;
                numerators[offset * ROW_TERMS + index] = weight;
            }
            const physical = physical_mod.committedRow(logical, trace.claim.log_size);
            write(&columns, 16, physical, t.endpoint_count);
            write(&columns, 20, physical, t.range_count);
            write(&columns, 28, physical, t.register_endpoint_count);
        }
        try core.fields.batchInverseInPlace(Q, denominators[0..term_count], inverses[0..term_count]);
        for (0..count) |offset| {
            const physical = physical_mod.committedRow(begin + offset, trace.claim.log_size);
            var values: [ROW_TERMS]Q = undefined;
            for (&values, 0..) |*value, index| value.* = inverses[offset * ROW_TERMS + index].mul(numerators[offset * ROW_TERMS + index]);
            const terms_by_bus = [_]Q{ values[0], values[1].add(values[2]), values[3], values[4].add(values[5]), read(&columns, 16, physical), read(&columns, 20, physical), values[6].add(values[7]), read(&columns, 28, physical) };
            for (terms_by_bus, 0..) |value, index| {
                write(&columns, index * 4, physical, value);
                totals[index] = totals[index].add(value);
            }
        }
        begin += count;
    }
    if (endpoint_count >= core.fields.m31.Modulus or register_endpoint_count >= core.fields.m31.Modulus or range_count >= core.fields.m31.Modulus) return error.InvalidWordMemoryCensus;
    var running: [COLUMN_COUNT / 4]Q = @splat(Q.zero());
    var shifts: [COLUMN_COUNT / 4]Q = undefined;
    for (totals, &shifts) |total, *shift| shift.* = try total.divM31(M.fromCanonical(@intCast(size)));
    for (0..size) |logical| {
        const physical = physical_mod.committedRow(logical, trace.claim.log_size);
        for (&running, shifts, 0..) |*sum, shift, index| {
            sum.* = sum.add(read(&columns, index * 4, physical)).sub(shift);
            write(&columns, index * 4, physical, sum.*);
        }
    }
    for (running) |sum| if (!sum.isZero()) return error.InvalidWordMemoryPrefix;
    return .{ .storage = storage, .columns = columns, .claim = .{ .transition_sum = totals[0], .link_sum = totals[1], .initial_sum = totals[2], .endpoint_sum = totals[3], .endpoint_count = endpoint_count, .register_endpoint_sum = totals[6], .register_endpoint_count = register_endpoint_count, .range_count = range_count, .range_sums = totals[8..].* } };
}
fn natural(value: Q) !u32 {
    const limbs = value.toM31Array();
    for (limbs[1..]) |limb| if (!limb.isZero()) return error.InvalidWordMemoryMultiplicity;
    return limbs[0].toU32();
}
fn read(columns: *const [COLUMN_COUNT][]M, at: usize, row: usize) Q {
    return Q.fromM31Array(.{ columns[at][row], columns[at + 1][row], columns[at + 2][row], columns[at + 3][row] });
}
fn write(columns: *[COLUMN_COUNT][]M, at: usize, row: usize, value: Q) void {
    for (value.toM31Array(), 0..) |limb, i| columns[at + i][row] = limb;
}

test "block-v5 word27 public endpoint fractions preserve exact buses and all row equations" {
    const a = std.testing.allocator;
    const Transition = @import("../air/block/memory_transition.zig").Transition;
    const events = [_]Transition{
        .{ .space = 0, .address = 31, .clock = (@as(u64, 1) << 48) + 1, .before = 7, .after = 7 },
        .{ .space = 1, .address = 0x2000, .clock = (@as(u64, 1) << 48) + 2, .before = 9, .after = 10 },
        .{ .space = 1, .address = 0x2000, .clock = (@as(u64, 1) << 48) + 3, .before = 10, .after = 11 },
        .{ .space = 1, .address = 0x2004, .clock = (@as(u64, 1) << 48) + 4, .before = 0, .after = 1 },
        .{ .space = 1, .address = 0xffff_fffc, .clock = std.math.maxInt(u64), .before = 0xffff_ffff, .after = 0xffff_ffff },
    };
    const challenges = protocol.Challenges{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() };
    // Independently sized shards exercise public and interior supplies,
    // both spaces, same-key continuity, padding and the global final row.
    var complete_endpoint = Q.zero();
    var complete_register = Q.zero();
    var complete_link = Q.zero();
    var complete_ranges: u64 = 0;
    var inverse_table = try RangeInverses.init(a, challenges.range16);
    defer inverse_table.deinit();
    for ([_]usize{ 0, 1, 3 }) |start| {
        const count: u32 = if (start == 0) 1 else 2;
        const claim = @import("../air/block/memory_component.zig").Claim{ .first_row = start, .total_rows = events.len, .rows = count, .log_size = 2, .first = events[start], .last = events[start + count - 1], .preceding = if (start == 0) null else events[start - 1] };
        var trace = try trace_mod.Trace.init(a, claim);
        defer trace.deinit();
        for (events[start..][0..count]) |event| try trace.append(event);
        try trace.seal();
        const endpoints = try publicEndpoints(claim, &challenges);
        var counter = try @import("block_v5_range16_v1.zig").Counter.init(a);
        defer counter.deinit();
        var generated = try generatePrepared(a, &trace, &challenges, &counter, &inverse_table);
        defer generated.deinit(a);
        const normalized = try normalize(generated.claim, @intCast(trace.domainSize()));
        for (0..trace.domainSize()) |logical| {
            const prior_logical = if (logical == 0) trace.domainSize() - 1 else logical - 1;
            const row = trace.rowAt(logical);
            const prior_row = trace.rowAt(prior_logical);
            const fixed = trace.fixedAt(logical);
            const t = terms(&challenges, &endpoints, fixed, row, prior_row, air.rangePoints(fixed, row), true);
            var wanted: [2]Q = @splat(Q.zero());
            if (logical < count) {
                const index = start + logical;
                if (index != 0 and (events[index - 1].space != events[index].space or events[index - 1].address != events[index].address)) {
                    const part: usize = if (events[index - 1].space == 1) 0 else 1;
                    wanted[part] = try challenges.endpoint.combineBase(protocol.endpointTuple(events[index - 1])).inv();
                }
                if (index + 1 == events.len) {
                    const part: usize = if (events[index].space == 1) 0 else 1;
                    wanted[part] = wanted[part].add(try challenges.endpoint.combineBase(protocol.endpointTuple(events[index])).inv());
                }
            }
            inline for (0..2) |part| {
                const at = 4 + 2 * part;
                const interior = if (t.weights[at].isZero()) Q.zero() else try t.weights[at].div(t.denominators[at]);
                try std.testing.expectEqual(wanted[part], interior.add(t.weights[at + 1]));
                try std.testing.expect(t.denominators[at + 1].eql(Q.one()));
            }
            var current: [COLUMN_COUNT]Q = undefined;
            var previous: [COLUMN_COUNT]Q = undefined;
            const physical = physical_mod.committedRow(logical, claim.log_size);
            const prior_physical = physical_mod.committedRow(prior_logical, claim.log_size);
            for (&current, &previous, generated.columns) |*out, *prior_out, column| {
                out.* = Q.fromBase(column[physical]);
                prior_out.* = Q.fromBase(column[prior_physical]);
            }
            for (air.constraints(claim, fixed, row, prior_row) ++ constraintsPrepared(&challenges, &endpoints, fixed, row, prior_row, current, previous, normalized)) |equation| try std.testing.expect(equation.isZero());
        }
        complete_endpoint = complete_endpoint.add(generated.claim.endpoint_sum);
        complete_register = complete_register.add(generated.claim.register_endpoint_sum);
        complete_link = complete_link.add(generated.claim.link_sum);
        complete_ranges += generated.claim.range_count;
    }
    var expected_endpoint = Q.zero();
    for ([_]usize{ 2, 3, 4 }) |index| expected_endpoint = expected_endpoint.add(try challenges.endpoint.combineBase(protocol.endpointTuple(events[index])).inv());
    try std.testing.expectEqual(expected_endpoint, complete_endpoint);
    try std.testing.expectEqual(try challenges.endpoint.combineBase(protocol.endpointTuple(events[0])).inv(), complete_register);
    try std.testing.expect(complete_link.isZero());
    try std.testing.expectEqual(@as(u64, 63), complete_ranges);
    try std.testing.expectEqual(@as(usize, 68), COLUMN_COUNT);
}

test "block-v5 word27 rejects active singular public endpoints without clearing unused denominators" {
    const Transition = @import("../air/block/memory_transition.zig").Transition;
    const Memory = @import("../air/block/memory_component.zig");
    const prior = Transition{ .space = 1, .address = 4, .clock = 1, .before = 0, .after = 7 };
    const current = Transition{ .space = 1, .address = 4, .clock = 2, .before = 7, .after = 8 };
    var challenges = protocol.Challenges{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() };
    const singular_z = challenges.endpoint.combineBase(protocol.endpointTuple(prior)).add(challenges.endpoint.z);
    challenges.endpoint = .init(singular_z, challenges.endpoint.alpha);
    try std.testing.expect(challenges.endpoint.combineBase(protocol.endpointTuple(prior)).isZero());
    const inactive_claim = Memory.Claim{ .first_row = 1, .total_rows = 3, .rows = 1, .log_size = 1, .first = current, .last = current, .preceding = prior };
    const unused = try publicEndpoints(inactive_claim, &challenges);
    for (unused.boundary_fraction ++ unused.final_fraction) |fraction| try std.testing.expect(fraction.isZero());
    var changed_key = current;
    changed_key.address = 8;
    changed_key.before = 0;
    var active_claim = inactive_claim;
    active_claim.first = changed_key;
    active_claim.last = changed_key;
    try std.testing.expectError(error.DivisionByZero, publicEndpoints(active_claim, &challenges));
    const final_claim = Memory.Claim{ .first_row = 0, .total_rows = 1, .rows = 1, .log_size = 1, .first = prior, .last = prior, .preceding = null };
    try std.testing.expectError(error.DivisionByZero, publicEndpoints(final_claim, &challenges));
}
