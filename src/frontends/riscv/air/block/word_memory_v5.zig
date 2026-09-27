//! Packed16-bit sorted memory with exact u64 clocks. Integer residuals are
//! bounded by131071, far below M31; range16 is a separate proved provider.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const transition = @import("memory_transition.zig");
const claim_mod = @import("memory_component.zig");
const protocol = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
pub const Layout = struct {
    pub const active = 0;
    pub const same = 1;
    pub const current_key = 2;
    pub const current_clock = 5;
    pub const before = 9;
    pub const key_gap = 11;
    pub const key_carry = 14;
    pub const clock_gap = 17;
    pub const clock_carry = 21;
    pub const after = 25;
    pub const len = 27;
};
pub const Row = [Layout.len]M;
pub const DIRECT_COUNT = 46;
pub const RANGE_COUNT = 17;
pub const RangePoint = Algebra(Q).RangePoint;
pub const Fixed = Algebra(Q).Fixed;
pub const tuple = Algebra(Q).tuple;
pub const predecessor = Algebra(Q).predecessor;
pub const rangePoints = Algebra(Q).rangePoints;
pub const constraints = Algebra(Q).constraints;
pub const endTuple = Algebra(Q).endTuple;
/// Public endpoints are typed u1/u32/u64 values. Check their packed encoding
/// before relying on the first-row predecessor supply instead of re-ranging
/// the removed duplicate cells. Interior supplies use authenticated shifted
/// current endpoints directly; there is no independent predecessor witness.
pub fn validatePublicClaim(claim: claim_mod.Claim) !void {
    try claim.validate();
    try validateEndpoint(claim.first);
    try validateEndpoint(claim.last);
    if (claim.preceding) |prior| {
        try validateEndpoint(prior);
    }
}
fn validateEndpoint(value: transition.Transition) !void {
    const encoded = protocol.transitionTuple(value);
    if (encoded[0].toU32() > 1 or
        try protocol.readLimbs(encoded[1..3]) != value.address or
        try protocol.readLimbs(encoded[3..7]) != value.clock or
        try protocol.readLimbs(encoded[7..9]) != value.before or
        try protocol.readLimbs(encoded[9..11]) != value.after) return error.InvalidWordMemoryPublicEndpoint;
}
pub fn rangeCountBounds(claim: claim_mod.Claim) struct { minimum: u64, maximum: u64 } {
    // Ten current limbs plus three key-gap or four clock-gap limbs. The
    // first global row has no predecessor and therefore no gap requests.
    return .{ .minimum = 13 * @as(u64, claim.rows) - (if (claim.first_row == 0) @as(u64, 3) else 0), .maximum = 14 * @as(u64, claim.rows) - (if (claim.first_row == 0) @as(u64, 4) else 0) };
}
pub fn witness(previous: ?transition.Transition, current: transition.Transition) !Row {
    var row: Row = @splat(M.zero());
    put(row[Layout.current_key..][0..2], current.address);
    row[Layout.current_key + 2] = M.fromCanonical(current.space);
    put(row[Layout.current_clock..][0..4], current.clock);
    put(row[Layout.before..][0..2], current.before);
    put(row[Layout.after..][0..2], current.after);
    if (previous) |prior| {
        _ = try transition.adjacency(prior, current);
        row[Layout.active] = M.one();
        const same = prior.space == current.space and prior.address == current.address;
        row[Layout.same] = M.fromCanonical(@intFromBool(same));
        if (same) gap(4, prior.clock, current.clock, row[Layout.clock_gap..][0..4], row[Layout.clock_carry..][0..4]) else gap(3, (@as(u64, prior.space) << 32) | prior.address, (@as(u64, current.space) << 32) | current.address, row[Layout.key_gap..][0..3], row[Layout.key_carry..][0..3]);
    }
    return row;
}
pub fn Algebra(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const RangePoint = struct { value: S, weight: S };
        pub const Fixed = struct { active: S, first: S, last: S, global_first: S, global_last: S, domain_last: S, ordinal: [4]S, previous_ordinal: [4]S };
        pub fn tuple(row: [Layout.len]S) [protocol.TRANSITION_ARITY]S {
            return .{row[Layout.current_key + 2]} ++ row[Layout.current_key..][0..2].* ++ row[Layout.current_clock..][0..4].* ++ row[Layout.before..][0..2].* ++ row[Layout.after..][0..2].*;
        }
        pub fn predecessor(public_prior: [protocol.ENDPOINT_ARITY]S, fixed: Self.Fixed, previous: [Layout.len]S) [protocol.ENDPOINT_ARITY]S {
            const shifted = Self.endTuple(previous);
            var result: [protocol.ENDPOINT_ARITY]S = undefined;
            for (&result, shifted, public_prior) |*out, cell, pinned| out.* = cell.add(fixed.first.mul(pinned.sub(cell)));
            return result;
        }
        pub fn rangePoints(fixed: Self.Fixed, row: [Layout.len]S) [RANGE_COUNT]Self.RangePoint {
            var result: [RANGE_COUNT]Self.RangePoint = undefined;
            var at: usize = 0;
            const prior_gate = row[Layout.active];
            // Previous values use the shifted ranged current endpoint or a
            // validated public shard edge; no duplicate cells are committed.
            inline for (.{ .{ Layout.current_key, 2 }, .{ Layout.current_clock, 4 }, .{ Layout.before, 2 }, .{ Layout.after, 2 } }) |part| for (0..part[1]) |i| {
                result[at] = .{ .value = row[part[0] + i], .weight = fixed.active };
                at += 1;
            };
            for (0..3) |i| {
                result[at] = .{ .value = row[Layout.key_gap + i], .weight = prior_gate.mul(S.one().sub(row[Layout.same])) };
                at += 1;
            }
            for (0..4) |i| {
                result[at] = .{ .value = row[Layout.clock_gap + i], .weight = prior_gate.mul(row[Layout.same]) };
                at += 1;
            }
            std.debug.assert(at == RANGE_COUNT);
            return result;
        }
        pub fn constraints(claim: claim_mod.Claim, fixed: Self.Fixed, row: [Layout.len]S, previous: [Layout.len]S) [DIRECT_COUNT]S {
            const public_prior = if (claim.preceding) |preceding| protocol.endpointTuple(preceding) else @as([protocol.ENDPOINT_ARITY]M, @splat(M.zero()));
            var prior_constants: [protocol.ENDPOINT_ARITY]S = undefined;
            var first_constants: [protocol.TRANSITION_ARITY]S = undefined;
            var last_constants: [protocol.TRANSITION_ARITY]S = undefined;
            for (&prior_constants, public_prior) |*cell, value| cell.* = base(value);
            for (&first_constants, protocol.transitionTuple(claim.first)) |*cell, value| cell.* = base(value);
            for (&last_constants, protocol.transitionTuple(claim.last)) |*cell, value| cell.* = base(value);
            return constraintsWithEndpoints(prior_constants, first_constants, last_constants, fixed, row, previous);
        }
        /// Identical canonical equations with explicitly bound public symbols.
        /// Recursive consumers supply authenticated endpoint graph inputs.
        pub fn constraintsWithEndpoints(prior_constants: [protocol.ENDPOINT_ARITY]S, first_constants: [protocol.TRANSITION_ARITY]S, last_constants: [protocol.TRANSITION_ARITY]S, fixed: Self.Fixed, row: [Layout.len]S, previous: [Layout.len]S) [DIRECT_COUNT]S {
            @setEvalBranchQuota(200000);
            var out: [DIRECT_COUNT]S = undefined;
            var at: usize = 0;
            const active = row[Layout.active];
            const same = row[Layout.same];
            const one = S.one();
            append(&out, &at, active.sub(fixed.active.sub(fixed.global_first)));
            append(&out, &at, active.mul(same.mul(same.sub(one))));
            append(&out, &at, fixed.active.mul(row[Layout.current_key + 2].mul(row[Layout.current_key + 2].sub(one))));
            inline for (.{ .{ Layout.key_carry, 3 }, .{ Layout.clock_carry, 4 } }) |part| for (0..part[1]) |i| append(&out, &at, active.mul(row[part[0] + i].mul(row[part[0] + i].sub(one))));
            const prior = Self.predecessor(prior_constants, fixed, previous);
            const prior_key = prior[1..3].* ++ .{prior[0]};
            for (0..3) |i| append(&out, &at, active.mul(same).mul(prior_key[i].sub(row[Layout.current_key + i])));
            for (0..2) |i| append(&out, &at, active.mul(same).mul(prior[7 + i].sub(row[Layout.before + i])));
            strict(3, &out, &at, active.mul(one.sub(same)), prior_key, row[Layout.current_key..][0..3].*, row[Layout.key_gap..][0..3].*, row[Layout.key_carry..][0..3].*);
            strict(4, &out, &at, active.mul(same), prior[3..7].*, row[Layout.current_clock..][0..4].*, row[Layout.clock_gap..][0..4].*, row[Layout.clock_carry..][0..4].*);
            const current = Self.tuple(row);
            for (current, first_constants) |present, wanted| append(&out, &at, fixed.first.mul(present.sub(wanted)));
            for (current, last_constants) |present, wanted| append(&out, &at, fixed.last.mul(present.sub(wanted)));
            std.debug.assert(at == DIRECT_COUNT);
            return out;
        }
        pub fn endTuple(row: [Layout.len]S) [protocol.ENDPOINT_ARITY]S {
            const full = Self.tuple(row);
            return full[0..7].* ++ full[9..11].*;
        }
        fn append(out: *[DIRECT_COUNT]S, at: *usize, value: S) void {
            out[at.*] = value;
            at.* += 1;
        }
        fn strict(comptime n: usize, out: *[DIRECT_COUNT]S, at: *usize, gate: S, prior: [n]S, current: [n]S, difference: [n]S, carry: [n]S) void {
            const radix = base(M.fromCanonical(65536));
            var incoming = S.one();
            for (0..n) |i| {
                append(out, at, gate.mul(prior[i].add(difference[i]).add(incoming).sub(current[i]).sub(radix.mul(carry[i]))));
                incoming = carry[i];
            }
            append(out, at, gate.mul(incoming));
        }
        fn base(value: M) S {
            if (S == Q) return Q.fromBase(value);
            return S.splat(Q.fromBase(value));
        }
    };
}
fn gap(comptime n: usize, prior: u64, current: u64, out: *[n]M, carries: *[n]M) void {
    put(out, current - prior - 1);
    var incoming: u32 = 1;
    for (0..n) |i| {
        incoming = (@as(u32, @intCast((prior >> @intCast(16 * i)) & 65535)) + out[i].toU32() + incoming) >> 16;
        carries[i] = M.fromCanonical(incoming);
    }
}
fn put(out: []M, value: anytype) void {
    var rest: u64 = value;
    for (out) |*limb| {
        limb.* = M.fromCanonical(@intCast(rest & 65535));
        rest >>= 16;
    }
}

test "block-v5 word27 authenticates shifted and public predecessor without duplicate columns" {
    const prior = transition.Transition{ .space = 1, .address = 0xffff_ffff, .clock = std.math.maxInt(u64) - 1, .before = 0xffff_0000, .after = 0xabcd_ffff };
    const current = transition.Transition{ .space = 1, .address = prior.address, .clock = std.math.maxInt(u64), .before = prior.after, .after = 0xffff_ffff };
    const claim = claim_mod.Claim{ .first_row = 1, .total_rows = 2, .rows = 1, .log_size = 1, .first = current, .last = current, .preceding = prior };
    try validatePublicClaim(claim);
    const row = try witness(prior, current);
    const previous = try witness(null, prior);
    var secure_row: [Layout.len]Q = undefined;
    var secure_previous: [Layout.len]Q = undefined;
    for (&secure_row, row) |*out, cell| out.* = Q.fromBase(cell);
    for (&secure_previous, previous) |*out, cell| out.* = Q.fromBase(cell);
    const zero_ordinals: [4]Q = @splat(Q.zero());
    const boundary = Fixed{ .active = Q.one(), .first = Q.one(), .last = Q.one(), .global_first = Q.zero(), .global_last = Q.one(), .domain_last = Q.zero(), .ordinal = zero_ordinals, .previous_ordinal = zero_ordinals };
    var interior = boundary;
    interior.first = Q.zero();
    interior.last = Q.zero();
    for (constraints(claim, boundary, secure_row, @splat(Q.zero()))) |equation| try std.testing.expect(equation.isZero());
    for (constraints(claim, interior, secure_row, secure_previous)) |equation| try std.testing.expect(equation.isZero());
    // Interior order and value continuity read the real previous current cells.
    inline for (.{ .{ Layout.current_key, 3 }, .{ Layout.current_clock, 4 }, .{ Layout.after, 2 } }) |part| for (0..part[1]) |index| {
        var changed = secure_previous;
        changed[part[0] + index] = changed[part[0] + index].add(Q.one());
        var rejected = false;
        for (constraints(claim, interior, secure_row, changed)) |equation| rejected = rejected or !equation.isZero();
        try std.testing.expect(rejected);
    };
    var wrong_boundary = claim;
    wrong_boundary.preceding.?.after ^= 1;
    var rejected_boundary = false;
    for (constraints(wrong_boundary, boundary, secure_row, secure_previous)) |equation| rejected_boundary = rejected_boundary or !equation.isZero();
    try std.testing.expect(rejected_boundary);
    const points = rangePoints(boundary, secure_row);
    var count: u64 = 0;
    for (points) |point| {
        if (point.weight.isZero()) continue;
        try std.testing.expect(point.weight.eql(Q.one()));
        try std.testing.expect(point.value.toM31Array()[0].toU32() < 65536);
        count += 1;
    }
    try std.testing.expectEqual(@as(u64, 14), count);
    try std.testing.expectEqual(@as(usize, 27), Layout.len);
    try std.testing.expectEqual(@as(usize, 46), DIRECT_COUNT);
}
