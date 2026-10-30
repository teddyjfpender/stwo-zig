//! Packed sorted RAM with embedded independently fixed initialization policy.
const R = @import("block_v7_memory_relations_v1.zig");
const Q = R.Q;
const P = R.P;
const Air = @import("../air/block/word_memory_lanes_v1.zig");
const Word = @import("../air/block/word_memory_v5.zig");
const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig");
const Halt = @import("block_v7_halt_algebra_v1.zig");
const Init = @import("block_v7_initial_algebra_v1.zig");
const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
const Old = @import("block_v5_word_memory_protocol_v1.zig");
pub const PLANES = 29;
/// One equation authority for scalar, packed and recursive evaluators. Endpoint
/// values remain symbolic in recursion; a prover-selected geometry is not a key.
pub fn equations(comptime S: type, prior: [9]S, first: [11]S, last: [11]S, halt: Halt.Constants(S), fixed: Air.Algebra(S).Fixed, row: [88]S, previous: [88]S, current: [116]S, before: [116]S, ch: R.Challenges(S), incoming: S, normalized: [PLANES]S) [161]S {
    @setEvalBranchQuota(500000);
    return directEquations(S, prior, first, last, halt, fixed, row, previous) ++ R.interactionConstraints(S, PLANES, terms(S, ch, incoming, fixed, row, previous), current, before, normalized);
}
pub const DIRECT_COUNT = 132;
/// Identical direct equation authority, separated only to permit base-field
/// evaluation on the real-domain path. Scalar and recursive callers share it.
pub fn directEquations(comptime S: type, prior: [9]S, first: [11]S, last: [11]S, halt: Halt.Constants(S), fixed: Air.Algebra(S).Fixed, row: [88]S, previous: [88]S) [DIRECT_COUNT]S {
    @setEvalBranchQuota(500000);
    const r = rows(S, row);
    return Air.Algebra(S).constraintsWithEndpoints(prior, first, last, fixed, r, rows(S, previous)) ++ Init.Algebra(S).constraints(access(S, fixed, r, 0), row[54..65].*) ++ Init.Algebra(S).constraints(access(S, fixed, r, 1), row[65..76].*) ++ Halt.Algebra(S).constraints(fixed[0].active, r[0][Word.Layout.current_key..][0..2].*, r[0][Word.Layout.current_clock..][0..4].*, r[0][Word.Layout.after..][0..2].*, halt, row[76..82].*) ++ Halt.Algebra(S).constraints(fixed[1].active, r[1][Word.Layout.current_key..][0..2].*, r[1][Word.Layout.current_clock..][0..4].*, r[1][Word.Layout.after..][0..2].*, halt, row[82..88].*);
}

pub fn rows(comptime S: type, row: [88]S) Air.Algebra(S).Row {
    return .{ row[0..27].*, row[27..54].* };
}
pub fn access(comptime S: type, fixed: Air.Algebra(S).Fixed, row: Air.Algebra(S).Row, lane: usize) Init.Algebra(S).Access {
    return .{ .global_first = fixed[lane].global_first, .predecessor_active = row[lane][Word.Layout.active], .same_address = row[lane][Word.Layout.same], .address = row[lane][Word.Layout.current_key..][0..2].*, .before = row[lane][Word.Layout.before..][0..2].* };
}
pub fn primaryTerms(comptime S: type, ch: R.Challenges(S), incoming: S, fixed: Air.Algebra(S).Fixed, flat: [88]S, previous: [88]S) [3]R.Term(S) {
    const row = rows(S, flat);
    const prior = rows(S, previous);
    const W = Word.Algebra(S);
    const I = Init.Algebra(S);
    var out: [3]R.Term(S) = @splat(.{});
    out[0] = .{ .left = ch.transition.combineSecure(W.tuple(row[0])), .right = ch.transition.combineSecure(W.tuple(row[1])), .wl = fixed[0].active.neg(), .wr = fixed[1].active.neg() };
    const ends = [2][9]S{ W.endTuple(row[0]), W.endTuple(row[1]) };
    var last: [9]S = undefined;
    var ordinal: [4]S = undefined;
    for (&last, ends[0], ends[1]) |*v, l, r| v.* = l.add(fixed[1].active.mul(r.sub(l)));
    for (&ordinal, fixed[0].ordinal, fixed[1].ordinal) |*v, l, r| v.* = l.add(fixed[1].active.mul(r.sub(l)));
    out[1] = .{ .left = ch.link.combineSecure(ordinal ++ last), .right = ch.link.combineSecure(fixed[0].previous_ordinal ++ W.endTuple(prior[1])), .wl = fixed[0].active.sub(fixed[0].global_last).sub(fixed[1].global_last), .wr = fixed[0].active.sub(fixed[0].first).neg(), .constant = fixed[0].first.mul(incoming).neg() };
    const a = [2]I.Access{ access(S, fixed, row, 0), access(S, fixed, row, 1) };
    const ir = [2]I.Row{ flat[54..65].*, flat[65..76].* };
    out[2] = .{ .left = ch.interval.combineSecure(ir[0][0..6].*), .right = ch.interval.combineSecure(ir[1][0..6].*), .wl = a[0].gate().neg(), .wr = a[1].gate().neg() };
    return out;
}
pub fn RangePair(comptime S: type) type {
    return struct { left: S, right: S, left_weight: S, right_weight: S };
}
/// Original typed inventory; weights here are positive requests. The lookup
/// term applies their original negative sign exactly once.
pub fn rangePairs(comptime S: type, fixed: Air.Algebra(S).Fixed, flat: [88]S) [24]RangePair(S) {
    const row = rows(S, flat);
    const W = Word.Algebra(S);
    const I = Init.Algebra(S);
    const a = [2]I.Access{ access(S, fixed, row, 0), access(S, fixed, row, 1) };
    const ir = [2]I.Row{ flat[54..65].*, flat[65..76].* };
    const old = [2][17]W.RangePoint{ W.rangePoints(fixed[0], row[0]), W.rangePoints(fixed[1], row[1]) };
    const extra = [2][7]I.RangePoint{ I.rangePoints(a[0], ir[0]), I.rangePoints(a[1], ir[1]) };
    var out: [24]RangePair(S) = undefined;
    for (&out, 0..) |*pair, i| pair.* = .{
        .left = if (i < 17) old[0][i].value else extra[0][i - 17].value,
        .right = if (i < 17) old[1][i].value else extra[1][i - 17].value,
        .left_weight = if (i < 17) old[0][i].weight else extra[0][i - 17].weight,
        .right_weight = if (i < 17) old[1][i].weight else extra[1][i - 17].weight,
    };
    return out;
}
pub fn terms(comptime S: type, ch: R.Challenges(S), incoming: S, fixed: Air.Algebra(S).Fixed, flat: [88]S, previous: [88]S) [PLANES]R.Term(S) {
    var out: [PLANES]R.Term(S) = @splat(.{});
    out[0..3].* = primaryTerms(S, ch, incoming, fixed, flat, previous);
    var count = S.zero();
    for (rangePairs(S, fixed, flat), 0..) |pair, i| {
        out[3 + i] = .{ .left = ch.range16.combineSecure(.{pair.left}), .right = ch.range16.combineSecure(.{pair.right}), .wl = pair.left_weight.neg(), .wr = pair.right_weight.neg() };
        count = count.add(pair.left_weight).add(pair.right_weight);
    }
    const row = rows(S, flat);
    out[27].wl = access(S, fixed, row, 0).gate().add(access(S, fixed, row, 1).gate());
    out[28].wl = count;
    return out;
}

pub const Spec = struct {
    pub const FIXED_COUNT = 24;
    pub const MAIN_COUNT = 88;
    pub const INTERACTION_COUNT = 116;
    pub const CONSTRAINT_COUNT = 161;
    pub const DEGREE = 4;
    pub const EXPANSION_BITS = 2;
    pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = blk: {
        var m: [MAIN_COUNT]bool = @splat(false);
        for (Air.shiftedColumns) |i| m[i] = true;
        break :blk m;
    };
    claim: Geometry.Claim,
    halt: Halt.Constants(Q),
    sums: [PLANES]Q,
    challenges: R.Challenges(Q),
    pub const Domain = struct {
        claim: Geometry.Claim,
        halt: Halt.Constants(Q),
        challenges: R.Challenges(Q),
        packed_challenges: R.Challenges(P),
        incoming: Q,
        normalized: [PLANES]Q,
        pub fn evaluate(self: Domain, fixed: [24]Q, row: [88]Q, previous: [88]Q, current: [116]Q, before: [116]Q, size: u32) ![161]Q {
            if (size != self.claim.rowCapacity()) return error.InvalidV7MemoryGeometry;
            return self.eval(Q, fixed, row, previous, current, before, self.challenges, self.incoming, self.normalized);
        }
        pub fn evaluatePacked(self: *const Domain, fixed: [24]P, row: [88]P, previous: [88]P, current: [116]P, before: [116]P) [161]P {
            var norm: [PLANES]P = undefined;
            for (&norm, self.normalized) |*v, x| v.* = P.splat(x);
            return self.eval(P, fixed, row, previous, current, before, self.packed_challenges, P.splat(self.incoming), norm);
        }
        fn eval(self: Domain, comptime S: type, fixed: [24]S, row: [88]S, previous: [88]S, current: [116]S, before: [116]S, ch: R.Challenges(S), incoming: S, norm: [PLANES]S) [161]S {
            @setEvalBranchQuota(500000);
            const f = Trace.fixedPoint(S, fixed, self.claim);
            var prior: [9]S = undefined;
            var first: [11]S = undefined;
            var last: [11]S = undefined;
            const prior_tuple = if (self.claim.preceding) |p| Old.endpointTuple(p) else @as([9]R.M, @splat(R.M.zero()));
            for (&prior, prior_tuple) |*v, x| v.* = R.lift(S, Q.fromBase(x));
            for (&first, Old.transitionTuple(self.claim.first)) |*v, x| v.* = R.lift(S, Q.fromBase(x));
            for (&last, Old.transitionTuple(self.claim.last)) |*v, x| v.* = R.lift(S, Q.fromBase(x));
            return equations(S, prior, first, last, Halt.lift(S, self.halt), f, row, previous, current, before, ch, incoming, norm);
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        try self.claim.validate();
        if (size != self.claim.rowCapacity()) return error.InvalidV7MemoryGeometry;
        var incoming = Q.zero();
        if (self.claim.preceding) |prior| {
            const tuple = Old.linkTuple(self.claim.first_event - 1, prior);
            var secure: [13]Q = undefined;
            for (&secure, tuple) |*v, x| v.* = Q.fromBase(x);
            incoming = try self.challenges.link.combineSecure(secure).inv();
        }
        return .{ .claim = self.claim, .halt = self.halt, .challenges = self.challenges, .packed_challenges = .from(self.challenges), .incoming = incoming, .normalized = try R.normalize(PLANES, self.sums, size) };
    }
    pub fn evaluate(self: Spec, fixed: [24]Q, row: [88]Q, previous: [88]Q, current: [116]Q, before: [116]Q, size: u32) ![161]Q {
        return (try self.prepareDomain(size)).evaluate(fixed, row, previous, current, before, size);
    }
};
