//! Nonterminal RAM: exact original v7 equations plus two complete-state delta
//! planes. Neither original claims nor equations are projected away.
const R = @import("block_v7_memory_relations_v1.zig");
const Old = @import("block_v7_ram_component_v1.zig");
const Air = @import("../air/block/word_memory_lanes_v1.zig");
const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig");
const Word = @import("../air/block/word_memory_v5.zig");
const Halt = @import("block_v7_halt_algebra_v1.zig");
const Q = R.Q;
const P = R.P;
pub const PLANES = 31;
pub fn deltaTerms(comptime S: type, fixed: Air.Algebra(S).Fixed, flat: [88]S, delta: R.Relation(S, 5)) [2]R.Term(S) {
    const rows = Old.rows(S, flat);
    var out: [2]R.Term(S) = undefined;
    for (&out, rows, fixed) |*term, row, f| {
        const address = .{row[Word.Layout.current_key + 2]} ++ row[Word.Layout.current_key..][0..2].*;
        term.* = .{ .left = delta.combineSecure(address ++ row[Word.Layout.after..][0..2].*), .right = delta.combineSecure(address ++ row[Word.Layout.before..][0..2].*), .wl = f.active, .wr = f.active.neg() };
    }
    return out;
}
pub fn terms(comptime S: type, ch: R.Challenges(S), incoming: S, fixed: Air.Algebra(S).Fixed, row: [88]S, previous: [88]S, delta: R.Relation(S, 5)) [PLANES]R.Term(S) {
    return Old.terms(S, ch, incoming, fixed, row, previous) ++ deltaTerms(S, fixed, row, delta);
}
pub fn deltaEquations(comptime S: type, fixed: Air.Algebra(S).Fixed, row: [88]S, current: [8]S, before: [8]S, delta: R.Relation(S, 5), normalized: [2]S) [2]S {
    return R.interactionConstraints(S, 2, deltaTerms(S, fixed, row, delta), current, before, normalized);
}
pub fn equations(comptime S: type, prior: [9]S, first: [11]S, last: [11]S, halt: Halt.Constants(S), fixed: Air.Algebra(S).Fixed, row: [88]S, previous: [88]S, current: [124]S, before: [124]S, ch: R.Challenges(S), delta: R.Relation(S, 5), incoming: S, normalized: [31]S) [163]S {
    return Old.equations(S, prior, first, last, halt, fixed, row, previous, current[0..116].*, before[0..116].*, ch, incoming, normalized[0..29].*) ++ deltaEquations(S, fixed, row, current[116..124].*, before[116..124].*, delta, normalized[29..31].*);
}
pub const Spec = struct {
    pub const FIXED_COUNT = Old.Spec.FIXED_COUNT;
    pub const MAIN_COUNT = Old.Spec.MAIN_COUNT;
    pub const INTERACTION_COUNT = 124;
    pub const CONSTRAINT_COUNT = 163;
    pub const DEGREE = 4;
    pub const EXPANSION_BITS = 2;
    pub const PREVIOUS_MAIN_MASK = Old.Spec.PREVIOUS_MAIN_MASK;
    claim: @import("block_v5_ram_lanes_protocol_v1.zig").Claim,
    halt: Halt.Constants(Q),
    sums: [PLANES]Q,
    challenges: R.Challenges(Q),
    delta: R.Relation(Q, 5),
    pub const Domain = struct {
        original: Old.Spec.Domain,
        delta: R.Relation(Q, 5),
        packed_delta: R.Relation(P, 5),
        normalized: [2]Q,
        pub fn evaluate(self: Domain, fixed: [24]Q, row: [88]Q, previous: [88]Q, current: [124]Q, before: [124]Q, size: u32) ![163]Q {
            return try self.original.evaluate(fixed, row, previous, current[0..116].*, before[0..116].*, size) ++ deltaEquations(Q, Trace.fixedPoint(Q, fixed, self.original.claim), row, current[116..124].*, before[116..124].*, self.delta, self.normalized);
        }
        pub fn evaluatePacked(self: *const Domain, fixed: [24]P, row: [88]P, previous: [88]P, current: [124]P, before: [124]P) [163]P {
            const norm: [2]P = .{ P.splat(self.normalized[0]), P.splat(self.normalized[1]) };
            return self.original.evaluatePacked(fixed, row, previous, current[0..116].*, before[0..116].*) ++ deltaEquations(P, Trace.fixedPoint(P, fixed, self.original.claim), row, current[116..124].*, before[116..124].*, self.packed_delta, norm);
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        var vector_delta: R.Relation(P, 5) = undefined;
        vector_delta.z = P.splat(self.delta.z);
        for (&vector_delta.powers, self.delta.powers) |*value, x| value.* = P.splat(x);
        return .{ .original = try (Old.Spec{ .claim = self.claim, .halt = self.halt, .sums = self.sums[0..29].*, .challenges = self.challenges }).prepareDomain(size), .delta = self.delta, .packed_delta = vector_delta, .normalized = try R.normalize(2, self.sums[29..31].*, size) };
    }
    pub fn evaluate(self: Spec, fixed: [24]Q, row: [88]Q, previous: [88]Q, current: [124]Q, before: [124]Q, size: u32) ![163]Q {
        return (try self.prepareDomain(size)).evaluate(fixed, row, previous, current, before, size);
    }
};
