//! Ten affine fractions share strict pair inverses and one prefix.
//! OWNER/range/selection fields are additive ledger shares; only their sum is
//! authenticated here. RAM keeps its own inverse/prefix and physical claim.
const E = @import("../../evaluation.zig");
const S = @import("../../providers/scalar_range.zig");
const V1 = @import("../load_store_v1/mod.zig");
const T = @import("types.zig");
const L = @import("layout.zig");
const Equations = @import("equations.zig");
const Tables = @import("../../providers/tables.zig");

/// Fused-pair layout (L.fused): three degree-one fraction witnesses and the
/// two tagged AND-relation byte pairs fused into the local prefix,
/// (S - S' + total*first - K0 - K1 - K2)*p0*p1 - (p0 + p1) = 0 (degree 3).
/// K_j*a*b = numerator_j fixes K_j = numerator_j/(a*b) whenever a*b != 0; a
/// one-sided pole with nonzero numerator is unsatisfiable. Every denominator
/// is z - <alpha, tuple> with the tuple committed before its challenges, so
/// the 8 non-strict poles per row (6 slot + 2 pair) occur with probability
/// at most 8*2^22/|QM31| < 2^-99 per proof. Range: a byte pair balances only
/// against a canonical AND-table pair row, so b13, b26, b73, b74 < 256.
pub fn emitPairsFor(comptime F: type, f: []const F, m: []const F, i: []const F, pi: []const F, claims: T.ClaimsFor(E.ConstFor(F)), ch: T.ChallengesFor(E.ConstFor(F)), pairs: Tables.ChallengesFor(E.ConstFor(F)), out: *E.SinkFor(F)) void {
    const Q = E.SecureFor(F);
    // Retain the existing negative OWNER orientation exactly.
    const owner = ch.owner.denominatorFor(F, Equations.ownerTupleForLogical(F, m)).neg();
    var r16: [L.U16.len]Q = undefined;
    for (L.LOGICAL_U16, &r16) |column, *d| d.* = ch.range16.denominatorFor(F, m[column]);
    const selection = ch.selection.denominatorFor(F, V1.equations.selectionTuple(F, m));
    const slots = [L.fused.WITNESSES][2]Q{ .{ owner, r16[0] }, .{ r16[1], r16[2] }, .{ r16[3], selection } };
    var contribution = Q.zero();
    for (slots, 0..) |slot, j| {
        const k = E.secureFor(F, i, L.fused.WITNESS + 4 * j);
        const numerator = if (j == 0) E.mulBaseFor(F, slot[1], m[0]).add(slot[0]) else slot[0].add(slot[1]);
        out.emit(k.mul(slot[0]).mul(slot[1]).sub(numerator));
        contribution = contribution.add(k);
    }
    const p0 = Tables.pairDenominatorFor(F, pairs, m[L.LOGICAL_U8[0]], m[L.LOGICAL_U8[1]]);
    const p1 = Tables.pairDenominatorFor(F, pairs, m[L.LOGICAL_U8[2]], m[L.LOGICAL_U8[3]]);
    const total = claims.owner.add(claims.range16).add(claims.range8).add(claims.selection);
    const current = E.secureFor(F, i, L.fused.LOCAL_PREFIX);
    const step = current.sub(E.secureFor(F, pi, L.fused.LOCAL_PREFIX)).add(E.mulBaseFor(F, E.splatFor(F, total), f[1])).sub(contribution);
    out.emit(step.mul(p0).mul(p1).sub(p0.add(p1)));
    out.emit(E.mulBaseFor(F, current, f[2]));
}

pub fn emitFor(comptime F: type, f: []const F, m: []const F, i: []const F, pi: []const F, claims: T.ClaimsFor(E.ConstFor(F)), ch: T.ChallengesFor(E.ConstFor(F)), out: *E.SinkFor(F)) void {
    const Q = E.SecureFor(F);
    var denominators: [L.LOCAL_FRACTIONS]Q = undefined;
    // Retain the existing negative OWNER orientation exactly.
    denominators[0] = ch.owner.denominatorFor(F, Equations.ownerTupleForLogical(F, m)).neg();
    for (L.LOGICAL_U16, 0..) |column, j| denominators[1 + j] = ch.range16.denominatorFor(F, m[column]);
    for (L.LOGICAL_U8, 0..) |column, j| denominators[1 + L.U16.len + j] = ch.range8.denominatorFor(F, m[column]);
    denominators[L.LOCAL_FRACTIONS - 1] = ch.selection.denominatorFor(F, V1.equations.selectionTuple(F, m));
    var contribution = Q.zero();
    for (0..L.LOCAL_PAIRS) |pair| {
        const a = denominators[2 * pair];
        const b = denominators[2 * pair + 1];
        const inverse = E.secureFor(F, i, L.LOCAL_INVERSES + 4 * pair);
        out.emit(inverse.mul(a).mul(b).sub(Q.one()));
        const numerator = if (pair == 0) E.mulBaseFor(F, b, m[0]).add(a) else a.add(b);
        contribution = contribution.add(numerator.mul(inverse));
    }
    const total = claims.owner.add(claims.range16).add(claims.range8).add(claims.selection);
    S.prefix(F, contribution, E.secureFor(F, i, L.LOCAL_PREFIX), E.secureFor(F, pi, L.LOCAL_PREFIX), f[1], f[2], total, out);
}
