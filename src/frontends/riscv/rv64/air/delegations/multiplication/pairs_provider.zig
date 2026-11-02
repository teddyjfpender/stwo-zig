//! MUL byte-pair encoding (pairs_layout): the unchanged integer product
//! authority, 24 strict inverse columns over 48 tagged AND-relation byte
//! pairs, and the FUNCTION fraction fused into ONE joint prefix residual.
//!
//! Soundness (see also word16_execution/README.md, byte-pair section):
//! - Range. Pair query k is the AND-relation tuple (b[2k], b[2k+1], 0, 1).
//!   It balances only against a table pair row (x, y, 0, 1) with canonical
//!   bytes x = row>>8, y = row&255 (Schwartz-Zippel over the AND challenges,
//!   drawn after MAIN), so b[2k], b[2k+1] < 256 exactly as with two BYTE
//!   queries. The fourth coordinate separates pair and AND tuples.
//! - Strict pairs. I_j*p_2j*p_2j+1 = 1 rejects every pole; the contribution
//!   (p_2j + p_2j+1)*I_j is exactly 1/p_2j + 1/p_2j+1 (degree 2).
//! - Fused FUNCTION. (S - S' + claim*first - C)*d_fn + active = 0 with C the
//!   degree-2 pair contribution (degree 3 overall). If d_fn != 0 it forces
//!   S - S' = C - active/d_fn - claim*first, the legacy recurrence. If
//!   d_fn = 0 the residual reads active = 0: unsatisfiable on an active row.
//!   An inactive row has an all-zero tuple (the arithmetic authority forces
//!   (1-enabled)*value = 0 and Boolean selectors summing to zero), so its
//!   d_fn is the challenge offset itself: zero with probability 1/|QM31|.
//! - last*S = 0 is unchanged.
const E = @import("../../evaluation.zig");
const Old = @import("provider.zig");
const L = @import("pairs_layout.zig");
const Tables = @import("../../providers/tables.zig");
pub const ChallengesFor = Old.ChallengesFor;
pub const Challenges = Old.Challenges;
pub const PairChallengesFor = Tables.ChallengesFor;
pub fn evaluateFor(comptime F: type, geometry: [L.FIXED]F, main: *const [L.MAIN]F, current: *const [L.INTERACTION]F, previous_prefix: E.SecureFor(F), previous_count: F, count: F, ch: ChallengesFor(E.ConstFor(F)), pairs: PairChallengesFor(E.ConstFor(F)), claim: E.ConstFor(F), out: *E.SinkFor(F)) void {
    const S = E.SecureFor(F);
    Old.arithmeticFor(F, geometry, main, previous_count, count, out);
    const bytes = Old.byteValuesFor(F, main);
    var contribution = S.zero();
    for (0..L.PAIR_COLUMNS) |j| {
        const p = Tables.pairDenominatorFor(F, pairs, bytes[4 * j], bytes[4 * j + 1]);
        const q = Tables.pairDenominatorFor(F, pairs, bytes[4 * j + 2], bytes[4 * j + 3]);
        const inverse = E.secureFor(F, current, 4 * j);
        out.emit(p.mul(q).mul(inverse).sub(S.one()));
        contribution = contribution.add(p.add(q).mul(inverse));
    }
    const d = E.denominatorFor(F, ch.offset, &ch.coefficients, &Old.tupleFor(F, main), false);
    const prefix = E.secureFor(F, current, L.PREFIX);
    const step = prefix.sub(previous_prefix).add(E.mulBaseFor(F, E.splatFor(F, claim), geometry[1])).sub(contribution);
    out.emit(step.mul(d).add(E.liftFor(F, Old.activeFor(F, main))));
    out.emit(E.mulBaseFor(F, prefix, geometry[2]));
}
/// Native per-row pair denominators in query order (tests and forgeries).
pub fn nativePairDenominators(main: *const [L.MAIN]E.Q, pairs: Tables.Challenges) [L.PAIR_QUERIES]E.Q {
    const bytes = Old.byteValuesFor(E.Q, main);
    var result: [L.PAIR_QUERIES]E.Q = undefined;
    for (&result, 0..) |*v, k| v.* = Tables.pairDenominatorFor(E.Q, pairs, bytes[2 * k], bytes[2 * k + 1]);
    return result;
}
