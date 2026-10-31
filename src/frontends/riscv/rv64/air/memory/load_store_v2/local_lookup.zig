//! Forty-two affine fractions share strict pair inverses and one prefix.
//! OWNER/range/selection fields are additive ledger shares; only their sum is
//! authenticated here. RAM keeps its own inverse/prefix and physical claim.
const E = @import("../../evaluation.zig");
const S = @import("../../providers/scalar_range.zig");
const V1 = @import("../load_store_v1/mod.zig");
const T = @import("types.zig");
const L = @import("layout.zig");
const Equations = @import("equations.zig");

pub fn emitFor(comptime F: type, f: []const F, m: []const F, i: []const F, pi: []const F, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    const Q = E.SecureFor(F);
    var denominators: [42]Q = undefined;
    // Retain the existing negative OWNER orientation exactly.
    denominators[0] = ch.owner.denominatorFor(F, Equations.ownerTuple(F, m)).neg();
    for (L.U16, 0..) |column, j| denominators[1 + j] = ch.range16.denominatorFor(F, m[column]);
    for (L.U8, 0..) |column, j| denominators[36 + j] = ch.range8.denominatorFor(F, m[column]);
    denominators[41] = ch.selection.denominatorFor(F, V1.equations.selectionTuple(F, m));
    var contribution = Q.zero();
    for (0..21) |pair| {
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
