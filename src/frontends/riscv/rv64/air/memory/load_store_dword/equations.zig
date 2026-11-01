//! LS-D64 residual authority: the audited V1 local equations and closed RAM
//! transition run UNCHANGED on the affine expansion, then the seven local
//! fractions (OWNER19 + 4 U16 + 2 U8) close one prefix. Degree <= 3.
const E = @import("../../evaluation.zig");
const S = @import("../../providers/scalar_range.zig");
const R = @import("../closed_ram/mod.zig");
const V1 = @import("../load_store_v1/mod.zig");
const V2 = @import("../load_store_v2/mod.zig");
const L = @import("layout.zig");
const T = @import("types.zig");

/// OWNER19 tuple of a dword row: the LS32 tuple map on the expanded row.
pub fn ownerTuple(comptime F: type, physical: []const F) [19]F {
    const m = L.expandFor(F, physical);
    return V2.equations.ownerTupleForLogical(F, &m);
}
pub fn emitFor(comptime F: type, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, rows: u32, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    emitWithPublicFor(F, f, m, pm, i, pi, E.qFor(F, rows), E.qFor(F, @intFromBool(rows != 0)), claims, ch, out);
}
pub fn emitWithPublicFor(comptime F: type, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, row_count: F, nonempty: F, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    const logical = L.expandFor(F, m);
    var previous: [L.LOGICAL_MAIN]F = @splat(F.zero());
    previous[0] = pm[0];
    V1.equations.emitLocalWithPublicFor(F, f, &logical, &previous, row_count, nonempty, out);
    R.equations.transitionRamFor(F, logical[0..28], i, pi, f[1], f[2], claims.ram, ch.ram, out);
    emitLocalLookupFor(F, f, &logical, i, pi, claims, ch, out);
}
/// Seven affine fractions in strict pairs; only their sum is authenticated.
pub fn emitLocalLookupFor(comptime F: type, f: []const F, m: []const F, i: []const F, pi: []const F, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    const Q = E.SecureFor(F);
    const d = denominatorsFor(F, m, ch);
    var contribution = Q.zero();
    for (0..L.LOCAL_PAIRS) |pair| {
        const inverse = E.secureFor(F, i, L.LOCAL_INVERSES + 4 * pair);
        const a = d[2 * pair];
        if (2 * pair + 1 < L.LOCAL_FRACTIONS) {
            const b = d[2 * pair + 1];
            out.emit(inverse.mul(a).mul(b).sub(Q.one()));
            // OWNER (a of pair 0) carries the Boolean activity; ranges are unit.
            const numerator = if (pair == 0) E.mulBaseFor(F, b, m[0]).add(a) else a.add(b);
            contribution = contribution.add(numerator.mul(inverse));
        } else {
            out.emit(inverse.mul(a).sub(Q.one()));
            contribution = contribution.add(inverse);
        }
    }
    const total = claims.owner.add(claims.range16).add(claims.range8);
    S.prefix(F, contribution, E.secureFor(F, i, L.LOCAL_PREFIX), E.secureFor(F, pi, L.LOCAL_PREFIX), f[1], f[2], total, out);
}
pub fn denominatorsFor(comptime F: type, m: []const F, ch: T.Challenges) [L.LOCAL_FRACTIONS]E.SecureFor(F) {
    var d: [L.LOCAL_FRACTIONS]E.SecureFor(F) = undefined;
    // Same negative OWNER orientation as LS32: CPU emits +, consumers -.
    d[0] = ch.owner.denominatorFor(F, V2.equations.ownerTupleForLogical(F, m)).neg();
    for (L.LOGICAL_U16, 0..) |c, j| d[1 + j] = ch.range16.denominatorFor(F, m[c]);
    for (L.LOGICAL_U8, 0..) |c, j| d[1 + L.LOGICAL_U16.len + j] = ch.range8.denominatorFor(F, m[c]);
    return d;
}
