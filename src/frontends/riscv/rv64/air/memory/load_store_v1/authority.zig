const E = @import("../../evaluation.zig");
const S = @import("../../providers/scalar_range.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const Eq = @import("equations.zig");
pub fn emitFor(comptime F: type, kind: L.Kind, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, rows: u32, expected: ?*const T.OwnerRows, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    if (kind == .ls) return Eq.emitFor(F, f, m, pm, i, pi, rows, claims, ch, out);
    if (kind == .owner) {
        for (0..22) |c| {
            var wanted = F.zero();
            for (0..64) |row| wanted = wanted.add(f[row].mul(E.qFor(F, expected.?[row][c].v)));
            out.emit(m[c].sub(wanted));
        }
        E.booleanFor(F, out, m[21]);
        S.single(F, ch.owner.denominatorFor(F, m[0..21].*), m[21].neg(), E.secureFor(F, i, 0), E.secureFor(F, i, 4), E.secureFor(F, pi, 4), f[64], f[65], claims.owner, out);
    } else {
        const d0 = ch.selection.denominatorFor(F, @import("selection.zig").tupleFor(F, f, 0));
        const d1 = ch.selection.denominatorFor(F, @import("selection.zig").tupleFor(F, f, 1));
        const inverse = E.secureFor(F, i, 0);
        out.emit(inverse.mul(d0).mul(d1).sub(E.SecureFor(F).one()));
        const numerator = E.mulBaseFor(F, d1, m[0]).add(E.mulBaseFor(F, d0, m[1]));
        S.prefix(F, numerator.mul(inverse).neg(), E.secureFor(F, i, 4), E.secureFor(F, pi, 4), f[4], f[5], claims.selection, out);
    }
}
