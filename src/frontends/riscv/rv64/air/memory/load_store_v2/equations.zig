//! CPU owner19 and scalable public boundary binding reuse checked arithmetic.
const E = @import("../../evaluation.zig");
const R = @import("../closed_ram/mod.zig");
const V1 = @import("../load_store_v1/mod.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
pub fn ownerTuple(comptime F: type, m: []const F) [19]F {
    var tuple: [19]F = undefined;
    tuple[0] = m[V1.layout.opcode];
    @memcpy(tuple[1..17], m[V1.layout.a..][0..16]);
    tuple[17] = m[9];
    tuple[18] = m[3];
    return tuple;
}
pub fn emitFor(comptime F: type, kind: L.Kind, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, rows: u32, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    if (kind == .ls) {
        V1.equations.emitLocalFor(F, f, m, pm, rows, out);
        R.equations.transitionRamFor(F, m[0..28], i, pi, f[1], f[2], claims.ram, ch.ram, out);
        @import("local_lookup.zig").emitFor(F, f, m, i, pi, claims, ch, out);
        out.emit(m[3].sub(m[12]).sub(m[13].mul(E.qFor(F, 65536))));
    } else if (kind == .selection) {
        V1.authority.emitFor(F, .selection, f, m, pm, i, pi, 0, null, claims, T.project(ch), out);
    } else if (kind == .range16 or kind == .range8) {
        R.equations.emitFor(F, if (kind == .range16) .range16 else .range8, f, m, pm, i, pi, 0, null, baseClaims(claims), baseChallenges(ch), out);
    } else {
        const active = m[0];
        const first = f[1];
        const nonempty = E.qFor(F, @intFromBool(rows != 0));
        out.emit(first.mul(active.sub(nonempty)));
        out.emit(f[2].mul(active));
        out.emit(F.one().sub(first).mul(active).mul(F.one().sub(pm[0])));
        out.emit(F.one().sub(first).mul(active.sub(pm[0])).mul(f[0].sub(E.qFor(F, rows))));
        for (m[1..14]) |value| out.emit(F.one().sub(active).mul(value));
        R.equations.boundaryLocalFor(F, m, pm, first, nonempty, out);
        const scalar = @import("../../providers/scalar_range.zig");
        scalar.single(F, ch.ram.denominatorFor(F, R.equations.ramTuple(F, if (kind == .initial) .initial else .terminal, m, false)), if (kind == .initial) active.neg() else active, E.secureFor(F, i, 0), E.secureFor(F, i, 4), E.secureFor(F, pi, 4), first, f[2], claims.ram, out);
        R.equations.rangesFor(F, m, i, pi, &L.BOUND_U16, 8, first, f[2], claims.range16, ch.range16, out);
        // Canonical tuple coordinates come from the independently anchored
        // RAM14 public multiset. There is no boundary U8 lookup debt.
        out.emit(E.splatFor(F, claims.range8));
    }
}
pub fn baseChallenges(ch: T.Challenges) R.types.Challenges {
    return .{ .ram = ch.ram, .owner = .{ .offset = T.Q.zero(), .coefficients = @splat(T.Q.zero()) }, .range16 = ch.range16, .range8 = ch.range8 };
}
pub fn baseClaims(c: T.Claims) R.types.Claims {
    return .{ .ram = c.ram, .owner = c.owner, .range16 = c.range16, .range8 = c.range8 };
}
