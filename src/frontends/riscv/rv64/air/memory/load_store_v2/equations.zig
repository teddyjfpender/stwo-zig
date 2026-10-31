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
        V1.equations.emitFor(F, f, m, pm, i, pi, rows, claims, T.project(ch), out);
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
        R.equations.boundaryAfterBindFor(F, if (kind == .initial) .initial else .terminal, m, pm, i, pi, first, f[2], nonempty, baseClaims(claims), baseChallenges(ch), out);
    }
}
pub fn baseChallenges(ch: T.Challenges) R.types.Challenges {
    return .{ .ram = ch.ram, .owner = .{ .offset = T.Q.zero(), .coefficients = @splat(T.Q.zero()) }, .range16 = ch.range16, .range8 = ch.range8 };
}
pub fn baseClaims(c: T.Claims) R.types.Claims {
    return .{ .ram = c.ram, .owner = c.owner, .range16 = c.range16, .range8 = c.range8 };
}
