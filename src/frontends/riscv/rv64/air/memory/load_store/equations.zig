//! CPU owner19 and scalable public boundary binding reuse checked arithmetic.
const E = @import("../../evaluation.zig");
const R = @import("../closed_ram/mod.zig");
const V1 = @import("../load_store_v1/mod.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const Tables = @import("../../providers/tables.zig");
pub fn ownerTuple(comptime F: type, physical: []const F) [19]F {
    const m = L.projection.expandFor(F, physical);
    return ownerTupleForLogical(F, &m);
}
pub fn ownerTupleForLogical(comptime F: type, m: []const F) [19]F {
    var tuple: [19]F = undefined;
    tuple[0] = m[V1.layout.opcode];
    @memcpy(tuple[1..17], m[V1.layout.a..][0..16]);
    tuple[17] = m[9];
    tuple[18] = m[3];
    return tuple;
}
pub fn emitFor(comptime F: type, kind: L.Kind, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, rows: u32, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    emitWithPublicFor(F, kind, f, m, pm, i, pi, E.qFor(F, rows), E.qFor(F, @intFromBool(rows != 0)), claims, ch, out);
}
/// Fused-pair layout (L.fused, Geometry.ls_fused_pairs). `pairs` are the AND
/// relation challenges serving the tagged byte pairs (x, y, 0, 1).
pub fn emitFusedWithPublicFor(comptime F: type, kind: L.Kind, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, row_count: F, nonempty: F, claims: T.ClaimsFor(E.ConstFor(F)), ch: T.ChallengesFor(E.ConstFor(F)), pairs: Tables.ChallengesFor(E.ConstFor(F)), out: *E.SinkFor(F)) void {
    if (kind == .ls) {
        const logical = L.projection.expandFor(F, m);
        var previous: [L.projection.LOGICAL_MAIN]F = @splat(F.zero());
        previous[0] = pm[0];
        V1.equations.emitLocalWithPublicFor(F, f, &logical, &previous, row_count, nonempty, out);
        fusedRamFor(F, logical[0..28], i, pi, f[1], f[2], claims.ram, ch.ram, out);
        @import("local_lookup.zig").emitPairsFor(F, f, &logical, i, pi, claims, ch, pairs, out);
        out.emit(logical[3].sub(logical[12]).sub(logical[13].mul(E.qFor(F, 65536))));
    } else if (kind == .initial or kind == .terminal) {
        emitBoundaryMainFor(F, f, m, pm, row_count, nonempty, out);
        const active = m[0];
        const d = ch.ram.denominatorFor(F, R.equations.ramTuple(F, if (kind == .initial) .initial else .terminal, m, false));
        fusedSingle(F, d, if (kind == .initial) active.neg() else active, E.secureFor(F, i, 0), E.secureFor(F, pi, 0), f[1], f[2], claims.ram, out);
        out.emit(E.splatFor(F, claims.range16));
        out.emit(E.splatFor(F, claims.range8));
    } else emitWithPublicFor(F, kind, f, m, pm, i, pi, row_count, nonempty, claims, ch, out);
}
/// Fused single fraction: (S - S' + claim*first)*d - w = 0 (degree 2) and
/// last*S = 0. If d != 0 this is the inverse/prefix recurrence; d = 0 reads
/// -w = 0, unsatisfiable on an active row. An inactive row's tuple is all
/// zero (emitBoundaryMainFor), so its d is the RAM challenge offset itself.
pub fn fusedSingle(comptime F: type, d: E.SecureFor(F), weight: F, current: E.SecureFor(F), previous: E.SecureFor(F), first: F, last: F, claim: E.ConstFor(F), out: *E.SinkFor(F)) void {
    out.emit(current.sub(previous).add(E.mulBaseFor(F, E.splatFor(F, claim), first)).mul(d).sub(E.liftFor(F, weight)));
    out.emit(E.mulBaseFor(F, current, last));
}
/// Fused RAM transition: (S - S' + claim*first)*b*a - active*(a - b) = 0
/// (degree 3) and last*S = 0. If a*b != 0 it forces the legacy increment
/// active*(1/b - 1/a). A one-sided pole with active = 1 is unsatisfiable;
/// both tuples are committed before the RAM challenges, so a pole occurs
/// with probability at most 2/|QM31| per row (standard LogUp fraction form).
pub fn fusedRamFor(comptime F: type, m: []const F, i: []const F, pi: []const F, first: F, last: F, claim: E.ConstFor(F), ch: R.types.RamChallengesFor(E.ConstFor(F)), out: *E.SinkFor(F)) void {
    const before = ch.denominatorFor(F, R.equations.ramTuple(F, .transition, m, false));
    const after = ch.denominatorFor(F, R.equations.ramTuple(F, .transition, m, true));
    const current = E.secureFor(F, i, L.fused.RAM_PREFIX);
    const step = current.sub(E.secureFor(F, pi, L.fused.RAM_PREFIX)).add(E.mulBaseFor(F, E.splatFor(F, claim), first));
    out.emit(step.mul(before).mul(after).sub(E.mulBaseFor(F, after.sub(before), m[0])));
    out.emit(E.mulBaseFor(F, current, last));
}
pub fn emitWithPublicFor(comptime F: type, kind: L.Kind, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, row_count: F, nonempty: F, claims: T.ClaimsFor(E.ConstFor(F)), ch: T.ChallengesFor(E.ConstFor(F)), out: *E.SinkFor(F)) void {
    if (kind == .ls) {
        emitLsWithPublicFor(F, f, m, pm, i, pi, row_count, nonempty, claims, ch, out);
    } else if (kind == .selection) {
        V1.authority.selectionFor(F, f, m, i, pi, claims.selection, ch.selection, out);
    } else if (kind == .range16 or kind == .range8) {
        @import("../../providers/scalar_range.zig").rangeFor(F, f, m, i, pi, if (kind == .range16) claims.range16 else claims.range8, if (kind == .range16) ch.range16 else ch.range8, out);
    } else {
        emitBoundaryWithPublicFor(F, kind, f, m, pm, i, pi, row_count, nonempty, claims, ch, out);
    }
}
/// Public INIT/TEARDOWN RAM14 debt. The chip proves only an active prefix of
/// exactly row_count rows and the signed LogUp sum of their RAM14 tuples.
/// Address order, uniqueness, alignment and every tuple coordinate's range are
/// receiver-owned: the receiver validates the public cell list natively and
/// requires claims.ram == expectedClaim(cells) exactly, which by LogUp
/// (random RAM challenges drawn after MAIN) forces the active-row multiset to
/// equal the canonical public tuples. No range lookups remain, so the range16
/// and range8 claims of these chips are constrained to zero here.
pub const BOUNDARY_MAIN_CONSTRAINTS = 20;
pub fn emitBoundaryMainFor(comptime F: type, f: []const F, m: []const F, pm: []const F, row_count: F, nonempty: F, out: *E.SinkFor(F)) void {
    const active = m[0];
    const first = f[1];
    const one = F.one();
    out.emit(first.mul(active.sub(nonempty)));
    out.emit(f[2].mul(active));
    out.emit(one.sub(first).mul(active).mul(one.sub(pm[0])));
    out.emit(one.sub(first).mul(active.sub(pm[0])).mul(f[0].sub(row_count)));
    for (m[1..L.BOUND_MAIN]) |value| out.emit(one.sub(active).mul(value));
    for ([_]usize{ R.layout.boundary.active, R.layout.boundary.readable, R.layout.boundary.writable }) |c| E.booleanFor(F, out, m[c]);
}
pub fn emitBoundaryWithPublicFor(comptime F: type, kind: L.Kind, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, row_count: F, nonempty: F, claims: T.ClaimsFor(E.ConstFor(F)), ch: T.ChallengesFor(E.ConstFor(F)), out: *E.SinkFor(F)) void {
    emitBoundaryMainFor(F, f, m, pm, row_count, nonempty, out);
    const active = m[0];
    const first = f[1];
    const scalar = @import("../../providers/scalar_range.zig");
    scalar.single(F, ch.ram.denominatorFor(F, R.equations.ramTuple(F, if (kind == .initial) .initial else .terminal, m, false)), if (kind == .initial) active.neg() else active, E.secureFor(F, i, 0), E.secureFor(F, i, 4), E.secureFor(F, pi, 4), first, f[2], claims.ram, out);
    out.emit(E.splatFor(F, claims.range16));
    out.emit(E.splatFor(F, claims.range8));
}
pub fn baseChallenges(ch: T.Challenges) R.types.Challenges {
    return .{ .ram = ch.ram, .owner = .{ .offset = T.Q.zero(), .coefficients = @splat(T.Q.zero()) }, .range16 = ch.range16, .range8 = ch.range8 };
}
pub fn baseClaims(c: T.Claims) R.types.Claims {
    return .{ .ram = c.ram, .owner = c.owner, .range16 = c.range16, .range8 = c.range8 };
}

/// The same LS residual authority over native or external arithmetic lanes.
/// Typed non-mask inputs are wires for a Circuit lane, Q for native lanes.
pub fn emitLsFor(comptime F: type, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, rows: u32, claims: T.ClaimsFor(E.ConstFor(F)), ch: T.ChallengesFor(E.ConstFor(F)), out: *E.SinkFor(F)) void {
    emitLsWithPublicFor(F, f, m, pm, i, pi, E.qFor(F, rows), E.qFor(F, @intFromBool(rows != 0)), claims, ch, out);
}
pub fn emitLsWithPublicFor(comptime F: type, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, row_count: F, nonempty: F, claims: T.ClaimsFor(E.ConstFor(F)), ch: T.ChallengesFor(E.ConstFor(F)), out: *E.SinkFor(F)) void {
    const logical = L.projection.expandFor(F, m);
    var previous: [L.projection.LOGICAL_MAIN]F = @splat(F.zero());
    previous[0] = pm[0];
    V1.equations.emitLocalWithPublicFor(F, f, &logical, &previous, row_count, nonempty, out);
    R.equations.transitionRamFor(F, logical[0..28], i, pi, f[1], f[2], claims.ram, ch.ram, out);
    @import("local_lookup.zig").emitFor(F, f, &logical, i, pi, claims, ch, out);
    out.emit(logical[3].sub(logical[12]).sub(logical[13].mul(E.qFor(F, 65536))));
}
