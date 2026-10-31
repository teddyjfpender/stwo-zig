//! ONE arithmetic-lane authority for domain/OODS, including all canonical debt.
const E = @import("../../evaluation.zig");
const S = @import("../../providers/scalar_range.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
pub fn ramTuple(comptime F: type, kind: L.Kind, m: []const F, after: bool) [14]F {
    var out: [14]F = @splat(F.zero());
    out[0] = F.one();
    if (kind == .transition) {
        @memcpy(out[1..5], m[L.trans.address..][0..4]);
        out[5] = m[if (after) L.trans.after_epoch else L.trans.before_epoch];
        out[6] = m[if (after) L.trans.after_low else L.trans.before_low];
        out[7] = m[if (after) L.trans.after_high else L.trans.before_high];
        @memcpy(out[8..12], m[(if (after) L.trans.after_value else L.trans.before_value)..][0..4]);
        out[12] = m[L.trans.readable];
        out[13] = m[L.trans.writable];
    } else {
        @memcpy(out[1..5], m[L.boundary.address..][0..4]);
        out[5] = m[L.boundary.epoch];
        out[6] = m[L.boundary.low];
        out[7] = m[L.boundary.high];
        @memcpy(out[8..12], m[L.boundary.value..][0..4]);
        out[12] = m[L.boundary.readable];
        out[13] = m[L.boundary.writable];
    }
    return out;
}
pub fn ownerTuple(comptime F: type, m: []const F) [13]F {
    var out: [13]F = undefined;
    out[0] = m[L.trans.owner];
    @memcpy(out[1..5], m[L.trans.address..][0..4]);
    out[5] = m[L.trans.after_epoch];
    out[6] = m[L.trans.after_low];
    out[7] = m[L.trans.after_high];
    @memcpy(out[8..12], m[L.trans.after_value..][0..4]);
    out[12] = m[L.trans.write];
    return out;
}
fn bind(comptime F: type, f: []const F, m: []const F, p: *const T.PublicRows, out: *E.SinkFor(F)) void {
    for (0..14) |c| {
        var wanted = F.zero();
        for (0..32) |i| wanted = wanted.add(f[i].mul(E.qFor(F, p[i][c].v)));
        out.emit(m[c].sub(wanted));
    }
}
pub fn rangesFor(comptime F: type, m: []const F, i: []const F, prev: []const F, comptime indices: []const usize, start: usize, first: F, last: F, claim: T.Q, ch: S.Challenges, out: *E.SinkFor(F)) void {
    const Q = E.SecureFor(F);
    var sum = Q.zero();
    for (0..(indices.len + 1) / 2) |batch| {
        const d = ch.denominatorFor(F, m[indices[2 * batch]]);
        const inverse = E.secureFor(F, i, start + 4 * batch);
        if (2 * batch + 1 < indices.len) {
            const e = ch.denominatorFor(F, m[indices[2 * batch + 1]]);
            out.emit(inverse.mul(d).mul(e).sub(Q.one()));
            sum = sum.add(d.add(e).mul(inverse));
        } else {
            out.emit(inverse.mul(d).sub(Q.one()));
            sum = sum.add(inverse);
        }
    }
    const at = start + 4 * ((indices.len + 1) / 2);
    S.prefix(F, sum, E.secureFor(F, i, at), E.secureFor(F, prev, at), first, last, claim, out);
}
pub fn emitFor(comptime F: type, kind: L.Kind, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, rows: u32, pubrows: ?*const T.PublicRows, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    if (kind == .range16 or kind == .range8) {
        S.rangeFor(F, f, m, i, pi, if (kind == .range16) claims.range16 else claims.range8, if (kind == .range16) ch.range16 else ch.range8, out);
        return;
    }
    const first = f[if (kind == .transition) 1 else 32];
    const last = f[if (kind == .transition) 2 else 33];
    const active = m[0];
    if (kind == .owner) {
        bind(F, f, m, pubrows.?, out);
        E.booleanFor(F, out, m[13]);
        S.single(F, ch.owner.denominatorFor(F, m[0..13].*), m[13].neg(), E.secureFor(F, i, 0), E.secureFor(F, i, 4), E.secureFor(F, pi, 4), first, last, claims.owner, out);
        return;
    }
    if (kind == .transition) {
        transitionLocalFor(F, f, m, pm, rows, out);
        transitionRamFor(F, m, i, pi, first, last, claims.ram, ch.ram, out);
        S.single(F, ch.owner.denominatorFor(F, ownerTuple(F, m)), active, E.secureFor(F, i, 8), E.secureFor(F, i, 12), E.secureFor(F, pi, 12), first, last, claims.owner, out);
        rangesFor(F, m, i, pi, &L.T_U16, L.T_RANGE16, first, last, claims.range16, ch.range16, out);
        rangesFor(F, m, i, pi, &L.T_U8, L.T_RANGE8, first, last, claims.range8, ch.range8, out);
    } else {
        bind(F, f, m, pubrows.?, out);
        boundaryAfterBindFor(F, kind, m, pm, i, pi, first, last, F.one(), claims, ch, out);
    }
}

/// Checked sorted boundary, RAM and range authority. Public binding is owned
/// by the caller: legacy fixed selectors or the scalable sealed-public claims.
/// nonempty is a verifier-bound PUBLIC constant, never a free trace witness.
pub fn boundaryAfterBindFor(comptime F: type, kind: L.Kind, m: []const F, pm: []const F, i: []const F, pi: []const F, first: F, last: F, nonempty: F, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    boundaryLocalFor(F, m, pm, first, nonempty, out);
    const active = m[0];
    S.single(F, ch.ram.denominatorFor(F, ramTuple(F, kind, m, false)), if (kind == .initial) active.neg() else active, E.secureFor(F, i, 0), E.secureFor(F, i, 4), E.secureFor(F, pi, 4), first, last, claims.ram, out);
    rangesFor(F, m, i, pi, &L.B_U16, L.B_RANGE16, first, last, claims.range16, ch.range16, out);
    rangesFor(F, m, i, pi, &L.B_U8, L.B_RANGE8, first, last, claims.range8, ch.range8, out);
}
/// Shared strict sorted-address arithmetic, before independently owned lookups.
pub fn boundaryLocalFor(comptime F: type, m: []const F, pm: []const F, first: F, nonempty: F, out: *E.SinkFor(F)) void {
    const active = m[0];
    const one = F.one();
    for ([_]usize{ 0, 12, 13 }) |c| E.booleanFor(F, out, m[c]);
    for (m[18..22]) |v| E.booleanFor(F, out, v);
    const sorted = active.sub(first.mul(nonempty));
    var delta = F.zero();
    for (0..4) |c| {
        out.emit(sorted.mul(pm[1 + c].add(m[14 + c]).add(if (c == 0) F.zero() else m[18 + c - 1]).sub(m[1 + c]).sub(m[18 + c].mul(E.qFor(F, 65536)))));
        delta = delta.add(m[14 + c]);
    }
    out.emit(sorted.mul(m[21]));
    out.emit(sorted.mul(delta.mul(m[22]).sub(one)));
    for (m[14..23]) |v| out.emit(one.sub(sorted).mul(v));
}

/// Shared bounded-integer clock, permission and unit-activity authority.
/// Caller supplies the unchanged 28-coordinate physical RAM prefix.
pub fn transitionLocalFor(comptime F: type, f: []const F, m: []const F, pm: []const F, rows: u32, out: *E.SinkFor(F)) void {
    const first = f[1];
    const last = f[2];
    const active = m[0];
    const one = F.one();
    for ([_]usize{ 0, 1, 2, 22, 23, 27 }) |c| E.booleanFor(F, out, m[c]);
    for (m[1..]) |v| out.emit(one.sub(active).mul(v));
    out.emit(first.mul(active.sub(E.qFor(F, @intFromBool(rows != 0)))));
    out.emit(last.mul(active));
    out.emit(one.sub(first).mul(active).mul(one.sub(pm[0])));
    out.emit(one.sub(first).mul(active.sub(pm[0])).mul(f[0].sub(E.qFor(F, rows))));
    const same = m[2];
    const cross = one.sub(same);
    out.emit(active.mul(same).mul(m[8].sub(m[9])));
    out.emit(active.mul(cross).mul(m[8].add(m[24]).add(one).sub(m[9])));
    out.emit(active.mul(same).mul(m[10].add(m[25]).add(one).sub(m[12]).sub(m[27].mul(E.qFor(F, 65536)))));
    out.emit(active.mul(same).mul(m[11].add(m[26]).add(m[27]).sub(m[13])));
    out.emit(same.mul(m[24]));
    for ([_]usize{ 25, 26, 27 }) |c| out.emit(cross.mul(m[c]));
    out.emit(active.mul(m[1]).mul(one.sub(m[23])));
    out.emit(active.mul(one.sub(m[1])).mul(one.sub(m[22])));
    for (0..4) |c| out.emit(active.mul(one.sub(m[1])).mul(m[18 + c].sub(m[14 + c])));
}

/// Same strict inverse and before-minus-after prefix used by the closed proof.
pub fn transitionRamFor(comptime F: type, m: []const F, i: []const F, pi: []const F, first: F, last: F, claim: T.Q, ch: T.RamChallenges, out: *E.SinkFor(F)) void {
    const active = m[0];
    const before = ch.denominatorFor(F, ramTuple(F, .transition, m, false));
    const after = ch.denominatorFor(F, ramTuple(F, .transition, m, true));
    const inverse = E.secureFor(F, i, 0);
    out.emit(inverse.mul(before).mul(after).sub(E.SecureFor(F).one()));
    S.prefix(F, E.mulBaseFor(F, after.sub(before).mul(inverse), active), E.secureFor(F, i, 4), E.secureFor(F, pi, 4), first, last, claim, out);
}
