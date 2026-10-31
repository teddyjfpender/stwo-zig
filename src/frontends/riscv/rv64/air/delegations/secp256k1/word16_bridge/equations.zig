//! One D3 scalar/packed authority, using unchanged RAM14 state and Wire35 RCB.
const E = @import("../../../evaluation.zig");
const R = @import("../../../memory/closed_ram/mod.zig");
const S = @import("../../../providers/scalar_range.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const P = @import("../program.zig");
const Decode = @import("../../../../decode.zig");
pub fn ramRow(comptime F: type, m: []const F, lane: usize) [28]F {
    var row: [28]F = undefined;
    row[0] = m[L.ACTIVE];
    row[1] = m[L.WRITE];
    row[2] = m[L.SAME + lane];
    row[3] = m[L.TICK];
    @memcpy(row[4..8], m[L.ADDRESS..][0..4]);
    row[4] = row[4].add(m[L.ACTIVE].mul(E.qFor(F, @intCast(8 * lane))));
    row[8] = m[L.PREV_EPOCH + lane];
    row[9] = m[L.EPOCH];
    row[10] = m[L.PREV_LOW + lane];
    row[11] = m[L.PREV_HIGH + lane];
    row[12] = m[L.LOW];
    row[13] = m[L.HIGH];
    for (0..4) |c| {
        row[14 + c] = m[L.BEFORE + 8 * lane + 2 * c].add(m[L.BEFORE + 8 * lane + 2 * c + 1].mul(E.qFor(F, 256)));
        row[18 + c] = m[L.AFTER + 8 * lane + 2 * c].add(m[L.AFTER + 8 * lane + 2 * c + 1].mul(E.qFor(F, 256)));
    }
    row[22] = m[L.READABLE + lane];
    row[23] = m[L.WRITABLE + lane];
    row[24] = m[L.GAP_EPOCH + lane];
    row[25] = m[L.GAP_LOW + lane];
    row[26] = m[L.GAP_HIGH + lane];
    row[27] = m[L.BORROW + lane];
    return row;
}
pub fn ownerTuple(comptime F: type, kind: P.Kind, m: []const F) [19]F {
    var t: [19]F = @splat(F.zero());
    t[0] = E.qFor(F, @intFromEnum(Decode.Opcode.ECALL));
    @memcpy(t[1..5], m[L.POINTER..][0..4]);
    t[9] = E.qFor(F, @as(u16, @truncate(T.tag(kind))));
    t[10] = E.qFor(F, T.tag(kind) >> 16);
    t[17] = m[L.EPOCH];
    t[18] = m[L.TICK];
    return t;
}
pub fn wireTuple(comptime F: type, kind: P.Kind, f: []const F, m: []const F, after: bool) [35]F {
    var t: [35]F = undefined;
    t[0] = E.qFor(F, @intFromEnum(kind));
    t[1] = m[L.CALL_ID];
    t[2] = f[if (after) 7 else 3];
    @memcpy(t[3..], m[(if (after) L.AFTER else L.BEFORE)..][0..32]);
    return t;
}
pub fn emitFor(comptime F: type, kind: P.Kind, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, calls: u32, first_id: u32, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    const one = F.one();
    const active = m[L.ACTIVE];
    const pad = one.sub(active);
    const Sec = E.SecureFor(F);
    var ram_term = Sec.zero();
    for (0..4) |lane| {
        const row = ramRow(F, m, lane);
        const prev = ramRow(F, pm, lane);
        R.equations.transitionLocalFor(F, f[0..3], &row, &prev, calls * @as(u32, @intCast(T.coordinates(kind))), out);
        const d = ch.ram.denominatorFor(F, R.equations.ramTuple(F, .transition, &row, false));
        const e = ch.ram.denominatorFor(F, R.equations.ramTuple(F, .transition, &row, true));
        const inv = E.secureFor(F, i, L.RAM + 4 * lane);
        out.emit(inv.mul(d).mul(e).sub(Sec.one()));
        ram_term = ram_term.add(E.mulBaseFor(F, e.sub(d).mul(inv), active));
        out.emit(active.mul(one.sub(m[L.READABLE + lane])));
    }
    S.prefix(F, ram_term, E.secureFor(F, i, 16), E.secureFor(F, pi, 16), f[1], f[2], claims.ram, out);
    out.emit(m[L.WRITE].sub(active.mul(f[6])));
    out.emit(m[L.TICK].sub(m[L.LOW]).sub(m[L.HIGH].mul(E.qFor(F, 65536))));
    for (m[L.CARRY..L.ALIGN]) |v| E.booleanFor(F, out, v);
    var aligned = F.zero();
    for (m[L.ALIGN..], 0..) |v, bit| {
        E.booleanFor(F, out, v);
        aligned = aligned.add(v.mul(E.qFor(F, @as(u32, 32) << @intCast(bit))));
    }
    out.emit(m[L.POINTER].sub(aligned));
    for (0..4) |c| out.emit(active.mul(m[L.POINTER + c].add(if (c == 0) f[3].mul(E.qFor(F, 32)) else m[L.CARRY + c - 1]).sub(m[L.ADDRESS + c]).sub(m[L.CARRY + c].mul(E.qFor(F, 65536)))));
    out.emit(m[L.CARRY + 3]);
    const continuation = active.mul(one.sub(f[4]));
    for ([_]usize{ 2, 3, 4, 5, 10, 11, 12, 13, 14 }) |c| out.emit(continuation.mul(m[c].sub(pm[c])));
    out.emit(active.mul(m[L.CALL_ID].sub(E.qFor(F, first_id)).sub(f[5])));
    for (m[2..]) |v| out.emit(pad.mul(v));
    S.single(F, ch.owner.denominatorFor(F, ownerTuple(F, kind, m)), active.mul(f[4]).neg(), E.secureFor(F, i, L.OWNER), E.secureFor(F, i, L.OWNER + 4), E.secureFor(F, pi, L.OWNER + 4), f[1], f[2], claims.owner, out);
    const d = E.denominatorFor(F, ch.wire.offset, &ch.wire.coefficients, &wireTuple(F, kind, f, m, false), true);
    const e = E.denominatorFor(F, ch.wire.offset, &ch.wire.coefficients, &wireTuple(F, kind, f, m, true), true);
    const inverse = E.secureFor(F, i, L.WIRE);
    out.emit(inverse.mul(d).mul(e).sub(Sec.one()));
    // Clearing the prefix denominator keeps affine input and quadratic output
    // weights D3. Strict pair inverse above forbids either zero denominator.
    const delta = E.secureFor(F, i, L.WIRE + 4).sub(E.secureFor(F, pi, L.WIRE + 4)).add(E.mulBaseFor(F, E.splatFor(F, claims.wire), f[1]));
    out.emit(delta.mul(d).mul(e).sub(E.mulBaseFor(F, e, active)).add(E.mulBaseFor(F, d, active.mul(f[6]))));
    out.emit(E.mulBaseFor(F, E.secureFor(F, i, L.WIRE + 4), f[2]));
    R.equations.rangesFor(F, m, i, pi, &L.U16, L.RANGE16, f[1], f[2], claims.range16, ch.range16, out);
    R.equations.rangesFor(F, m, i, pi, &L.U8, L.RANGE8, f[1], f[2], claims.range8, ch.range8, out);
}
