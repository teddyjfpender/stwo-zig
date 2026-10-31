//! One mixed-lane authority: CPU OWNER19, K IO11, and strict RAM14 chronology.
const E = @import("../../../evaluation.zig");
const R = @import("../../../memory/closed_ram/mod.zig");
const S = @import("../../../providers/scalar_range.zig");
const T = @import("types.zig");
const L = @import("layout.zig");
const Decode = @import("../../../../decode.zig");
pub fn ownerTuple(comptime F: type, m: []const F) [19]F {
    var tuple: [19]F = @splat(F.zero());
    tuple[0] = E.qFor(F, @intFromEnum(Decode.Opcode.ECALL));
    @memcpy(tuple[1..5], m[L.POINTER..][0..4]);
    tuple[9] = E.qFor(F, 1);
    tuple[10] = E.qFor(F, 1); // a7=0x10001
    tuple[17] = m[9];
    tuple[18] = m[3];
    return tuple;
}
pub fn ioTuple(comptime F: type, f: []const F, m: []const F, after: bool) [11]F {
    var tuple: [11]F = undefined;
    tuple[0] = m[L.CALL_ID];
    tuple[1] = E.qFor(F, @intFromBool(after));
    tuple[2] = f[3];
    @memcpy(tuple[3..], m[(if (after) L.AFTER_BYTES else L.BEFORE_BYTES)..][0..8]);
    return tuple;
}
pub fn emitFor(comptime F: type, _: L.Kind, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, calls: u32, first_id: u32, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    R.equations.transitionLocalFor(F, f[0..3], m[0..28], pm[0..28], 25 * calls, out);
    const one = F.one();
    const active = m[0];
    const padding = one.sub(active);
    out.emit(m[3].sub(m[12]).sub(m[13].mul(E.qFor(F, 65536))));
    out.emit(m[1].sub(active)); // every lane is an atomic read/write, requires R and W
    out.emit(active.mul(one.sub(m[22])));
    out.emit(active.mul(one.sub(m[23])));
    for (m[L.ADDRESS_CARRY..L.ALIGN_BITS]) |v| E.booleanFor(F, out, v);
    var aligned = F.zero();
    for (m[L.ALIGN_BITS..MAIN_END], 0..) |v, bit| {
        E.booleanFor(F, out, v);
        aligned = aligned.add(v.mul(E.qFor(F, @as(u32, 8) << @intCast(bit))));
    }
    out.emit(m[L.POINTER].sub(aligned));
    for (0..4) |c| out.emit(active.mul(m[L.POINTER + c].add(if (c == 0) f[3].mul(E.qFor(F, 8)) else m[L.ADDRESS_CARRY + c - 1]).sub(m[4 + c]).sub(m[L.ADDRESS_CARRY + c].mul(E.qFor(F, 65536)))));
    out.emit(m[L.ADDRESS_CARRY + 3]); // no pointer+lane overflow
    for (0..4) |c| {
        out.emit(m[14 + c].sub(m[L.BEFORE_BYTES + 2 * c]).sub(m[L.BEFORE_BYTES + 2 * c + 1].mul(E.qFor(F, 256))));
        out.emit(m[18 + c].sub(m[L.AFTER_BYTES + 2 * c]).sub(m[L.AFTER_BYTES + 2 * c + 1].mul(E.qFor(F, 256))));
    }
    const continuation = active.mul(one.sub(f[4]));
    for ([_]usize{ 9, 12, 13, 28, 29, 30, 31, 32 }) |c| out.emit(continuation.mul(m[c].sub(pm[c])));
    out.emit(active.mul(m[L.CALL_ID].sub(E.qFor(F, first_id)).sub(f[5])));
    for (m[28..]) |v| out.emit(padding.mul(v));
    R.equations.transitionRamFor(F, m, i, pi, f[1], f[2], claims.ram, ch.ram, out);
    S.single(F, ch.owner.denominatorFor(F, ownerTuple(F, m)), active.mul(f[4]).neg(), E.secureFor(F, i, L.OWNER), E.secureFor(F, i, L.OWNER + 4), E.secureFor(F, pi, L.OWNER + 4), f[1], f[2], claims.owner, out);
    const d = E.denominatorFor(F, ch.io.offset, &ch.io.coefficients, &ioTuple(F, f, m, false), true);
    const e = E.denominatorFor(F, ch.io.offset, &ch.io.coefficients, &ioTuple(F, f, m, true), true);
    const inv = E.secureFor(F, i, L.IO);
    out.emit(inv.mul(d).mul(e).sub(E.SecureFor(F).one()));
    S.prefix(F, E.mulBaseFor(F, d.add(e).mul(inv), active.neg()), E.secureFor(F, i, L.IO + 4), E.secureFor(F, pi, L.IO + 4), f[1], f[2], claims.io, out);
    R.equations.rangesFor(F, m, i, pi, &L.U16, L.RANGE16, f[1], f[2], claims.range16, ch.range16, out);
    R.equations.rangesFor(F, m, i, pi, &L.U8, L.RANGE8, f[1], f[2], claims.range8, ch.range8, out);
}
const MAIN_END = L.MAIN;
