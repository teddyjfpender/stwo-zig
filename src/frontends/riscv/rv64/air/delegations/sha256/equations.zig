//! One degree-3 scalar/packed constraint authority for the SHA-256 truth.
//! `v` is a mask view with fixed(c), main(c), previousActive(),
//! interaction(c) and previousInteraction(c); all lanes share this order.
const std = @import("std");
const E = @import("../../evaluation.zig");
const L = @import("layout.zig");
pub const WireFor = @import("../secp256k1/equations.zig").WireFor;
pub const Wire = WireFor(E.Q);

inline fn pow2(comptime F: type, k: usize) F {
    return E.qFor(F, @as(u32, 1) << @intCast(k));
}
inline fn xor2(comptime F: type, x: F, y: F) F {
    const xy = x.mul(y);
    return x.add(y).sub(xy.add(xy));
}
inline fn xor3(comptime F: type, x: F, y: F, z: F) F {
    return xor2(F, xor2(F, x, y), z);
}
/// Weighted half-word of a register: sum_k 2^k bit(base + 16 hi + k).
fn half(comptime F: type, v: anytype, base: usize, hi: bool) F {
    var acc = F.zero();
    const off: usize = if (hi) 16 else 0;
    for (0..16) |k| acc = acc.add(v.main(base + off + k).mul(pow2(F, k)));
    return acc;
}
/// Composed carry value from Boolean columns.
fn carry(comptime F: type, v: anytype, base: usize, bits: usize) F {
    var acc = F.zero();
    for (0..bits) |k| acc = acc.add(v.main(base + k).mul(pow2(F, k)));
    return acc;
}
const Sigma = struct { r0: usize, r1: usize, r2: usize, shift: bool };
pub const BIG0 = Sigma{ .r0 = 2, .r1 = 13, .r2 = 22, .shift = false };
pub const BIG1 = Sigma{ .r0 = 6, .r1 = 11, .r2 = 25, .shift = false };
pub const SMALL0 = Sigma{ .r0 = 7, .r1 = 18, .r2 = 3, .shift = true };
pub const SMALL1 = Sigma{ .r0 = 17, .r1 = 19, .r2 = 10, .shift = true };
/// Bit i of a rotate/rotate/(rotate|shift) XOR over register `base`.
fn sigmaBit(comptime F: type, v: anytype, base: usize, s: Sigma, i: usize) F {
    const x = v.main(base + (i + s.r0) % 32);
    const y = v.main(base + (i + s.r1) % 32);
    if (s.shift and i + s.r2 >= 32) return xor2(F, x, y);
    return xor3(F, x, y, v.main(base + (i + s.r2) % 32));
}
fn sigmaHalf(comptime F: type, v: anytype, base: usize, s: Sigma, hi: bool) F {
    var acc = F.zero();
    const off: usize = if (hi) 16 else 0;
    for (0..16) |k| acc = acc.add(sigmaBit(F, v, base, s, off + k).mul(pow2(F, k)));
    return acc;
}
/// Ch(x, y, z) = z + x (y - z), bitwise.
fn chHalf(comptime F: type, v: anytype, x: usize, y: usize, z: usize, hi: bool) F {
    var acc = F.zero();
    const off: usize = if (hi) 16 else 0;
    for (0..16) |k| {
        const zz = v.main(z + off + k);
        acc = acc.add(zz.add(v.main(x + off + k).mul(v.main(y + off + k).sub(zz))).mul(pow2(F, k)));
    }
    return acc;
}
/// Maj(x, y, z) = xy + z (x XOR y), bitwise.
fn majHalf(comptime F: type, v: anytype, x: usize, y: usize, z: usize, hi: bool) F {
    var acc = F.zero();
    const off: usize = if (hi) 16 else 0;
    for (0..16) |k| {
        const xx = v.main(x + off + k);
        const yy = v.main(y + off + k);
        acc = acc.add(xx.mul(yy).add(v.main(z + off + k).mul(xor2(F, xx, yy))).mul(pow2(F, k)));
    }
    return acc;
}
inline fn constHalf(comptime F: type, value: u32, hi: bool) F {
    return E.qFor(F, if (hi) value >> 16 else value & 0xffff);
}

/// Byte b (0..31) of a Wire35 coordinate as a linear form in MAIN.
fn wireByte(comptime F: type, v: anytype, wire: u32, b: usize) F {
    var base: usize = undefined;
    switch (wire) {
        // State word i, little-endian byte b % 4.
        L.STATE_WIRE => base = L.stateWord(b / 4, 8 * (b % 4)),
        // Block byte 4j + m is big-endian byte m of W_j.
        1, 2 => {
            const j = 8 * (wire - 1) + b / 4;
            base = L.w(j, 8 * (3 - b % 4));
        },
        L.OUTPUT_WIRE => return v.main(L.OUT + b),
        else => unreachable,
    }
    var acc = F.zero();
    for (0..8) |k| acc = acc.add(v.main(base + k).mul(pow2(F, k)));
    return acc;
}
pub fn tuple(comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), wire: u32) [L.WIRE_ARITY]F {
    var t: [L.WIRE_ARITY]F = undefined;
    t[0] = E.qFor(F, L.PROGRAM_KIND);
    t[1] = E.firstIdFor(F, public).add(v.fixed(L.ROW));
    t[2] = E.qFor(F, wire);
    for (0..32) |b| t[3 + b] = wireByte(F, v, wire, b);
    return t;
}
fn secure(comptime F: type, v: anytype, start: usize, previous: bool) E.SecureFor(F) {
    var c: [4]F = undefined;
    for (&c, 0..) |*x, i| x.* = if (previous) v.previousInteraction(start + i) else v.interaction(start + i);
    return E.secureFromCoordinatesFor(F, c);
}

/// MAIN-only authority: Booleanity, message schedule, 64 rounds, feed-forward
/// and the contiguous activity prefix. Emission order is protocol authority.
pub fn emitMain(comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    const one = F.one();
    const two16 = pow2(F, 16);
    E.booleanFor(F, sink, v.main(L.ACTIVE));
    for (L.W..L.OUT) |c| E.booleanFor(F, sink, v.main(c));
    for (16..64) |t| for ([2]bool{ false, true }) |hi| {
        var rhs = sigmaHalf(F, v, L.w(t - 2, 0), SMALL1, hi).add(half(F, v, L.w(t - 7, 0), hi)).add(sigmaHalf(F, v, L.w(t - 15, 0), SMALL0, hi)).add(half(F, v, L.w(t - 16, 0), hi));
        if (hi) rhs = rhs.add(carry(F, v, L.scheduleCarry(t, false, 0), 2));
        sink.emit(half(F, v, L.w(t, 0), hi).add(carry(F, v, L.scheduleCarry(t, hi, 0), 2).mul(two16)).sub(rhs));
    };
    for (0..64) |t| {
        const j = t + 4;
        for ([2]bool{ false, true }) |hi| {
            const t1 = half(F, v, L.e(j - 4, 0), hi).add(sigmaHalf(F, v, L.e(j - 1, 0), BIG1, hi)).add(chHalf(F, v, L.e(j - 1, 0), L.e(j - 2, 0), L.e(j - 3, 0), hi)).add(constHalf(F, L.K[t], hi)).add(half(F, v, L.w(t, 0), hi));
            var rhs_e = t1.add(half(F, v, L.a(j - 4, 0), hi));
            if (hi) rhs_e = rhs_e.add(carry(F, v, L.roundCarry(t, .e, false, 0), 3));
            sink.emit(half(F, v, L.e(j, 0), hi).add(carry(F, v, L.roundCarry(t, .e, hi, 0), 3).mul(two16)).sub(rhs_e));
            var rhs_a = t1.add(sigmaHalf(F, v, L.a(j - 1, 0), BIG0, hi)).add(majHalf(F, v, L.a(j - 1, 0), L.a(j - 2, 0), L.a(j - 3, 0), hi));
            if (hi) rhs_a = rhs_a.add(carry(F, v, L.roundCarry(t, .a, false, 0), 3));
            sink.emit(half(F, v, L.a(j, 0), hi).add(carry(F, v, L.roundCarry(t, .a, hi, 0), 3).mul(two16)).sub(rhs_a));
        }
    }
    for (0..8) |i| for ([2]bool{ false, true }) |hi| {
        const b: usize = L.OUT + 4 * i + (if (hi) @as(usize, 2) else 0);
        const out = v.main(b).add(v.main(b + 1).mul(pow2(F, 8)));
        var rhs = half(F, v, L.stateWord(i, 0), hi).add(half(F, v, L.finalWord(i, 0), hi));
        if (hi) rhs = rhs.add(v.main(L.finalCarry(i, false)));
        sink.emit(out.add(v.main(L.finalCarry(i, hi)).mul(two16)).sub(rhs));
    };
    const active = v.main(L.ACTIVE);
    const previous = v.previousActive();
    const first = v.fixed(L.FIRST);
    sink.emit(first.mul(one.sub(active)));
    sink.emit(one.sub(first).mul(active).mul(one.sub(previous)));
    sink.emit(previous.mul(one.sub(active)).mul(v.fixed(L.ROW).sub(E.callsFor(F, public))));
    sink.emit(v.fixed(L.LAST).mul(active));
}

pub fn emit(comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), claim: E.ConstFor(F), wire: WireFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    emitMain(F, v, public, sink);
    const active = v.main(L.ACTIVE);
    var d: [4]E.SecureFor(F) = undefined;
    for (&d, [4]u32{ L.STATE_WIRE, L.MESSAGE_WIRES[0], L.MESSAGE_WIRES[1], L.OUTPUT_WIRE }) |*x, id| x.* = E.denominatorFor(F, wire.offset, &wire.coefficients, &tuple(F, v, public, id), true);
    // Inputs are consumed (-active); the new state is produced (+active).
    const c0 = secure(F, v, 0, false);
    const c1 = secure(F, v, 4, false);
    const c1_prev = secure(F, v, 4, true);
    const delta0 = c0.sub(c1_prev).add(E.mulBaseFor(F, E.splatFor(F, claim), v.fixed(L.FIRST)));
    sink.emit(delta0.mul(d[0]).mul(d[1]).add(E.mulBaseFor(F, d[0].add(d[1]), active)));
    sink.emit(c1.sub(c0).mul(d[2]).mul(d[3]).add(E.mulBaseFor(F, d[3].sub(d[2]), active)));
}

comptime {
    std.debug.assert(L.CONSTRAINTS == L.BOOLEANS + 96 + 256 + 16 + 4 + 2);
}
