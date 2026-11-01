//! One degree-3 scalar/packed constraint authority for the arith256_mod truth.
//! `v` is a mask view with fixed(c), main(c), previousActive(),
//! interaction(c) and previousInteraction(c); all lanes share this order.
const std = @import("std");
const E = @import("../../evaluation.zig");
const L = @import("layout.zig");
pub const WireFor = @import("../secp256k1/equations.zig").WireFor;
pub const Wire = WireFor(E.Q);

/// Local challenges: the BYTE lookup point (drawn after MAIN is committed)
/// and the shared Wire35 challenges.
pub fn ChallengesFor(comptime C: type) type {
    return struct { bytes: C, wire: WireFor(C) };
}
pub const Challenges = ChallengesFor(E.Q);

inline fn k(comptime F: type, value: u32) F {
    return E.qFor(F, value);
}
fn carry(comptime F: type, v: anytype, j: usize) F {
    if (j >= L.CARRIES) return F.zero();
    return v.main(L.CARRY_LO + j).add(v.main(L.CARRY_HI + j).mul(k(F, 256))).sub(v.main(L.ACTIVE).mul(k(F, L.CARRY_OFFSET)));
}
fn chunk(comptime F: type, v: anytype, base: usize, i: usize) F {
    return v.main(base + 2 * i).add(v.main(base + 2 * i + 1).mul(k(F, 256)));
}
/// sum_i x_i y_{n-i} over the byte columns of two operands.
fn convolution(comptime F: type, v: anytype, x: usize, x_len: usize, y: usize, y_len: usize, n: usize) F {
    var acc = F.zero();
    var i: usize = if (n + 1 > y_len) n + 1 - y_len else 0;
    while (i < x_len and i <= n) : (i += 1) acc = acc.add(v.main(x + i).mul(v.main(y + n - i)));
    return acc;
}
/// Positive part a*b + c and negative part q*m + r of coefficient n.
fn positive(comptime F: type, v: anytype, n: usize) F {
    var acc = convolution(F, v, L.A, L.LIMBS, L.B, L.LIMBS, n);
    if (n < L.LIMBS) acc = acc.add(v.main(L.C + n));
    return acc;
}
fn negative(comptime F: type, v: anytype, n: usize) F {
    var acc = convolution(F, v, L.QUOTIENT, L.Q_LIMBS, L.M, L.LIMBS, n);
    if (n < L.LIMBS) acc = acc.add(v.main(L.R + n));
    return acc;
}
pub fn byteQuery(comptime F: type, v: anytype, index: usize) F {
    const q = L.query(index);
    const x = v.main(q.column);
    return if (q.addend == 0) x else x.add(k(F, q.addend));
}

/// Byte b (0..31) of a Wire35 coordinate.
fn wireColumn(wire: u32) usize {
    return switch (wire) {
        0 => L.A,
        1 => L.B,
        2 => L.C,
        3 => L.M,
        4 => L.R_BEFORE,
        L.OUTPUT_WIRE => L.R,
        else => unreachable,
    };
}
pub fn tuple(comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), wire: u32) [L.WIRE_ARITY]F {
    var t: [L.WIRE_ARITY]F = undefined;
    t[0] = k(F, L.PROGRAM_KIND);
    t[1] = E.firstIdFor(F, public).add(v.fixed(L.ROW));
    t[2] = k(F, wire);
    const base = wireColumn(wire);
    for (0..32) |b| t[3 + b] = v.main(base + b);
    return t;
}
fn secure(comptime F: type, v: anytype, start: usize, previous: bool) E.SecureFor(F) {
    var c: [4]F = undefined;
    for (&c, 0..) |*x, i| x.* = if (previous) v.previousInteraction(start + i) else v.interaction(start + i);
    return E.secureFromCoordinatesFor(F, c);
}

/// MAIN-only authority: Booleanity, the m = 0 indicator, the carried
/// identity, r < m and the contiguous activity prefix. Emission order is
/// protocol authority.
pub fn emitMain(comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    const one = F.one();
    const active = v.main(L.ACTIVE);
    const z = v.main(L.Z);
    E.booleanFor(F, sink, active);
    E.booleanFor(F, sink, z);
    for (0..L.BORROWS) |i| E.booleanFor(F, sink, v.main(L.BORROW + i));
    // z = [m == 0]: sum(m) is a sum of Wire35-inherited bytes, below 2^13.
    var sum_m = F.zero();
    for (0..L.LIMBS) |i| sum_m = sum_m.add(v.main(L.M + i));
    sink.emit(z.mul(sum_m));
    sink.emit(sum_m.mul(v.main(L.INV)).sub(active.sub(z)));
    // (1 - z)(a*b + c) - q*m - r = 0, two coefficients per carried group.
    const live = one.sub(z);
    const radix = k(F, 256);
    for (0..L.GROUPS) |j| {
        const lo = 2 * j;
        const hi = lo + 1;
        var pos = positive(F, v, lo);
        var neg = negative(F, v, lo);
        if (hi < L.COEFFICIENTS) {
            pos = pos.add(positive(F, v, hi).mul(radix));
            neg = neg.add(negative(F, v, hi).mul(radix));
        }
        var g = live.mul(pos).sub(neg).sub(carry(F, v, j).mul(k(F, 65536)));
        if (j > 0) g = g.add(carry(F, v, j - 1));
        sink.emit(g);
    }
    // m - r - (active - z) = d, borrows on 16-bit chunks, no final borrow.
    for (0..L.CHUNKS) |i| {
        var e = chunk(F, v, L.M, i).sub(chunk(F, v, L.R, i)).sub(chunk(F, v, L.D, i));
        if (i == 0) e = e.sub(active.sub(z));
        if (i > 0) e = e.sub(v.main(L.BORROW + i - 1));
        if (i < L.BORROWS) e = e.add(v.main(L.BORROW + i).mul(k(F, 65536)));
        sink.emit(e);
    }
    const previous = v.previousActive();
    const first = v.fixed(L.FIRST);
    sink.emit(first.mul(one.sub(active)));
    sink.emit(one.sub(first).mul(active).mul(one.sub(previous)));
    sink.emit(previous.mul(one.sub(active)).mul(v.fixed(L.ROW).sub(E.callsFor(F, public))));
    sink.emit(v.fixed(L.LAST).mul(active));
}

/// Fraction `index` of the BYTE chain: (numerator, denominator).
fn byteFraction(comptime F: type, v: anytype, ch: ChallengesFor(E.ConstFor(F)), index: usize) struct { F, E.SecureFor(F) } {
    const gamma = E.splatFor(F, ch.bytes);
    if (index < L.BYTE_QUERIES) return .{ F.one(), gamma.sub(E.liftFor(F, byteQuery(F, v, index))) };
    std.debug.assert(index == L.BYTE_QUERIES);
    return .{ v.main(L.MULT).neg(), gamma.sub(E.liftFor(F, v.fixed(L.BYTE))) };
}
fn batch(comptime F: type, delta: E.SecureFor(F), n0: F, d0: E.SecureFor(F), n1: F, d1: E.SecureFor(F), sink: *E.SinkFor(F)) void {
    sink.emit(delta.mul(d0).mul(d1).sub(E.mulBaseFor(F, d1, n0)).sub(E.mulBaseFor(F, d0, n1)));
}

pub fn emit(comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), claim: E.ConstFor(F), ch: ChallengesFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    emitMain(F, v, public, sink);
    // BYTE chain: closes to zero around the trace (no public claim).
    for (0..L.BYTE_BATCHES) |b| {
        const current = secure(F, v, 4 * b, false);
        const prior = if (b == 0) secure(F, v, L.BYTE_LAST, true) else secure(F, v, 4 * (b - 1), false);
        const f0 = byteFraction(F, v, ch, 2 * b);
        const f1 = byteFraction(F, v, ch, 2 * b + 1);
        batch(F, current.sub(prior), f0[0], f0[1], f1[0], f1[1], sink);
    }
    // Wire35 chain: inputs consumed (-active), the new r produced (+active).
    const active = v.main(L.ACTIVE);
    const ids = [L.WIRE_FRACTIONS]u32{ 0, 1, 2, 3, 4, L.OUTPUT_WIRE };
    for (0..L.WIRE_BATCHES) |w| {
        const at = L.WIRE_FIRST + 4 * w;
        const current = secure(F, v, at, false);
        const prior = if (w == 0) secure(F, v, L.WIRE_LAST, true).sub(E.mulBaseFor(F, E.splatFor(F, claim), v.fixed(L.FIRST))) else secure(F, v, at - 4, false);
        var d: [2]E.SecureFor(F) = undefined;
        var n: [2]F = undefined;
        for (0..2) |i| {
            const id = ids[2 * w + i];
            d[i] = E.denominatorFor(F, ch.wire.offset, &ch.wire.coefficients, &tuple(F, v, public, id), true);
            n[i] = if (id == L.OUTPUT_WIRE) active else active.neg();
        }
        batch(F, current.sub(prior), n[0], d[0], n[1], d[1], sink);
    }
}
