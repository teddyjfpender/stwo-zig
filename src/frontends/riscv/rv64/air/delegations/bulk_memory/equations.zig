//! The single polynomial authority for the three bulk-memory kinds.
//!
//! All constraints have degree <= 3. Fractions are listed per row in a fixed
//! order; consecutive pairs share one inverse group `inv * d1 * d2 = 1`, and
//! each relation (RAM14, OWNER19, U16) keeps one centered prefix column.
const std = @import("std");
const E = @import("../../evaluation.zig");
const S = @import("../../providers/scalar_range.zig");
const Decode = @import("../../../decode.zig");
const L = @import("layout.zig");
const T = @import("types.zig");

pub const RAM = 0;
pub const OWNER = 1;
pub const RANGE16 = 2;
pub fn Fraction(comptime F: type) type {
    return struct { d: E.SecureFor(F), w: F, relation: u2 };
}
pub fn ramTuple(comptime F: type, address: [4]F, epoch: F, low: F, high: F, value: [4]F, readable: F, writable: F) [14]F {
    var out: [14]F = undefined;
    out[0] = F.one();
    @memcpy(out[1..5], &address);
    out[5] = epoch;
    out[6] = low;
    out[7] = high;
    @memcpy(out[8..12], &value);
    out[12] = readable;
    out[13] = writable;
    return out;
}
fn limbs(comptime F: type, m: []const F, start: usize) [4]F {
    return m[start..][0..4].*;
}
/// Address limbs of `base + step` given three Boolean carries; the top limb has
/// no carry out, so a wrapping address is non-canonical and cannot meet RAM.
pub fn advance(comptime F: type, base: [4]F, carries: []const F, step: u32) [4]F {
    var out: [4]F = undefined;
    for (0..4) |c| {
        const in = if (c == 0) E.qFor(F, step) else carries[c - 1];
        out[c] = base[c].add(in);
        if (c < 3) out[c] = out[c].sub(carries[c].mul(E.qFor(F, 65536)));
    }
    return out;
}
fn ecallTuple(comptime F: type, m: []const F) [19]F {
    var out: [19]F = @splat(F.zero());
    out[0] = E.qFor(F, @intFromEnum(Decode.Opcode.ECALL));
    @memcpy(out[1..5], m[L.desc.pointer..][0..4]);
    out[9] = F.one().add(m[L.desc.set]); // a7 limb 0: 1 (memcpy) or 2 (memset)
    out[10] = E.qFor(F, 3); // a7 limb 1
    out[17] = m[L.desc.epoch];
    out[18] = m[L.desc.tick_low].add(m[L.desc.tick_high].mul(E.qFor(F, 65536)));
    return out;
}
/// Shared token shape: tag, after clock, dst, payload (src limbs or fill), words.
pub fn tokenTuple(comptime F: type, tag: u32, epoch: F, low: F, high: F, dst: [4]F, payload: [4]F, words: F) [19]F {
    var out: [19]F = @splat(F.zero());
    out[0] = E.qFor(F, tag);
    out[1] = epoch;
    out[2] = low;
    out[3] = high;
    @memcpy(out[4..8], &dst);
    @memcpy(out[8..12], &payload);
    out[12] = words;
    return out;
}
pub fn descWords(comptime F: type, m: []const F) F {
    return m[L.desc.len_q0].add(m[L.desc.len_l1].mul(E.qFor(F, 8192)));
}
pub fn descPacket(comptime F: type, m: []const F, k: usize) [4]F {
    return switch (k) {
        0 => limbs(F, m, L.desc.dst),
        1 => limbs(F, m, L.desc.word1),
        else => .{ m[L.desc.len_q0].mul(E.qFor(F, 8)), m[L.desc.len_l1], F.zero(), F.zero() },
    };
}
pub fn descAddress(comptime F: type, m: []const F, k: usize) [4]F {
    const p = limbs(F, m, L.desc.pointer);
    if (k == 0) return p;
    const p8 = advance(F, p, m[L.desc.carry8..][0..3], 8);
    return if (k == 1) p8 else advance(F, p8, m[L.desc.carry16..][0..3], 8);
}
fn afterClock(comptime F: type, m: []const F, kind: L.Kind) [3]F {
    const base: usize = if (kind == .desc) L.desc.epoch else L.copy.epoch;
    return m[base..][0..3].*;
}
fn ramPair(comptime F: type, ch: T.Challenges, address: [4]F, k: []const F, after: [3]F, before_value: [4]F, after_value: [4]F, readable: F, writable: F, active: F) [2]Fraction(F) {
    const b = ch.ram.denominatorFor(F, ramTuple(F, address, k[L.clock.epoch], k[L.clock.low], k[L.clock.high], before_value, readable, writable));
    const a = ch.ram.denominatorFor(F, ramTuple(F, address, after[0], after[1], after[2], after_value, readable, writable));
    return .{ .{ .d = b, .w = active, .relation = RAM }, .{ .d = a, .w = active.neg(), .relation = RAM } };
}
fn range(comptime F: type, ch: T.Challenges, value: F) Fraction(F) {
    return .{ .d = ch.range16.denominatorFor(F, value), .w = F.one(), .relation = RANGE16 };
}
/// U8 facts as two U16 facts: x < 2^16 and 256x < 2^16 imply x < 256.
fn byteRanges(comptime F: type, ch: T.Challenges, value: F) [2]Fraction(F) {
    return .{ range(F, ch, value), range(F, ch, value.mul(E.qFor(F, 256))) };
}
fn clockRanges(comptime F: type, ch: T.Challenges, k: []const F) [3]Fraction(F) {
    const b = byteRanges(F, ch, k[L.clock.gap8]);
    return .{ range(F, ch, k[L.clock.gap16]), b[0], b[1] };
}
pub fn fractions(comptime F: type, comptime kind: L.Kind, m: []const F, ch: T.Challenges) [L.fractionCount(kind)]Fraction(F) {
    var out: [L.fractionCount(kind)]Fraction(F) = undefined;
    var at: usize = 0;
    const one = F.one();
    const after = afterClock(F, m, kind);
    switch (kind) {
        .desc => {
            const a = m[L.desc.active];
            const set = m[L.desc.set];
            for (0..3) |k| {
                const value = descPacket(F, m, k);
                const pair = ramPair(F, ch, descAddress(F, m, k), m[L.desc.clocks + L.CLOCK * k ..][0..L.CLOCK], after, value, value, one, m[L.desc.writable + k], a);
                out[at] = pair[0];
                out[at + 1] = pair[1];
                at += 2;
            }
            const dst = limbs(F, m, L.desc.dst);
            const words = descWords(F, m);
            out[at] = .{ .d = ch.owner.denominatorFor(F, ecallTuple(F, m)), .w = a.neg(), .relation = OWNER };
            out[at + 1] = .{ .d = ch.owner.denominatorFor(F, tokenTuple(F, T.TOKEN_COPY, after[0], after[1], after[2], dst, limbs(F, m, L.desc.word1), words)), .w = a.sub(set), .relation = OWNER };
            out[at + 2] = .{ .d = ch.owner.denominatorFor(F, tokenTuple(F, T.TOKEN_SET, after[0], after[1], after[2], dst, .{ m[L.desc.fill_low], F.zero(), F.zero(), F.zero() }, words)), .w = set, .relation = OWNER };
            at += 3;
            out[at] = range(F, ch, m[L.desc.tick_low]);
            at += 1;
            inline for (.{ m[L.desc.tick_high], m[L.desc.fill_low], m[L.desc.fill_high] }) |v| {
                const b = byteRanges(F, ch, v);
                out[at] = b[0];
                out[at + 1] = b[1];
                at += 2;
            }
            out[at] = range(F, ch, m[L.desc.len_q0]);
            at += 1;
            for (0..3) |k| {
                const r = clockRanges(F, ch, m[L.desc.clocks + L.CLOCK * k ..][0..L.CLOCK]);
                @memcpy(out[at..][0..3], &r);
                at += 3;
            }
        },
        .copy => {
            const a = m[L.copy.active];
            const value = limbs(F, m, L.copy.value);
            const d = ramPair(F, ch, limbs(F, m, L.copy.dst), m[L.copy.dst_clock..][0..L.CLOCK], after, limbs(F, m, L.copy.dst_before), value, one, one, a);
            const s = ramPair(F, ch, limbs(F, m, L.copy.src), m[L.copy.src_clock..][0..L.CLOCK], after, value, value, one, m[L.copy.src_writable], a);
            out[0..4].* = .{ d[0], d[1], s[0], s[1] };
            out[4] = .{ .d = ch.owner.denominatorFor(F, tokenTuple(F, T.TOKEN_COPY, after[0], after[1], after[2], limbs(F, m, L.copy.dst), limbs(F, m, L.copy.src), m[L.copy.remaining])), .w = m[L.copy.start].neg(), .relation = OWNER };
            const rd = clockRanges(F, ch, m[L.copy.dst_clock..][0..L.CLOCK]);
            const rs = clockRanges(F, ch, m[L.copy.src_clock..][0..L.CLOCK]);
            out[5..8].* = rd;
            out[8..11].* = rs;
            at = 11;
        },
        .set => {
            const a = m[L.set.active];
            const fill = m[L.set.fill].mul(E.qFor(F, 257));
            const d = ramPair(F, ch, limbs(F, m, L.set.dst), m[L.set.dst_clock..][0..L.CLOCK], after, limbs(F, m, L.set.dst_before), .{ fill, fill, fill, fill }, one, one, a);
            out[0..2].* = d;
            out[2] = .{ .d = ch.owner.denominatorFor(F, tokenTuple(F, T.TOKEN_SET, after[0], after[1], after[2], limbs(F, m, L.set.dst), .{ m[L.set.fill], F.zero(), F.zero(), F.zero() }, m[L.set.remaining])), .w = m[L.set.start].neg(), .relation = OWNER };
            out[3..6].* = clockRanges(F, ch, m[L.set.dst_clock..][0..L.CLOCK]);
            at = 6;
        },
    }
    std.debug.assert(at == out.len);
    return out;
}
/// Strict lexicographic RAM predecessor `(be, bt) < (E, T)` as an integer fact.
/// Same epoch: bl + 2^16 bh + g16 + 2^16 g8 + 1 = TL + 2^16 TH (< 2^25 < p).
/// Cross epoch: be + g16 + 1 = E (< 2^17 < p). Gap ranges come from fractions.
fn clockConstraints(comptime F: type, k: []const F, after: [3]F, active: F, out: *E.SinkFor(F)) void {
    const one = F.one();
    const big = E.qFor(F, 65536);
    const same = k[L.clock.same];
    E.booleanFor(F, out, same);
    out.emit(active.mul(same).mul(k[L.clock.epoch].sub(after[0])));
    const lhs = k[L.clock.low].add(k[L.clock.high].mul(big)).add(k[L.clock.gap16]).add(k[L.clock.gap8].mul(big)).add(one);
    out.emit(active.mul(same).mul(lhs.sub(after[1]).sub(after[2].mul(big))));
    out.emit(active.mul(one.sub(same)).mul(k[L.clock.epoch].add(k[L.clock.gap16]).add(one).sub(after[0])));
}
/// Active rows are exactly the public prefix `[0, rows)` and the last row is
/// padding, so the wrapped predecessor of row 0 is inactive.
fn countConstraints(comptime F: type, f: []const F, active: F, previous: F, rows: u32, out: *E.SinkFor(F)) void {
    const one = F.one();
    const first = f[1];
    out.emit(first.mul(active.sub(E.qFor(F, @intFromBool(rows != 0)))));
    out.emit(f[2].mul(active));
    out.emit(one.sub(first).mul(active).mul(one.sub(previous)));
    out.emit(one.sub(first).mul(previous.sub(active)).mul(f[0].sub(E.qFor(F, rows))));
}
/// One call is a maximal run of body rows: start row (token), then
/// continuation rows with address +8, remaining -1, same after clock and
/// payload, ending exactly at remaining = 1.
fn chainConstraints(comptime F: type, comptime kind: L.Kind, m: []const F, pm: []const F, out: *E.SinkFor(F)) void {
    const C = if (kind == .copy) L.copy else L.set;
    const one = F.one();
    const a = m[C.active];
    const s = m[C.start];
    const c = a.sub(s);
    E.booleanFor(F, out, s);
    out.emit(c.mul(one.sub(pm[C.active])));
    out.emit(pm[C.active].mul(pm[C.remaining].sub(one)).mul(one.sub(c)));
    for ([_]usize{ C.epoch, C.tick_low, C.tick_high }) |col| out.emit(c.mul(m[col].sub(pm[col])));
    out.emit(c.mul(pm[C.remaining].sub(one).sub(m[C.remaining])));
    chain(F, m, pm, C.dst, C.dst_carry, s, c, out);
    if (kind == .copy) chain(F, m, pm, L.copy.src, L.copy.src_carry, s, c, out) else out.emit(c.mul(m[L.set.fill].sub(pm[L.set.fill])));
}
fn chain(comptime F: type, m: []const F, pm: []const F, address: usize, carries: usize, s: F, c: F, out: *E.SinkFor(F)) void {
    for (m[carries..][0..3]) |v| {
        E.booleanFor(F, out, v);
        out.emit(s.mul(v));
    }
    const next = advance(F, pm[address..][0..4].*, m[carries..][0..3], 8);
    for (0..4) |i| out.emit(c.mul(next[i].sub(m[address + i])));
}
pub fn emitFor(comptime F: type, comptime kind: L.Kind, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, rows: u32, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    const one = F.one();
    const a = m[0];
    const width = L.main(kind);
    E.booleanFor(F, out, a);
    for (m[1..width]) |v| out.emit(one.sub(a).mul(v));
    countConstraints(F, f, a, pm[0], rows, out);
    const after = afterClock(F, m, kind);
    switch (kind) {
        .desc => {
            E.booleanFor(F, out, m[L.desc.set]);
            for (m[L.desc.carry8..][0..6]) |v| E.booleanFor(F, out, v);
            out.emit(m[L.desc.word1].sub(m[L.desc.fill_low]).sub(m[L.desc.fill_high].mul(E.qFor(F, 256))));
            for (0..3) |k| clockConstraints(F, m[L.desc.clocks + L.CLOCK * k ..][0..L.CLOCK], after, a, out);
            for (m[L.desc.writable..][0..3]) |v| E.booleanFor(F, out, v);
        },
        .copy => {
            chainConstraints(F, .copy, m, pm, out);
            clockConstraints(F, m[L.copy.dst_clock..][0..L.CLOCK], after, a, out);
            clockConstraints(F, m[L.copy.src_clock..][0..L.CLOCK], after, a, out);
            E.booleanFor(F, out, m[L.copy.src_writable]);
        },
        .set => {
            chainConstraints(F, .set, m, pm, out);
            clockConstraints(F, m[L.set.dst_clock..][0..L.CLOCK], after, a, out);
        },
    }
    emitFractions(F, kind, f, m, i, pi, claims, ch, out);
}
pub fn emitFractions(comptime F: type, comptime kind: L.Kind, f: []const F, m: []const F, i: []const F, pi: []const F, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    const Sec = E.SecureFor(F);
    const list = fractions(F, kind, m, ch);
    var sums = [3]Sec{ Sec.zero(), Sec.zero(), Sec.zero() };
    var j: usize = 0;
    while (j < list.len) : (j += 2) {
        const inverse = E.secureFor(F, i, 2 * j);
        const x = list[j];
        if (j + 1 < list.len) {
            const y = list[j + 1];
            out.emit(inverse.mul(x.d).mul(y.d).sub(Sec.one()));
            sums[x.relation] = sums[x.relation].add(E.mulBaseFor(F, y.d.mul(inverse), x.w));
            sums[y.relation] = sums[y.relation].add(E.mulBaseFor(F, x.d.mul(inverse), y.w));
        } else {
            out.emit(inverse.mul(x.d).sub(Sec.one()));
            sums[x.relation] = sums[x.relation].add(E.mulBaseFor(F, inverse, x.w));
        }
    }
    const values = claims.values();
    for (0..3) |r| {
        const at = L.prefix(kind, r);
        S.prefix(F, sums[r], E.secureFor(F, i, at), E.secureFor(F, pi, at), f[1], f[2], values[r], out);
    }
}
