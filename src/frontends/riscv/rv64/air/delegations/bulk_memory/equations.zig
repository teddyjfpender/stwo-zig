//! The single polynomial authority for the six bulk-memory kinds.
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
    return advanceBy(F, base, carries, E.qFor(F, step));
}
/// As `advance` with a step that is an affine expression in the trace.
pub fn advanceBy(comptime F: type, base: [4]F, carries: []const F, step: F) [4]F {
    var out: [4]F = undefined;
    for (0..4) |c| {
        const in = if (c == 0) step else carries[c - 1];
        out[c] = base[c].add(in);
        if (c < 3) out[c] = out[c].sub(carries[c].mul(E.qFor(F, 65536)));
    }
    return out;
}
/// CPU OWNER19 ECALL tuple: pointer `a0`, tag limbs `(limb0, 3, 0, 0)`, clock.
fn ecallTuple(comptime F: type, pointer: [4]F, limb0: F, epoch: F, low: F, high: F) [19]F {
    var out: [19]F = @splat(F.zero());
    out[0] = E.qFor(F, @intFromEnum(Decode.Opcode.ECALL));
    @memcpy(out[1..5], &pointer);
    out[9] = limb0; // a7 limb 0: 1 memcpy, 2 memset, 3 memcmp
    out[10] = E.qFor(F, 3); // a7 limb 1
    out[17] = epoch;
    out[18] = low.add(high.mul(E.qFor(F, 65536)));
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
/// memcmp result token (last body row -> descriptor): sign bits of the result.
pub fn resultTuple(comptime F: type, after: [3]F, neg: F, pos: F) [19]F {
    var out: [19]F = @splat(F.zero());
    out[0] = E.qFor(F, T.TOKEN_CMP_RESULT);
    out[1] = after[0];
    out[2] = after[1];
    out[3] = after[2];
    out[4] = neg;
    out[5] = pos;
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
    const base: usize = switch (kind) {
        .desc => L.desc.epoch,
        .cdesc => L.cdesc.epoch,
        .copy, .set, .ucopy, .cmp => L.copy.epoch,
    };
    return m[base..][0..3].*;
}
/// The limbs of an unaligned source word from its bytes.
pub fn byteLimbs(comptime F: type, bytes: []const F) [4]F {
    var out: [4]F = undefined;
    for (0..4) |i| out[i] = bytes[2 * i].add(bytes[2 * i + 1].mul(E.qFor(F, 256)));
    return out;
}
/// Unaligned copy: the destination limb `i` at byte shift `r` from the 16
/// bytes `prev ++ cur` (previous and current source words).
pub fn shiftedLimb(comptime F: type, prev: []const F, cur: []const F, r: usize, i: usize) F {
    const lo = 2 * i + r;
    const b0 = if (lo < 8) prev[lo] else cur[lo - 8];
    const b1 = if (lo + 1 < 8) prev[lo + 1] else cur[lo + 1 - 8];
    return b0.add(b1.mul(E.qFor(F, 256)));
}
/// Token source address of an unaligned run: aligned word + shift.
pub fn ucopySource(comptime F: type, m: []const F) [4]F {
    var out = limbs(F, m, L.ucopy.src);
    for (0..7) |k| out[0] = out[0].add(m[L.ucopy.sel + k].mul(E.qFor(F, @intCast(k + 1))));
    return out;
}
/// The memcmp result word: -1 (neg), 1 (pos) or 0 as four u16 limbs.
pub fn resultLimbs(comptime F: type, neg: F, pos: F) [4]F {
    const n = neg.mul(E.qFor(F, 65535));
    return .{ pos.add(n), n, n, n };
}
pub fn cdescPacket(comptime F: type, m: []const F, k: usize) [4]F {
    return switch (k) {
        0 => limbs(F, m, L.cdesc.a),
        1 => limbs(F, m, L.cdesc.b),
        else => .{ m[L.cdesc.len_q0].mul(E.qFor(F, 8)), m[L.cdesc.len_l1], F.zero(), F.zero() },
    };
}
pub fn cdescAddress(comptime F: type, m: []const F, k: usize) [4]F {
    var p = limbs(F, m, L.cdesc.pointer);
    const carries = [3]usize{ L.cdesc.carry8, L.cdesc.carry16, L.cdesc.carry24 };
    for (0..k) |j| p = advance(F, p, m[carries[j]..][0..3], 8);
    return p;
}
/// Lookup-cheap byte split of a canonical limb `lo + 256 hi`: `lo < 256` as
/// two U16 facts and `hi < 2^16` as one; with the limb < 2^16 this forces
/// `hi < 256` (lo + 256 hi < 2^24 < p is an integer equation).
fn limbBytes(comptime F: type, ch: T.Challenges, lo: F, hi: F) [3]Fraction(F) {
    const b = byteRanges(F, ch, lo);
    return .{ b[0], b[1], range(F, ch, hi) };
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
            out[at] = .{ .d = ch.owner.denominatorFor(F, ecallTuple(F, limbs(F, m, L.desc.pointer), F.one().add(set), after[0], after[1], after[2])), .w = a.neg(), .relation = OWNER };
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
        .ucopy => {
            const U = L.ucopy;
            const a = m[U.active];
            const c = a.sub(m[U.start]);
            const value = byteLimbs(F, m[U.bytes..][0..8]);
            const d = ramPair(F, ch, limbs(F, m, U.dst), m[U.dst_clock..][0..L.CLOCK], after, limbs(F, m, U.dst_before), limbs(F, m, U.out), one, one, c);
            const s = ramPair(F, ch, limbs(F, m, U.src), m[U.src_clock..][0..L.CLOCK], after, value, value, one, m[U.src_writable], a);
            out[0..4].* = .{ d[0], d[1], s[0], s[1] };
            out[4] = .{ .d = ch.owner.denominatorFor(F, tokenTuple(F, T.TOKEN_COPY, after[0], after[1], after[2], limbs(F, m, U.dst), ucopySource(F, m), m[U.remaining].sub(one))), .w = m[U.start].neg(), .relation = OWNER };
            out[5..8].* = clockRanges(F, ch, m[U.dst_clock..][0..L.CLOCK]);
            out[8..11].* = clockRanges(F, ch, m[U.src_clock..][0..L.CLOCK]);
            at = 11;
            for (0..4) |i| {
                out[at..][0..3].* = limbBytes(F, ch, m[U.bytes + 2 * i], m[U.bytes + 2 * i + 1]);
                at += 3;
            }
        },
        .cdesc => {
            const D = L.cdesc;
            const a = m[D.active];
            for (0..3) |k| {
                const value = cdescPacket(F, m, k);
                const pair = ramPair(F, ch, cdescAddress(F, m, k), m[D.clocks + L.CLOCK * k ..][0..L.CLOCK], after, value, value, one, m[D.writable + k], a);
                out[at] = pair[0];
                out[at + 1] = pair[1];
                at += 2;
            }
            const result = ramPair(F, ch, cdescAddress(F, m, 3), m[D.clocks + 3 * L.CLOCK ..][0..L.CLOCK], after, limbs(F, m, D.result_before), resultLimbs(F, m[D.neg], m[D.pos]), one, one, a);
            out[at] = result[0];
            out[at + 1] = result[1];
            at += 2;
            out[at] = .{ .d = ch.owner.denominatorFor(F, ecallTuple(F, limbs(F, m, D.pointer), E.qFor(F, 3), after[0], after[1], after[2])), .w = a.neg(), .relation = OWNER };
            out[at + 1] = .{ .d = ch.owner.denominatorFor(F, tokenTuple(F, T.TOKEN_CMP, after[0], after[1], after[2], limbs(F, m, D.a), limbs(F, m, D.b), m[D.len_q0].add(m[D.len_l1].mul(E.qFor(F, 8192))))), .w = a, .relation = OWNER };
            out[at + 2] = .{ .d = ch.owner.denominatorFor(F, resultTuple(F, after, m[D.neg], m[D.pos])), .w = a.neg(), .relation = OWNER };
            at += 3;
            out[at] = range(F, ch, m[D.tick_low]);
            const th = byteRanges(F, ch, m[D.tick_high]);
            out[at + 1] = th[0];
            out[at + 2] = th[1];
            out[at + 3] = range(F, ch, m[D.len_q0]);
            at += 4;
            for (0..4) |k| {
                out[at..][0..3].* = clockRanges(F, ch, m[D.clocks + L.CLOCK * k ..][0..L.CLOCK]);
                at += 3;
            }
        },
        .cmp => {
            const C = L.cmp;
            const a = m[C.active];
            const pa = ramPair(F, ch, limbs(F, m, C.a), m[C.a_clock..][0..L.CLOCK], after, limbs(F, m, C.va), limbs(F, m, C.va), one, m[C.a_writable], a);
            const pb = ramPair(F, ch, limbs(F, m, C.b), m[C.b_clock..][0..L.CLOCK], after, limbs(F, m, C.vb), limbs(F, m, C.vb), one, m[C.b_writable], a);
            out[0..4].* = .{ pa[0], pa[1], pb[0], pb[1] };
            out[4] = .{ .d = ch.owner.denominatorFor(F, tokenTuple(F, T.TOKEN_CMP, after[0], after[1], after[2], limbs(F, m, C.a), limbs(F, m, C.b), m[C.remaining])), .w = m[C.start].neg(), .relation = OWNER };
            out[5] = .{ .d = ch.owner.denominatorFor(F, resultTuple(F, after, m[C.lt], m[C.diff].sub(m[C.lt]))), .w = m[C.last], .relation = OWNER };
            out[6..9].* = clockRanges(F, ch, m[C.a_clock..][0..L.CLOCK]);
            out[9..12].* = clockRanges(F, ch, m[C.b_clock..][0..L.CLOCK]);
            out[12..15].* = limbBytes(F, ch, m[C.alo], m[C.ahi]);
            out[15..18].* = limbBytes(F, ch, m[C.blo], m[C.bhi]);
            out[18] = range(F, ch, m[C.gap]);
            at = 19;
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
/// Unaligned copy run: lead row + one row per destination word. The lead row
/// does not advance the destination (the row after it writes word 0).
fn ucopyConstraints(comptime F: type, m: []const F, pm: []const F, out: *E.SinkFor(F)) void {
    const U = L.ucopy;
    const one = F.one();
    const a = m[U.active];
    const s = m[U.start];
    const c = a.sub(s);
    E.booleanFor(F, out, s);
    out.emit(c.mul(one.sub(pm[U.active])));
    out.emit(pm[U.active].mul(pm[U.remaining].sub(one)).mul(one.sub(c)));
    for ([_]usize{ U.epoch, U.tick_low, U.tick_high }) |col| out.emit(c.mul(m[col].sub(pm[col])));
    out.emit(c.mul(pm[U.remaining].sub(one).sub(m[U.remaining])));
    // Destination: +8 except right after the lead row (step 8 (1 - start')).
    for (m[U.dst_carry..][0..3]) |v| {
        E.booleanFor(F, out, v);
        out.emit(s.mul(v));
    }
    const next = advanceBy(F, pm[U.dst..][0..4].*, m[U.dst_carry..][0..3], E.qFor(F, 8).mul(one.sub(pm[U.start])));
    for (0..4) |i| out.emit(c.mul(next[i].sub(m[U.dst + i])));
    chain(F, m, pm, U.src, U.src_carry, s, c, out);
    // One-hot shift 1..7, constant along the run.
    var sum = F.zero();
    for (0..7) |k| {
        E.booleanFor(F, out, m[U.sel + k]);
        sum = sum.add(m[U.sel + k]);
    }
    out.emit(sum.sub(a));
    for (0..7) |k| out.emit(c.mul(m[U.sel + k].sub(pm[U.sel + k])));
    // Written limbs from the previous and current source bytes.
    for (0..4) |i| {
        var v = F.zero();
        for (0..7) |k| v = v.add(m[U.sel + k].mul(shiftedLimb(F, pm[U.bytes..][0..8], m[U.bytes..][0..8], k + 1, i)));
        out.emit(c.mul(m[U.out + i].sub(v)));
    }
}
/// memcmp run: rows up to the first differing word pair (or all `N`).
fn cmpConstraints(comptime F: type, m: []const F, pm: []const F, out: *E.SinkFor(F)) void {
    const C = L.cmp;
    const one = F.one();
    const a = m[C.active];
    const s = m[C.start];
    const c = a.sub(s);
    const last = m[C.last];
    const diff = m[C.diff];
    const is_one = m[C.is_one];
    E.booleanFor(F, out, s);
    E.booleanFor(F, out, last);
    out.emit(c.mul(one.sub(pm[C.active])));
    out.emit(c.mul(pm[C.last]));
    out.emit(pm[C.active].mul(one.sub(pm[C.last])).mul(one.sub(c)));
    for ([_]usize{ C.epoch, C.tick_low, C.tick_high }) |col| out.emit(c.mul(m[col].sub(pm[col])));
    out.emit(c.mul(pm[C.remaining].sub(one).sub(m[C.remaining])));
    chain(F, m, pm, C.a, C.a_carry, s, c, out);
    chain(F, m, pm, C.b, C.b_carry, s, c, out);
    // is_one = [remaining == 1]; the run ends exactly at a difference or there.
    const r1 = m[C.remaining].sub(one);
    E.booleanFor(F, out, is_one);
    out.emit(r1.mul(is_one));
    out.emit(a.mul(r1.mul(m[C.inv]).sub(one).add(is_one)));
    out.emit(last.mul(one.sub(diff)).mul(one.sub(is_one)));
    out.emit(diff.mul(one.sub(last)));
    out.emit(is_one.mul(one.sub(last)));
    // First difference: equal limbs before the selected limb, equal low bytes
    // when it is the high byte, and a strict byte order with sign `lt`.
    E.booleanFor(F, out, diff);
    var sum = F.zero();
    for (0..4) |i| {
        E.booleanFor(F, out, m[C.limbsel + i]);
        sum = sum.add(m[C.limbsel + i]);
    }
    E.booleanFor(F, out, m[C.hb]);
    E.booleanFor(F, out, m[C.lt]);
    out.emit(sum.sub(diff));
    for (0..4) |i| out.emit(one.sub(diff).mul(m[C.va + i].sub(m[C.vb + i])));
    for (0..3) |i| {
        var before_selected = F.zero();
        for (i + 1..4) |k| before_selected = before_selected.add(m[C.limbsel + k]);
        out.emit(before_selected.mul(m[C.va + i].sub(m[C.vb + i])));
    }
    var sa = F.zero();
    var sb = F.zero();
    for (0..4) |i| {
        sa = sa.add(m[C.limbsel + i].mul(m[C.va + i]));
        sb = sb.add(m[C.limbsel + i].mul(m[C.vb + i]));
    }
    const k256 = E.qFor(F, 256);
    out.emit(m[C.alo].add(m[C.ahi].mul(k256)).sub(sa));
    out.emit(m[C.blo].add(m[C.bhi].mul(k256)).sub(sb));
    const hb = m[C.hb];
    out.emit(hb.mul(m[C.alo].sub(m[C.blo])));
    out.emit(m[C.da].sub(m[C.alo]).sub(hb.mul(m[C.ahi].sub(m[C.alo]))));
    out.emit(m[C.db].sub(m[C.blo]).sub(hb.mul(m[C.bhi].sub(m[C.blo]))));
    const sign = one.sub(m[C.lt].mul(E.qFor(F, 2)));
    out.emit(diff.mul(m[C.gap].add(one).sub(sign.mul(m[C.da].sub(m[C.db])))));
    out.emit(one.sub(diff).mul(m[C.gap]));
    out.emit(one.sub(diff).mul(m[C.lt]));
    out.emit(one.sub(diff).mul(hb));
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
        .ucopy => {
            ucopyConstraints(F, m, pm, out);
            clockConstraints(F, m[L.ucopy.dst_clock..][0..L.CLOCK], after, a.sub(m[L.ucopy.start]), out);
            clockConstraints(F, m[L.ucopy.src_clock..][0..L.CLOCK], after, a, out);
            E.booleanFor(F, out, m[L.ucopy.src_writable]);
        },
        .cdesc => {
            const D = L.cdesc;
            for (m[D.carry8..][0..9]) |v| E.booleanFor(F, out, v);
            for (0..4) |k| clockConstraints(F, m[D.clocks + L.CLOCK * k ..][0..L.CLOCK], after, a, out);
            for (m[D.writable..][0..3]) |v| E.booleanFor(F, out, v);
            E.booleanFor(F, out, m[D.neg]);
            E.booleanFor(F, out, m[D.pos]);
            out.emit(m[D.neg].mul(m[D.pos]));
        },
        .cmp => {
            cmpConstraints(F, m, pm, out);
            clockConstraints(F, m[L.cmp.a_clock..][0..L.CLOCK], after, a, out);
            clockConstraints(F, m[L.cmp.b_clock..][0..L.CLOCK], after, a, out);
            E.booleanFor(F, out, m[L.cmp.a_writable]);
            E.booleanFor(F, out, m[L.cmp.b_writable]);
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
