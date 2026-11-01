//! The single polynomial authority for the two Keccak-sponge bridge kinds.
//!
//! All constraints have degree <= 3. Fractions are listed per row in a fixed
//! order; consecutive pairs share one inverse group `inv * d1 * d2 = 1`, and
//! each relation (RAM14, OWNER19, IO11, AND3, U16, U8) keeps one centered
//! prefix column. Soundness argument:
//! design/riscv-proving-stack/rv64-keccak-sponge-service.md.
const std = @import("std");
const E = @import("../../evaluation.zig");
const S = @import("../../providers/scalar_range.zig");
const Decode = @import("../../../decode.zig");
const L = @import("layout.zig");
const T = @import("types.zig");

pub const RAM = 0;
pub const OWNER = 1;
pub const IO = 2;
pub const AND = 3;
pub const RANGE16 = 4;
pub const RANGE8 = 5;
pub fn Fraction(comptime F: type) type {
    return struct { d: E.SecureFor(F), w: F, relation: u3 };
}
fn q(comptime F: type, value: u32) F {
    return E.qFor(F, value);
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
/// Address limbs of `base + step` given three Boolean carries; the top limb has
/// no carry out, so a wrapping address is non-canonical and cannot meet RAM.
pub fn advance(comptime F: type, base: [4]F, carries: []const F, step: u32) [4]F {
    var out: [4]F = undefined;
    for (0..4) |c| {
        const in = if (c == 0) q(F, step) else carries[c - 1];
        out[c] = base[c].add(in);
        if (c < 3) out[c] = out[c].sub(carries[c].mul(q(F, 65536)));
    }
    return out;
}
/// Little-endian u16 limbs of eight byte columns.
pub fn limbsOfBytes(comptime F: type, bytes: []const F) [4]F {
    var out: [4]F = undefined;
    for (0..4) |i| out[i] = bytes[2 * i].add(bytes[2 * i + 1].mul(q(F, 256)));
    return out;
}
fn limbs(comptime F: type, m: []const F, start: usize) [4]F {
    return m[start..][0..4].*;
}
fn shiftValue(comptime F: type, sigma: []const F) F {
    var s = F.zero();
    for (sigma[1..8], 1..) |v, j| s = s.add(v.mul(q(F, @intCast(j))));
    return s;
}
pub fn ioTuple(comptime F: type, id: F, direction: F, lane: usize, bytes: [8]F) [11]F {
    var out: [11]F = undefined;
    out[0] = id;
    out[1] = direction;
    out[2] = q(F, @intCast(lane));
    @memcpy(out[3..], &bytes);
    return out;
}
pub fn ecallTuple(comptime F: type, m: []const F) [19]F {
    const C = L.call;
    var out: [19]F = @splat(F.zero());
    out[0] = q(F, @intFromEnum(Decode.Opcode.ECALL));
    @memcpy(out[1..5], m[C.pointer..][0..4]);
    out[9] = q(F, @as(u16, @truncate(T.TAG)));
    out[10] = q(F, @as(u16, @truncate(T.TAG >> 16)));
    out[17] = m[C.epoch];
    out[18] = m[C.tick_low].add(m[C.tick_high].mul(q(F, 65536)));
    return out;
}
/// Call -> first permutation row: after clock, aligned message base, bytes and
/// words remaining, flags, shift and the first permutation's IO11 ID.
pub fn tokenTuple(comptime F: type, clock3: [3]F, base: [4]F, len: F, words: F, fin: F, fresh: F, shift: F, id: F) [19]F {
    var out: [19]F = @splat(F.zero());
    out[0] = q(F, T.TOKEN);
    @memcpy(out[1..4], &clock3);
    @memcpy(out[4..8], &base);
    out[8] = len;
    out[9] = words;
    out[10] = fin;
    out[11] = fresh;
    out[12] = shift;
    out[13] = id;
    return out;
}
pub fn callLen(comptime F: type, m: []const F) F {
    return m[L.call.len0].add(m[L.call.len1].mul(q(F, 65536)));
}
pub fn callPacket(comptime F: type, m: []const F, k: usize) [4]F {
    const C = L.call;
    return switch (k) {
        0 => limbs(F, m, C.state),
        1 => .{ shiftValue(F, m[C.shift..][0..8]).add(m[C.in_q0].mul(q(F, 8))), m[C.in_hi], m[C.in_hi + 1], m[C.in_hi + 2] },
        2 => .{ m[C.len0], m[C.len1], F.zero(), F.zero() },
        else => .{ m[C.fin].add(m[C.fresh].mul(q(F, 2))), F.zero(), F.zero(), F.zero() },
    };
}
pub fn callPacketAddress(comptime F: type, m: []const F, k: usize) [4]F {
    var a = limbs(F, m, L.call.pointer);
    for (0..k) |step| a = advance(F, a, m[L.call.pcarry + 3 * step ..][0..3], 8);
    return a;
}
pub fn callStateAddress(comptime F: type, m: []const F, lane: usize) [4]F {
    const base = limbs(F, m, L.call.state);
    if (lane == 0) return base;
    return advance(F, base, m[L.call.scarry + 3 * (lane - 1) ..][0..3], @intCast(8 * lane));
}
pub fn permSlotAddress(comptime F: type, m: []const F, j: usize) [4]F {
    const base = limbs(F, m, L.perm.base);
    if (j == 0) return base;
    return advance(F, base, m[L.perm.wcarry + 3 * (j - 1) ..][0..3], @intCast(8 * j));
}
fn afterClock(comptime F: type, m: []const F, kind: L.Kind) [3]F {
    const base: usize = if (kind == .call) L.call.epoch else L.perm.epoch;
    return m[base..][0..3].*;
}
fn ramPair(comptime F: type, ch: T.Challenges, address: [4]F, k: []const F, after: [3]F, before_value: [4]F, after_value: [4]F, readable: F, writable: F, weight: F) [2]Fraction(F) {
    const b = ch.ram.denominatorFor(F, ramTuple(F, address, k[L.clock.epoch], k[L.clock.low], k[L.clock.high], before_value, readable, writable));
    const a = ch.ram.denominatorFor(F, ramTuple(F, address, after[0], after[1], after[2], after_value, readable, writable));
    return .{ .{ .d = b, .w = weight, .relation = RAM }, .{ .d = a, .w = weight.neg(), .relation = RAM } };
}
fn r16(comptime F: type, ch: T.Challenges, value: F) Fraction(F) {
    return .{ .d = ch.range16.denominatorFor(F, value), .w = F.one(), .relation = RANGE16 };
}
fn r8(comptime F: type, ch: T.Challenges, value: F) Fraction(F) {
    return .{ .d = ch.range8.denominatorFor(F, value), .w = F.one(), .relation = RANGE8 };
}
fn io(comptime F: type, ch: T.Challenges, tuple: [11]F, weight: F) Fraction(F) {
    return .{ .d = E.denominatorFor(F, ch.io.offset, &ch.io.coefficients, &tuple, true), .w = weight, .relation = IO };
}
fn bytes8(comptime F: type, m: []const F, start: usize) [8]F {
    return m[start..][0..8].*;
}
/// IO11 input bytes of lane `l`: pre XOR msg = pre + msg - 2 (pre AND msg) for
/// rate lanes, pre for capacity lanes.
pub fn inputBytes(comptime F: type, m: []const F, lane: usize) [8]F {
    const P = L.perm;
    var out = bytes8(F, m, P.pre + 8 * lane);
    if (lane < T.RATE_LANES) for (&out, 0..) |*v, b| {
        const t = 8 * lane + b;
        v.* = v.add(m[P.msg + t]).sub(m[P.and_ + t].mul(q(F, 2)));
    };
    return out;
}
pub fn permId(comptime F: type, f: []const F, first_id: u32) F {
    return q(F, first_id).add(f[0]);
}
pub fn fractions(comptime F: type, comptime kind: L.Kind, f: []const F, m: []const F, first_id: u32, ch: T.Challenges) [L.fractionCount(kind)]Fraction(F) {
    var out: [L.fractionCount(kind)]Fraction(F) = undefined;
    var at: usize = 0;
    const one = F.one();
    const after = afterClock(F, m, kind);
    switch (kind) {
        .call => {
            const C = L.call;
            const a = m[C.active];
            const base = [4]F{ m[C.in_q0].mul(q(F, 8)), m[C.in_hi], m[C.in_hi + 1], m[C.in_hi + 2] };
            out[0] = .{ .d = ch.owner.denominatorFor(F, ecallTuple(F, m)), .w = a.neg(), .relation = OWNER };
            out[1] = .{ .d = ch.owner.denominatorFor(F, tokenTuple(F, after, base, callLen(F, m), m[C.words], m[C.fin], m[C.fresh], shiftValue(F, m[C.shift..][0..8]), m[C.id])), .w = a, .relation = OWNER };
            at = 2;
            for (0..4) |k| {
                const v = callPacket(F, m, k);
                const pair = ramPair(F, ch, callPacketAddress(F, m, k), m[C.pclock + L.CLOCK * k ..][0..L.CLOCK], after, v, v, one, m[C.pwritable + k], a);
                out[at..][0..2].* = pair;
                at += 2;
            }
            for (0..T.LANES) |l| {
                const pair = ramPair(F, ch, callStateAddress(F, m, l), m[C.sclock + L.CLOCK * l ..][0..L.CLOCK], after, limbsOfBytes(F, m[C.old + 8 * l ..][0..8]), limbsOfBytes(F, m[C.new + 8 * l ..][0..8]), one, one, a);
                out[at..][0..2].* = pair;
                at += 2;
            }
            for (0..T.LANES) |l| {
                out[at] = io(F, ch, ioTuple(F, m[C.id], q(F, T.LINK), l, bytes8(F, m, C.old + 8 * l)), a.sub(m[C.fresh]));
                at += 1;
            }
            const last_id = m[C.id].add(m[C.q]).add(m[C.fin]).sub(one);
            for (0..T.LANES) |l| {
                out[at] = io(F, ch, ioTuple(F, last_id, one, l, bytes8(F, m, C.new + 8 * l)), a.neg());
                at += 1;
            }
            inline for (.{ m[C.tick_low], m[C.in_q0], m[C.q], m[C.len1].mul(q(F, 4096)) }) |v| {
                out[at] = r16(F, ch, v);
                at += 1;
            }
            for (0..4) |k| {
                out[at] = r16(F, ch, m[C.pclock + L.CLOCK * k + L.clock.gap16]);
                at += 1;
            }
            for (0..T.LANES) |l| {
                out[at] = r16(F, ch, m[C.sclock + L.CLOCK * l + L.clock.gap16]);
                at += 1;
            }
            inline for (.{ m[C.tick_high], m[C.r], m[C.r].add(q(F, 120)), m[C.e], m[C.e].add(q(F, 248)) }) |v| {
                out[at] = r8(F, ch, v);
                at += 1;
            }
            for (0..4) |k| {
                out[at] = r8(F, ch, m[C.pclock + L.CLOCK * k + L.clock.gap8]);
                at += 1;
            }
            for (0..T.LANES) |l| {
                out[at] = r8(F, ch, m[C.sclock + L.CLOCK * l + L.clock.gap8]);
                at += 1;
            }
        },
        .perm => {
            const P = L.perm;
            const a = m[P.active];
            const first = m[P.first];
            const id = permId(F, f, first_id);
            out[0] = .{ .d = ch.owner.denominatorFor(F, tokenTuple(F, after, limbs(F, m, P.base), m[P.rb], m[P.wr], m[P.fin], m[P.freshfirst], shiftValue(F, m[P.shift..][0..8]), id)), .w = first.neg(), .relation = OWNER };
            at = 1;
            for (0..T.LANES) |l| {
                out[at] = io(F, ch, ioTuple(F, id, F.zero(), l, inputBytes(F, m, l)), a.neg());
                at += 1;
            }
            // First row: the call's link (direction LINK, same ID); otherwise
            // the previous permutation's output (direction 1, ID - 1).
            const prev_id = id.sub(one).add(first);
            const prev_dir = one.add(first);
            for (0..T.LANES) |l| {
                out[at] = io(F, ch, ioTuple(F, prev_id, prev_dir, l, bytes8(F, m, P.pre + 8 * l)), a.sub(m[P.freshfirst]).neg());
                at += 1;
            }
            for (0..T.RATE) |t| {
                const tuple = [3]F{ m[P.pre + t], m[P.msg + t], m[P.and_ + t] };
                out[at] = .{ .d = E.denominatorFor(F, ch.and_.offset, ch.and_.coefficients[0..3], &tuple, true), .w = one, .relation = AND };
                at += 1;
            }
            for (0..T.SLOTS) |j| {
                const v = limbsOfBytes(F, m[P.window + 8 * j ..][0..8]);
                const pair = ramPair(F, ch, permSlotAddress(F, m, j), m[P.wclock + L.CLOCK * j ..][0..L.CLOCK], after, v, v, one, m[P.wwritable + j], m[P.read + j]);
                out[at..][0..2].* = pair;
                at += 2;
            }
            for (0..T.SLOTS) |j| {
                out[at] = r16(F, ch, m[P.wclock + L.CLOCK * j + L.clock.gap16]);
                at += 1;
            }
            for (0..T.SLOTS) |j| {
                out[at] = r8(F, ch, m[P.wclock + L.CLOCK * j + L.clock.gap8]);
                at += 1;
            }
            for (0..T.SLOTS) |j| for (0..4) |i| {
                out[at] = r8(F, ch, m[P.window + 8 * j + 2 * i + 1]);
                at += 1;
            };
        },
    }
    std.debug.assert(at == out.len);
    return out;
}
comptime {
    // The first permutation row consumes direction 1 + first = LINK.
    std.debug.assert(T.LINK == 2);
}

/// Strict lexicographic RAM predecessor `(be, bt) < (E, T)` as an integer fact,
/// gated by the access weight. Same epoch:
/// bl + 2^16 bh + g16 + 2^16 g8 + 1 = TL + 2^16 TH; cross epoch: be + g16 + 1 = E.
fn clockConstraints(comptime F: type, k: []const F, after: [3]F, gate: F, out: *E.SinkFor(F)) void {
    const one = F.one();
    const big = q(F, 65536);
    const same = k[L.clock.same];
    E.booleanFor(F, out, same);
    out.emit(gate.mul(same).mul(k[L.clock.epoch].sub(after[0])));
    const lhs = k[L.clock.low].add(k[L.clock.high].mul(big)).add(k[L.clock.gap16]).add(k[L.clock.gap8].mul(big)).add(one);
    out.emit(gate.mul(same).mul(lhs.sub(after[1]).sub(after[2].mul(big))));
    out.emit(gate.mul(one.sub(same)).mul(k[L.clock.epoch].add(k[L.clock.gap16]).add(one).sub(after[0])));
}
/// Active rows are exactly the public prefix `[0, rows)` and the last row is
/// padding, so the wrapped predecessor of row 0 is inactive.
fn countConstraints(comptime F: type, f: []const F, active: F, previous: F, rows: u32, out: *E.SinkFor(F)) void {
    const one = F.one();
    const first = f[1];
    out.emit(first.mul(active.sub(q(F, @intFromBool(rows != 0)))));
    out.emit(f[2].mul(active));
    out.emit(one.sub(first).mul(active).mul(one.sub(previous)));
    out.emit(one.sub(first).mul(previous.sub(active)).mul(f[0].sub(q(F, rows))));
}
fn sum(comptime F: type, values: []const F) F {
    var s = F.zero();
    for (values) |v| s = s.add(v);
    return s;
}
fn emitCall(comptime F: type, f: []const F, m: []const F, pm: []const F, rows: u32, out: *E.SinkFor(F)) void {
    const C = L.call;
    const one = F.one();
    const a = m[C.active];
    E.booleanFor(F, out, a);
    out.emit(m[C.fresh].mul(one.sub(a)));
    for (m[C.shift..][0..8]) |v| E.booleanFor(F, out, v);
    out.emit(sum(F, m[C.shift..][0..8]).sub(a));
    for (m[C.pcarry..][0..9]) |v| E.booleanFor(F, out, v);
    for ([_]usize{ C.fin, C.fresh, C.zero }) |c| E.booleanFor(F, out, m[c]);
    for (m[C.scarry..][0..72]) |v| E.booleanFor(F, out, v);
    for (m[C.pwritable..][0..4]) |v| E.booleanFor(F, out, v);
    countConstraints(F, f, a, pm[C.active], rows, out);
    const after = afterClock(F, m, .call);
    for (0..4) |k| clockConstraints(F, m[C.pclock + L.CLOCK * k ..][0..L.CLOCK], after, a, out);
    for (0..T.LANES) |l| clockConstraints(F, m[C.sclock + L.CLOCK * l ..][0..L.CLOCK], after, a, out);
    const len = callLen(F, m);
    // len = 136 q + r with r < 136 and q < 2^16 (fractions): exact integers.
    out.emit(m[C.q].mul(q(F, T.RATE)).add(m[C.r]).sub(len));
    // Without finalize the message is whole blocks.
    out.emit(one.sub(m[C.fin]).mul(m[C.r]));
    // zero = [len == 0].
    out.emit(m[C.zero].mul(len));
    out.emit(a.mul(len.mul(m[C.zinv]).sub(one).add(m[C.zero])));
    // words = (shift + len + 7 - e) / 8 with e < 8, or 0 for an empty message.
    const span = shiftValue(F, m[C.shift..][0..8]).add(len).add(q(F, 7)).sub(m[C.e]);
    out.emit(a.mul(m[C.words].mul(q(F, 8)).sub(one.sub(m[C.zero]).mul(span))));
}
fn emitPerm(comptime F: type, f: []const F, m: []const F, pm: []const F, rows: u32, out: *E.SinkFor(F)) void {
    const P = L.perm;
    const one = F.one();
    const a = m[P.active];
    const first = m[P.first];
    const last = m[P.last];
    const c = a.sub(first);
    for ([_]usize{ P.active, P.first, P.last, P.lastfin, P.freshfirst, P.fin }) |col| E.booleanFor(F, out, m[col]);
    for (m[P.shift..][0..8]) |v| E.booleanFor(F, out, v);
    out.emit(sum(F, m[P.shift..][0..8]).sub(a));
    for (m[P.bcarry..][0..3]) |v| E.booleanFor(F, out, v);
    for (m[P.mask..][0..T.RATE]) |v| E.booleanFor(F, out, v);
    for (m[P.read..][0..T.SLOTS]) |v| E.booleanFor(F, out, v);
    for (m[P.wcarry..][0..51]) |v| E.booleanFor(F, out, v);
    for (m[P.wwritable..][0..T.SLOTS]) |v| E.booleanFor(F, out, v);
    countConstraints(F, f, a, pm[P.active], rows, out);
    out.emit(first.mul(one.sub(a)));
    out.emit(last.mul(one.sub(a)));
    out.emit(m[P.freshfirst].mul(one.sub(first)));
    out.emit(m[P.lastfin].sub(last.mul(m[P.fin])));
    // Runs: a continuation follows an active row; an active non-last row is
    // followed by a continuation; a last row is followed by a first or padding.
    out.emit(c.mul(one.sub(pm[P.active])));
    out.emit(pm[P.active].mul(one.sub(pm[P.last])).mul(one.sub(c)));
    out.emit(pm[P.last].mul(c));
    for ([_]usize{ P.epoch, P.tick_low, P.tick_high, P.fin }) |col| out.emit(c.mul(m[col].sub(pm[col])));
    for (0..8) |i| out.emit(c.mul(m[P.shift + i].sub(pm[P.shift + i])));
    const next = advance(F, limbs(F, pm, P.base), m[P.bcarry..][0..3], T.RATE);
    for (0..4) |i| out.emit(c.mul(m[P.base + i].sub(next[i])));
    for (m[P.bcarry..][0..3]) |v| out.emit(one.sub(c).mul(v));
    // Byte and word counters: rb drops by 136 per block, wr by the words the
    // previous row read; the last row absorbs exactly rb bytes, reads wr words.
    const reads = sum(F, m[P.read..][0..T.SLOTS]);
    out.emit(c.mul(m[P.rb].sub(pm[P.rb]).add(q(F, T.RATE))));
    out.emit(c.mul(m[P.wr].sub(pm[P.wr]).add(sum(F, pm[P.read..][0..T.SLOTS]))));
    out.emit(last.mul(m[P.wr].sub(reads)));
    out.emit(last.mul(sum(F, m[P.mask..][0..T.RATE]).sub(m[P.rb])));
    // Thermometer mask: a full block except on the finalizing last row.
    for (0..T.RATE - 1) |t| out.emit(m[P.mask + t + 1].mul(one.sub(m[P.mask + t])));
    out.emit(a.mul(one.sub(m[P.lastfin])).mul(one.sub(m[P.mask + T.RATE - 1])));
    out.emit(m[P.lastfin].mul(m[P.mask + T.RATE - 1]));
    out.emit(one.sub(a).mul(m[P.mask]));
    // msg_t = mask_t * data_t + pad_t; data_t is window byte t + shift.
    for (0..T.RATE) |t| {
        var data = F.zero();
        for (0..8) |s| data = data.add(m[P.shift + s].mul(m[P.window + t + s]));
        const prev = if (t == 0) a else m[P.mask + t - 1];
        var pad = prev.sub(m[P.mask + t]);
        if (t == T.RATE - 1) pad = pad.add(m[P.lastfin].mul(q(F, 0x80)));
        out.emit(m[P.msg + t].sub(m[P.mask + t].mul(data)).sub(pad));
    }
    // Slot 0 is word 17k: read on the first row, else the previous slot 17.
    for (0..8) |b| out.emit(c.mul(m[P.window + b].sub(pm[P.window + 8 * 17 + b])));
    // Reads are a prefix of the message words, row after row.
    out.emit(m[P.read].mul(one.sub(first)));
    for (1..T.SLOTS - 1) |j| out.emit(m[P.read + j + 1].mul(one.sub(m[P.read + j])));
    out.emit(m[P.read + 1].mul(one.sub(first.mul(m[P.read])).sub(c.mul(pm[P.read + T.SLOTS - 1]))));
    const after = afterClock(F, m, .perm);
    for (0..T.SLOTS) |j| clockConstraints(F, m[P.wclock + L.CLOCK * j ..][0..L.CLOCK], after, m[P.read + j], out);
    // A fresh call starts from the zero state.
    for (m[P.pre..][0..200]) |v| out.emit(m[P.freshfirst].mul(v));
}
pub fn emitFor(comptime F: type, comptime kind: L.Kind, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, rows: u32, first_id: u32, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    switch (kind) {
        .call => emitCall(F, f, m, pm, rows, out),
        .perm => emitPerm(F, f, m, pm, rows, out),
    }
    emitFractions(F, kind, f, m, i, pi, first_id, claims, ch, out);
}
pub fn emitFractions(comptime F: type, comptime kind: L.Kind, f: []const F, m: []const F, i: []const F, pi: []const F, first_id: u32, claims: T.Claims, ch: T.Challenges, out: *E.SinkFor(F)) void {
    const Sec = E.SecureFor(F);
    const list = fractions(F, kind, f, m, first_id, ch);
    var sums: [T.RELATIONS]Sec = @splat(Sec.zero());
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
    for (0..T.RELATIONS) |r| {
        const at = L.prefix(kind, r);
        S.prefix(F, sums[r], E.secureFor(F, i, at), E.secureFor(F, pi, at), f[1], f[2], values[r], out);
    }
}
