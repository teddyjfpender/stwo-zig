//! Narrow call descriptor. State RAM/IO words move to state_word rows; packet
//! reads and the exact existing CPU/first-permutation OWNER tuples remain here.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../../evaluation.zig");
const Old = @import("../equations.zig");
const L = @import("../layout.zig");
const T = @import("../types.zig");
const State = @import("state_word.zig");
const M = core.fields.m31.M31;
pub const MAIN = 74;
pub const WORD_LOW = 72;
pub const WORD_HIGH = 73;
pub const FIXED = 3;
pub const CONSTRAINTS = 54;
pub const LOCAL_QUERIES = 2 + 25 + 9 + 11;
pub const LOCAL_PADDED = 64;
pub const OM31_INTER = 56; // binding16 +RAM4pairs+prefix40
fn q(comptime F: type, n: u32) F {
    return E.qFor(F, n);
}
fn sum(comptime F: type, v: []const F) F {
    var out = F.zero();
    for (v) |x| out = out.add(x);
    return out;
}
fn shift(comptime F: type, m: *const [MAIN]F) F {
    var out = F.zero();
    for (m[L.call.shift..][0..8], 0..) |x, i| out = out.add(x.mul(q(F, @intCast(i))));
    return out;
}
pub fn row(call: T.Call, words: []const T.State, first_id: u32) ![MAIN]M {
    try T.validateCall(call, words);
    if (first_id == 0 or (try std.math.add(u64, first_id, call.permutations() - 1)) >= core.fields.m31.Modulus) return error.InvalidSerializedStateRow;
    const full = @import("../source.zig").callRow(call, first_id, @splat(0));
    var out: [MAIN]M = undefined;
    @memcpy(out[0..72], full[0..72]);
    out[WORD_LOW] = M.fromCanonical(@as(u16, @truncate(call.p().words())));
    out[WORD_HIGH] = M.fromCanonical(@intCast(call.p().words() >> 16));
    return out;
}
/// Each lane is an independent source-owned unit token, not an unconstrained
/// producer-declared multiplicity. Complete tuple equality binds all metadata.
pub fn emitStateTokens(comptime F: type, m: *const [MAIN]F, sink: anytype) void {
    var word: [State.MAIN]F = @splat(F.zero());
    const C = L.call;
    word[State.c.active] = m[C.active];
    @memcpy(word[State.c.epoch..][0..3], m[C.epoch..][0..3]);
    @memcpy(word[State.c.pointer..][0..4], m[C.pointer..][0..4]);
    @memcpy(word[State.c.state..][0..4], m[C.state..][0..4]);
    word[State.c.first_id] = m[C.id];
    word[State.c.last_id] = m[C.id].add(m[C.q]).add(m[C.fin]).sub(F.one());
    word[State.c.fin] = m[C.fin];
    word[State.c.fresh] = m[C.fresh];
    for (0..25) |lane| {
        word[State.c.lane] = q(F, @intCast(lane));
        sink.emit(Old.OWNER, State.token(F, &word), m[C.active]);
    }
}
pub fn emitRaw(comptime F: type, m: *const [MAIN]F, sink: anytype) void {
    const C = L.call;
    const a = m[C.active];
    const one = F.one();
    const after = m[C.epoch..][0..3].*;
    const base = [4]F{ m[C.in_q0].mul(q(F, 8)), m[C.in_hi], m[C.in_hi + 1], m[C.in_hi + 2] };
    sink.emit(Old.OWNER, Old.ecallTuple(F, m), a.neg());
    sink.emit(Old.OWNER, Old.tokenTuple(F, after, base, Old.callLen(F, m), m[C.words], m[C.fin], m[C.fresh], shift(F, m), m[C.id]), a);
    emitStateTokens(F, m, sink);
    for (0..4) |k| {
        const before = m[C.pclock + L.CLOCK * k ..][0..L.CLOCK];
        const address = Old.callPacketAddress(F, m, k);
        const value = Old.callPacket(F, m, k);
        sink.emit(Old.RAM, Old.ramTuple(F, address, before[0], before[1], before[2], value, one, m[C.pwritable + k]), a);
        sink.emit(Old.RAM, Old.ramTuple(F, address, after[0], after[1], after[2], value, one, m[C.pwritable + k]), a.neg());
    }
    inline for (.{ m[C.tick_low], m[C.in_q0], m[C.q], m[C.len1].mul(q(F, 4096)) }) |v| sink.emit(Old.RANGE16, [1]F{v}, one);
    for (0..4) |k| sink.emit(Old.RANGE16, [1]F{m[C.pclock + L.CLOCK * k + L.clock.gap16]}, one);
    inline for (.{ m[C.tick_high], m[C.r], m[C.r].add(q(F, 120)), m[C.e], m[C.e].add(q(F, 248)) }) |v| sink.emit(Old.RANGE8, [1]F{v}, one);
    for (0..4) |k| sink.emit(Old.RANGE8, [1]F{m[C.pclock + L.CLOCK * k + L.clock.gap8]}, one);
    sink.emit(Old.RANGE16, [1]F{m[WORD_LOW]}, one);
    sink.emit(Old.RANGE8, [1]F{m[WORD_HIGH]}, one);
    sink.emit(Old.RANGE8, [1]F{m[WORD_HIGH].mul(q(F, 64))}, one);
}
pub fn emitMain(comptime F: type, f: *const [3]F, m: *const [MAIN]F, previous_active: F, rows: F, nonempty: F, sink: anytype) void {
    const C = L.call;
    const one = F.one();
    const a = m[C.active];
    for ([_]usize{ C.active, C.fin, C.fresh, C.zero }) |col| sink.emit(m[col].mul(m[col].sub(one)));
    sink.emit(m[C.fresh].mul(one.sub(a)));
    for (m[C.shift..][0..8]) |v| sink.emit(v.mul(v.sub(one)));
    sink.emit(sum(F, m[C.shift..][0..8]).sub(a));
    for (m[C.pcarry..][0..9]) |v| sink.emit(v.mul(v.sub(one)));
    for (m[C.pwritable..][0..4]) |v| sink.emit(v.mul(v.sub(one)));
    sink.emit(f[1].mul(a.sub(nonempty)));
    sink.emit(f[2].mul(a));
    sink.emit(one.sub(f[1]).mul(a).mul(one.sub(previous_active)));
    sink.emit(one.sub(f[1]).mul(previous_active.sub(a)).mul(f[0].sub(rows)));
    for (0..4) |k| {
        const before = m[C.pclock + L.CLOCK * k ..][0..L.CLOCK];
        const same = before[L.clock.same];
        sink.emit(same.mul(same.sub(one)));
        sink.emit(a.mul(same).mul(before[0].sub(m[C.epoch])));
        const lhs = before[1].add(before[2].mul(q(F, 65536))).add(before[4]).add(before[5].mul(q(F, 65536))).add(one);
        sink.emit(a.mul(same).mul(lhs.sub(m[C.tick_low]).sub(m[C.tick_high].mul(q(F, 65536)))));
        sink.emit(a.mul(one.sub(same)).mul(before[0].add(before[4]).add(one).sub(m[C.epoch])));
    }
    // Two range-checked limbs keep the covering-word division an exact integer
    // statement, independent of the future permutation/reader component.
    sink.emit(m[C.words].sub(m[WORD_LOW]).sub(m[WORD_HIGH].mul(q(F, 65536))));
    sink.emit(a.mul(one.sub(m[C.fin])).mul(m[C.zero]));
    const len = Old.callLen(F, m);
    sink.emit(m[C.q].mul(q(F, T.RATE)).add(m[C.r]).sub(len));
    sink.emit(one.sub(m[C.fin]).mul(m[C.r]));
    sink.emit(m[C.zero].mul(len));
    sink.emit(a.mul(len.mul(m[C.zinv]).sub(one).add(m[C.zero])));
    const span = shift(F, m).add(len).add(q(F, 7)).sub(m[C.e]);
    sink.emit(a.mul(m[C.words].mul(q(F, 8)).sub(one.sub(m[C.zero]).mul(span))));
}
