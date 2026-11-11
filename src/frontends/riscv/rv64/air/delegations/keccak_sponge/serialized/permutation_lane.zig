//! Closed absorption source: one of25 complete Keccak lanes per row. Header
//! supplies the two endpoint chain tokens; message_word supplies full WINDOW
//! tuples. No production admission until both sources and physical closure pass.
const core = @import("stwo_core");
const E = @import("../../../evaluation.zig");
const Old = @import("../equations.zig");
const L = @import("../layout.zig");
const M = core.fields.m31.M31;
pub const MAIN = 67;
pub const FIXED = 3;
pub const LOCAL_QUERIES = 25;
pub const LOCAL_PADDED = 32;
pub const OM31_INTER = 32; // modeled local binding plus global relation columns
pub const TOKEN_CHAIN: u32 = 0x4b53_0003;
pub const TOKEN_WINDOW: u32 = 0x4b53_0004;
pub const c = struct {
    pub const active = 0;
    pub const lane = 1;
    pub const rate = 2;
    pub const id = 3;
    pub const first = 4;
    pub const lastfin = 5;
    pub const freshfirst = 6;
    pub const shift = 7; //8 one-hot
    pub const remaining = 15;
    pub const previous_mask = 16;
    pub const pre = 17; //8 bytes
    pub const msg = 25;
    pub const and_ = 33;
    pub const mask = 41;
    pub const window = 49; //two adjacent words,16 bytes
    pub const next_remaining = 65;
    pub const shift_value = 66;
};
fn q(comptime F: type, n: u32) F {
    return E.qFor(F, n);
}
fn sum(comptime F: type, v: []const F) F {
    var s = F.zero();
    for (v) |x| s = s.add(x);
    return s;
}
pub fn row(old: *const [L.perm.MAIN]M, id: u32, lane: u8) ![MAIN]M {
    if (lane >= 25 or id == 0 or id >= core.fields.m31.Modulus) return error.InvalidSerializedLane;
    const P = L.perm;
    var out: [MAIN]M = @splat(M.zero());
    out[c.active] = old[P.active];
    out[c.lane] = M.fromCanonical(lane);
    out[c.rate] = M.fromCanonical(@intFromBool(lane < 17));
    out[c.id] = M.fromCanonical(id);
    out[c.first] = old[P.first];
    out[c.lastfin] = old[P.lastfin];
    out[c.freshfirst] = old[P.freshfirst];
    @memcpy(out[c.shift..][0..8], old[P.shift..][0..8]);
    for (old[P.shift..][0..8], 0..) |v, i| out[c.shift_value] = out[c.shift_value].add(v.mul(M.fromCanonical(@intCast(i))));
    @memcpy(out[c.pre..][0..8], old[P.pre + 8 * @as(usize, lane) ..][0..8]);
    const upto: usize = @min(@as(usize, lane) * 8, 136);
    out[c.remaining] = sum(M, old[P.mask + upto ..][0 .. 136 - upto]);
    out[c.previous_mask] = if (lane == 0) old[P.active] else old[P.mask + upto - 1];
    if (lane < 17) {
        @memcpy(out[c.msg..][0..8], old[P.msg + upto ..][0..8]);
        @memcpy(out[c.and_..][0..8], old[P.and_ + upto ..][0..8]);
        @memcpy(out[c.mask..][0..8], old[P.mask + upto ..][0..8]);
        @memcpy(out[c.window..][0..16], old[P.window + upto ..][0..16]);
    }
    out[c.next_remaining] = out[c.remaining].sub(sum(M, out[c.mask..][0..8]));
    return out;
}
pub fn chain(comptime F: type, m: *const [MAIN]F, next: bool) [19]F {
    var t: [19]F = @splat(F.zero());
    t[0] = q(F, TOKEN_CHAIN);
    t[1] = m[c.id];
    t[2] = m[c.first];
    t[3] = m[c.lastfin];
    t[4] = m[c.freshfirst];
    t[5] = m[c.shift_value];
    t[6] = m[c.lane].add(if (next) F.one() else F.zero());
    t[7] = m[if (next) c.next_remaining else c.remaining];
    t[8] = if (next) m[c.rate].mul(m[c.mask + 7]).add(F.one().sub(m[c.rate]).mul(m[c.previous_mask])) else m[c.previous_mask];
    return t;
}
pub fn window(comptime F: type, id: F, slot: F, value: [8]F) [19]F {
    var t: [19]F = @splat(F.zero());
    t[0] = q(F, TOKEN_WINDOW);
    t[1] = id;
    t[2] = slot;
    @memcpy(t[3..11], &value);
    return t;
}
pub fn emitRaw(comptime F: type, m: *const [MAIN]F, sink: anytype) void {
    const a = m[c.active];
    const rate = m[c.rate];
    sink.emit(Old.OWNER, chain(F, m, false), a.neg());
    sink.emit(Old.OWNER, chain(F, m, true), a);
    sink.emit(Old.OWNER, window(F, m[c.id], m[c.lane], m[c.window..][0..8].*), rate.neg());
    sink.emit(Old.OWNER, window(F, m[c.id], m[c.lane].add(F.one()), m[c.window + 8 ..][0..8].*), rate.neg());
    var input: [11]F = undefined;
    input[0] = m[c.id];
    input[1] = F.zero();
    input[2] = m[c.lane];
    for (input[3..], 0..) |*v, b| v.* = m[c.pre + b].add(m[c.msg + b]).sub(m[c.and_ + b].mul(q(F, 2)));
    sink.emit(Old.IO, input, a.neg());
    input[0] = m[c.id].sub(F.one()).add(m[c.first]);
    input[1] = F.one().add(m[c.first]);
    @memcpy(input[3..], m[c.pre..][0..8]);
    sink.emit(Old.IO, input, a.sub(m[c.freshfirst]).neg());
    for (0..8) |b| {
        sink.emit(Old.AND, [3]F{ m[c.pre + b], m[c.msg + b], m[c.and_ + b] }, rate);
        sink.emit(Old.RANGE8, [1]F{m[c.pre + b]}, F.one());
    }
    for ([_]usize{ c.lane, c.remaining, c.next_remaining }) |col| sink.emit(Old.RANGE8, [1]F{m[col]}, F.one());
    sink.emit(Old.RANGE8, [1]F{m[c.lane].add(q(F, 239))}, rate);
    sink.emit(Old.RANGE8, [1]F{m[c.lane].sub(q(F, 17)).mul(q(F, 32))}, a.sub(rate));
}
pub fn emitMain(comptime F: type, fixed: *const [3]F, m: *const [MAIN]F, sink: anytype) void {
    const a = m[c.active];
    const rate = m[c.rate];
    const one = F.one();
    sink.emit(a.mul(m[c.lane].sub(fixed[0])));
    sink.emit(rate.sub(a.mul(fixed[1])));
    for ([_]usize{ c.active, c.rate, c.first, c.lastfin, c.freshfirst, c.previous_mask }) |col| sink.emit(m[col].mul(m[col].sub(one)));
    sink.emit(rate.mul(one.sub(a)));
    sink.emit(m[c.first].mul(one.sub(a)));
    sink.emit(m[c.lastfin].mul(one.sub(a)));
    sink.emit(m[c.freshfirst].mul(one.sub(m[c.first])));
    var sv = F.zero();
    for (m[c.shift..][0..8], 0..) |v, i| {
        sink.emit(v.mul(v.sub(one)));
        sv = sv.add(v.mul(q(F, @intCast(i))));
    }
    sink.emit(sum(F, m[c.shift..][0..8]).sub(a));
    sink.emit(sv.sub(m[c.shift_value]));
    sink.emit(m[c.next_remaining].sub(m[c.remaining]).add(sum(F, m[c.mask..][0..8])));
    for (0..8) |b| {
        const mask = m[c.mask + b];
        const previous = if (b == 0) m[c.previous_mask] else m[c.mask + b - 1];
        sink.emit(mask.mul(mask.sub(one)));
        sink.emit(mask.mul(one.sub(previous)));
        sink.emit(one.sub(rate).mul(mask));
        sink.emit(m[c.freshfirst].mul(m[c.pre + b]));
        var data = F.zero();
        for (0..8) |s| data = data.add(m[c.shift + s].mul(m[c.window + b + s]));
        var pad = rate.mul(previous.sub(mask));
        if (b == 7) pad = pad.add(m[c.lastfin].mul(fixed[2]).mul(q(F, 128)));
        sink.emit(m[c.msg + b].sub(mask.mul(data)).sub(pad));
        sink.emit(one.sub(rate).mul(m[c.msg + b]));
        sink.emit(one.sub(rate).mul(m[c.and_ + b]));
    }
}
