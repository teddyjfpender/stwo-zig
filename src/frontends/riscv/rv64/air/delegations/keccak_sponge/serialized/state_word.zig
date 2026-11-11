//! Closed source prototype: one complete sponge state RAM word per row.
//! The descriptor must emit all25 StateToken tuples; no execution admission is
//! granted by this component alone. Existing RAM14/IO11 encodings are reused.
const std = @import("std");
const core = @import("stwo_core");
const Legacy = @import("../equations.zig");
const T = @import("../types.zig");
const E = @import("../../../evaluation.zig");
const M = core.fields.m31.M31;
pub const MAIN = 46;
pub const FIXED = 3;
pub const CONSTRAINTS = 20;
pub const LOCAL_QUERIES = 1 + 17 + 19;
pub const LOCAL_PADDED = 64;
pub const GLOBAL_RAM_FRACTIONS = 2;
pub const GLOBAL_IO_FRACTIONS = 2;
pub const OM31_INTER = 48; // binding16 +RAM(pair+prefix)16 +IO(pair+prefix)16
pub const TOKEN_STATE: u32 = 0x4b53_0002;
pub const c = struct {
    pub const active = 0;
    pub const lane = 1;
    pub const epoch = 2;
    pub const tick_low = 3;
    pub const tick_high = 4;
    pub const pointer = 5;
    pub const state = 9;
    pub const first_id = 13;
    pub const last_id = 14;
    pub const fin = 15;
    pub const fresh = 16;
    pub const address = 17;
    pub const carry = 21;
    pub const clock = 24;
    pub const old = 30;
    pub const new = 38;
};
pub const RANGE16 = [_]usize{ c.epoch, c.tick_low, c.pointer, c.pointer + 1, c.pointer + 2, c.pointer + 3, c.state, c.state + 1, c.state + 2, c.state + 3, c.address, c.address + 1, c.address + 2, c.address + 3, c.clock, c.clock + 1, c.clock + 4 };
pub const RANGE8 = [_]usize{ c.tick_high, c.clock + 2, c.clock + 5, c.old, c.old + 1, c.old + 2, c.old + 3, c.old + 4, c.old + 5, c.old + 6, c.old + 7, c.new, c.new + 1, c.new + 2, c.new + 3, c.new + 4, c.new + 5, c.new + 6, c.new + 7 };
fn q(comptime F: type, v: u32) F {
    return E.qFor(F, v);
}
fn word(out: []M, v: u64) void {
    for (out, 0..) |*x, i| x.* = M.fromCanonical(@as(u16, @truncate(v >> @as(u6, @intCast(16 * i)))));
}
fn bytes(out: []M, v: u64) void {
    for (out, 0..) |*x, i| x.* = M.fromCanonical(@as(u8, @truncate(v >> @as(u6, @intCast(8 * i)))));
}
pub fn row(call: T.Call, first_id: u32, last_out: [25]u64, lane: u8) ![MAIN]M {
    if (lane >= 25 or first_id == 0 or call.epoch == 0 or call.tick == 0) return error.InvalidSerializedStateRow;
    try T.Native.validatePacket(call.pointer, call.p());
    const last = try std.math.add(u64, first_id, call.permutations() - 1);
    if (last >= core.fields.m31.Modulus) return error.InvalidSerializedStateRow;
    const before = call.state[lane];
    if (before.rights != 3 or before.epoch > call.epoch or (before.epoch == call.epoch and before.tick >= call.tick)) return error.InvalidSerializedStatePredecessor;
    var out: [MAIN]M = @splat(M.zero());
    out[c.active] = M.one();
    out[c.lane] = M.fromCanonical(lane);
    out[c.epoch] = M.fromCanonical(call.epoch);
    out[c.tick_low] = M.fromCanonical(@as(u16, @truncate(call.tick)));
    out[c.tick_high] = M.fromCanonical(call.tick >> 16);
    word(out[c.pointer..][0..4], call.pointer);
    word(out[c.state..][0..4], call.p().state);
    out[c.first_id] = M.fromCanonical(first_id);
    out[c.last_id] = M.fromCanonical(@intCast(last));
    out[c.fin] = M.fromCanonical(@intFromBool(call.p().finalize()));
    out[c.fresh] = M.fromCanonical(@intFromBool(call.p().fresh()));
    word(out[c.address..][0..4], try std.math.add(u64, call.p().state, 8 * @as(u64, lane)));
    var carry: u32 = 8 * @as(u32, lane);
    for (0..3) |i| {
        const limb: u32 = @as(u16, @truncate(call.p().state >> @as(u6, @intCast(16 * i))));
        carry = (limb + carry) >> 16;
        out[c.carry + i] = M.fromCanonical(carry);
    }
    out[c.clock] = M.fromCanonical(before.epoch);
    out[c.clock + 1] = M.fromCanonical(@as(u16, @truncate(before.tick)));
    out[c.clock + 2] = M.fromCanonical(before.tick >> 16);
    if (before.epoch == call.epoch) {
        const gap = call.tick - before.tick - 1;
        out[c.clock + 3] = M.one();
        out[c.clock + 4] = M.fromCanonical(@as(u16, @truncate(gap)));
        out[c.clock + 5] = M.fromCanonical(gap >> 16);
    } else out[c.clock + 4] = M.fromCanonical(call.epoch - before.epoch - 1);
    bytes(out[c.old..][0..8], before.value);
    bytes(out[c.new..][0..8], last_out[lane]);
    return out;
}
/// The descriptor produces exactly one token for each lane0..24. All metadata,
/// full64-bit pointers and both IDs are authenticated; no digest projection.
pub fn token(comptime F: type, m: *const [MAIN]F) [19]F {
    var out: [19]F = @splat(F.zero());
    out[0] = q(F, TOKEN_STATE);
    @memcpy(out[1..4], m[c.epoch..][0..3]);
    @memcpy(out[4..8], m[c.pointer..][0..4]);
    @memcpy(out[8..12], m[c.state..][0..4]);
    out[12] = m[c.first_id];
    out[13] = m[c.last_id];
    out[14] = m[c.fin];
    out[15] = m[c.fresh];
    out[16] = m[c.lane];
    return out;
}
pub fn emitRaw(comptime F: type, m: *const [MAIN]F, sink: anytype) void {
    const a = m[c.active];
    const one = F.one();
    const address = m[c.address..][0..4].*;
    sink.emit(Legacy.OWNER, token(F, m), a.neg());
    sink.emit(Legacy.RAM, Legacy.ramTuple(F, address, m[c.clock], m[c.clock + 1], m[c.clock + 2], Legacy.limbsOfBytes(F, m[c.old..][0..8]), one, one), a);
    sink.emit(Legacy.RAM, Legacy.ramTuple(F, address, m[c.epoch], m[c.tick_low], m[c.tick_high], Legacy.limbsOfBytes(F, m[c.new..][0..8]), one, one), a.neg());
    var input: [11]F = undefined;
    input[0] = m[c.first_id];
    input[1] = q(F, T.LINK);
    input[2] = m[c.lane];
    @memcpy(input[3..], m[c.old..][0..8]);
    var output = input;
    output[0] = m[c.last_id];
    output[1] = one;
    @memcpy(output[3..], m[c.new..][0..8]);
    sink.emit(Legacy.IO, input, a.sub(m[c.fresh]));
    sink.emit(Legacy.IO, output, a.neg());
    for (RANGE16) |col| sink.emit(Legacy.RANGE16, [1]F{m[col]}, one);
    for (RANGE8) |col| sink.emit(Legacy.RANGE8, [1]F{m[col]}, one);
}
pub fn emitMain(comptime F: type, f: *const [3]F, m: *const [MAIN]F, previous_active: F, rows: F, nonempty: F, sink: anytype) void {
    const one = F.one();
    const a = m[c.active];
    for ([_]usize{ c.active, c.fin, c.fresh, c.clock + 3, c.carry, c.carry + 1, c.carry + 2 }) |col| sink.emit(m[col].mul(m[col].sub(one)));
    sink.emit(m[c.fresh].mul(one.sub(a)));
    for (0..4) |i| {
        const add = if (i == 0) m[c.lane].mul(q(F, 8)) else m[c.carry + i - 1];
        var root = m[c.state + i].add(add).sub(m[c.address + i]);
        if (i < 3) root = root.sub(m[c.carry + i].mul(q(F, 65536)));
        sink.emit(root);
    }
    const same = m[c.clock + 3];
    sink.emit(a.mul(same).mul(m[c.clock].sub(m[c.epoch])));
    const before = m[c.clock + 1].add(m[c.clock + 2].mul(q(F, 65536)));
    const after = m[c.tick_low].add(m[c.tick_high].mul(q(F, 65536)));
    const gap = m[c.clock + 4].add(m[c.clock + 5].mul(q(F, 65536)));
    sink.emit(a.mul(same).mul(before.add(gap).add(one).sub(after)));
    sink.emit(a.mul(one.sub(same)).mul(m[c.clock].add(m[c.clock + 4]).add(one).sub(m[c.epoch])));
    sink.emit(a.mul(one.sub(same)).mul(m[c.clock + 5]));
    // Exact public active prefix, with one wrap-guard padding row.
    sink.emit(f[1].mul(a.sub(nonempty)));
    sink.emit(f[2].mul(a));
    sink.emit(one.sub(f[1]).mul(a).mul(one.sub(previous_active)));
    sink.emit(one.sub(f[1]).mul(previous_active.sub(a)).mul(f[0].sub(rows)));
}
