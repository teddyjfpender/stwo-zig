//! Closed message source: one original covering-word slot per row. Exactly one
//! RAM read per original slot; slot0 of continuation blocks is linked to slot17
//! of the preceding block, never re-read at the same clock. Header integration
//! must supply every full metadata token before this becomes an admitted chip.
const core = @import("stwo_core");
const E = @import("../../../evaluation.zig");
const Old = @import("../equations.zig");
const L = @import("../layout.zig");
const Lane = @import("permutation_lane.zig");
const M = core.fields.m31.M31;
pub const MAIN = 35;
pub const FIXED = 3;
pub const LOCAL_QUERIES = 28;
pub const LOCAL_PADDED = 32;
pub const OM31_INTER = 32; // modeled local binding plus global relation columns
pub const TOKEN_WORD: u32 = 0x4b53_0005;
pub const TOKEN_CARRY: u32 = 0x4b53_0006;
pub const c = struct {
    pub const active = 0;
    pub const slot = 1;
    pub const first = 2;
    pub const last = 3;
    pub const read = 4;
    pub const id = 5;
    pub const epoch = 6;
    pub const low = 7;
    pub const high = 8;
    pub const base = 9;
    pub const address = 13;
    pub const carry = 17;
    pub const clock = 20;
    pub const writable = 26;
    pub const value = 27;
};
fn q(comptime F: type, n: u32) F {
    return E.qFor(F, n);
}
pub fn row(old: *const [L.perm.MAIN]M, id: u32, slot: u8) ![MAIN]M {
    if (slot >= 18 or id == 0 or id >= core.fields.m31.Modulus) return error.InvalidSerializedMessageWord;
    const P = L.perm;
    var out: [MAIN]M = @splat(M.zero());
    out[c.active] = old[P.active];
    out[c.slot] = M.fromCanonical(slot);
    out[c.first] = old[P.first];
    out[c.last] = old[P.last];
    out[c.read] = old[P.read + @as(usize, slot)];
    out[c.id] = M.fromCanonical(id);
    @memcpy(out[c.epoch..][0..3], old[P.epoch..][0..3]);
    @memcpy(out[c.base..][0..4], old[P.base..][0..4]);
    var carries: [3]M = @splat(M.zero());
    if (slot != 0) @memcpy(&carries, old[P.wcarry + 3 * (@as(usize, slot) - 1) ..][0..3]);
    @memcpy(out[c.carry..][0..3], &carries);
    const address = Old.advance(M, out[c.base..][0..4].*, &carries, 8 * @as(u32, slot));
    @memcpy(out[c.address..][0..4], &address);
    @memcpy(out[c.clock..][0..6], old[P.wclock + 6 * @as(usize, slot) ..][0..6]);
    out[c.writable] = old[P.wwritable + @as(usize, slot)];
    @memcpy(out[c.value..][0..8], old[P.window + 8 * @as(usize, slot) ..][0..8]);
    return out;
}
pub fn token(comptime F: type, m: *const [MAIN]F) [19]F {
    var t: [19]F = @splat(F.zero());
    t[0] = q(F, TOKEN_WORD);
    t[1] = m[c.id];
    t[2] = m[c.slot];
    t[3] = m[c.read];
    t[4] = m[c.first];
    t[5] = m[c.last];
    @memcpy(t[6..9], m[c.epoch..][0..3]);
    @memcpy(t[9..13], m[c.base..][0..4]);
    return t;
}
fn carryToken(comptime F: type, id: F, bytes: [8]F) [19]F {
    var t: [19]F = @splat(F.zero());
    t[0] = q(F, TOKEN_CARRY);
    t[1] = id;
    @memcpy(t[2..10], &bytes);
    return t;
}
pub fn emitRaw(comptime F: type, fixed: *const [3]F, m: *const [MAIN]F, sink: anytype) void {
    const a = m[c.active];
    const one = F.one();
    const read = m[c.read];
    sink.emit(Old.OWNER, token(F, m), a.neg());
    const w = a.mul(q(F, 2).sub(fixed[1]).sub(fixed[2]));
    sink.emit(Old.OWNER, Lane.window(F, m[c.id], m[c.slot], m[c.value..][0..8].*), w);
    sink.emit(Old.OWNER, carryToken(F, m[c.id].sub(one), m[c.value..][0..8].*), a.sub(m[c.first]).mul(fixed[1]).neg());
    sink.emit(Old.OWNER, carryToken(F, m[c.id], m[c.value..][0..8].*), a.sub(m[c.last]).mul(fixed[2]));
    const value = Old.limbsOfBytes(F, m[c.value..][0..8]);
    const address = m[c.address..][0..4].*;
    sink.emit(Old.RAM, Old.ramTuple(F, address, m[c.clock], m[c.clock + 1], m[c.clock + 2], value, one, m[c.writable]), read);
    sink.emit(Old.RAM, Old.ramTuple(F, address, m[c.epoch], m[c.low], m[c.high], value, one, m[c.writable]), read.neg());
    for ([_]usize{ c.epoch, c.low, c.base, c.base + 1, c.base + 2, c.base + 3, c.address, c.address + 1, c.address + 2, c.address + 3, c.clock, c.clock + 1, c.clock + 4 }) |col| sink.emit(Old.RANGE16, [1]F{m[col]}, one);
    for ([_]usize{ c.high, c.clock + 2, c.clock + 5, c.value, c.value + 1, c.value + 2, c.value + 3, c.value + 4, c.value + 5, c.value + 6, c.value + 7 }) |col| sink.emit(Old.RANGE8, [1]F{m[col]}, one);
}
pub fn emitMain(comptime F: type, fixed: *const [3]F, m: *const [MAIN]F, sink: anytype) void {
    const one = F.one();
    const read = m[c.read];
    const same = m[c.clock + 3];
    const big = q(F, 65536);
    for ([_]usize{ c.active, c.first, c.last, c.read, c.writable, c.clock + 3, c.carry, c.carry + 1, c.carry + 2 }) |col| sink.emit(m[col].mul(m[col].sub(one)));
    sink.emit(m[c.slot].sub(fixed[0]));
    sink.emit(read.mul(one.sub(m[c.active])));
    sink.emit(m[c.first].mul(one.sub(m[c.active])));
    sink.emit(m[c.last].mul(one.sub(m[c.active])));
    sink.emit(fixed[1].mul(read).mul(one.sub(m[c.first])));
    const add = fixed[0].mul(q(F, 8));
    for (0..4) |i| {
        const incoming = if (i == 0) add else m[c.carry + i - 1];
        const outgoing = if (i == 3) F.zero() else m[c.carry + i].mul(big);
        sink.emit(m[c.base + i].add(incoming).sub(m[c.address + i]).sub(outgoing));
    }
    sink.emit(read.mul(same).mul(m[c.clock].sub(m[c.epoch])));
    const bt = m[c.clock + 1].add(m[c.clock + 2].mul(big));
    const at = m[c.low].add(m[c.high].mul(big));
    sink.emit(read.mul(same).mul(bt.add(m[c.clock + 4]).add(m[c.clock + 5].mul(big)).add(one).sub(at)));
    sink.emit(read.mul(one.sub(same)).mul(m[c.clock].add(m[c.clock + 4]).add(one).sub(m[c.epoch])));
    sink.emit(read.mul(one.sub(same)).mul(m[c.clock + 5]));
}
