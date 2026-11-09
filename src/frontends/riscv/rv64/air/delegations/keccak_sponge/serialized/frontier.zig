//! Closed tiny CPU frontier. It consumes the existing CPU OWNER19 locally;
//! one typed, injective Wire35 tuple delegates the WHOLE call to another shard.
//! There are no RAM accesses and no8-column Wire tax at every CPU retirement.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../../evaluation.zig");
const Old = @import("../equations.zig");
const L = @import("../layout.zig");
const T = @import("../types.zig");
const M = core.fields.m31.M31;
pub const production_admission_open = false;
pub const WIRE_KIND: u32 = 0x5350_4746;
pub const WIRE = 6;
pub const MAIN = 8;
pub const FIXED = 3;
pub const LOCAL_QUERIES = 3;
pub const OM31_INTER = 24;
pub const MAIN_CONSTRAINTS = 7;
pub const c = struct {
    pub const active = 0;
    pub const pointer = 1;
    pub const epoch = 5;
    pub const low = 6;
    pub const high = 7;
};
comptime {
    // The admitted packet bridge enum is the common Wire35 kind authority for
    // secp, SHA, arith, curves and the OP sparse-Miller candidate. This check
    // deliberately fails when a future registered kind aliases this namespace.
    const Kind = @import("../../secp256k1/word16_bridge/types.zig").Kind;
    for (@typeInfo(Kind).@"enum".fields) |field| if (field.value == WIRE_KIND) @compileError("sponge Wire35 namespace collision");
    if (WIRE_KIND >= core.fields.m31.Modulus) @compileError("Wire namespace must be canonical M31");
}
pub fn validatePublic(calls: u32, log: u32, epoch: u32, ordinal: u32) !void {
    if (log < 5 or log > 22 or epoch == 0 or epoch > 65535 or ordinal >= 256 or epoch != ordinal + 1) return error.SpongeFrontierGeometry;
    if (calls >= (@as(u32, 1) << @intCast(log))) return error.SpongeFrontierGeometry;
}
pub fn row(pointer: u64, epoch: u16, tick: u24, expected_epoch: u16) ![MAIN]M {
    if (pointer % 8 != 0 or epoch == 0 or epoch != expected_epoch or tick == 0) return error.SpongeFrontierRecord;
    var out: [MAIN]M = undefined;
    out[c.active] = M.one();
    for (out[c.pointer..][0..4], 0..) |*v, i| v.* = M.fromCanonical(@as(u16, @truncate(pointer >> @as(u6, @intCast(16 * i)))));
    out[c.epoch] = M.fromCanonical(epoch);
    out[c.low] = M.fromCanonical(@as(u16, @truncate(tick)));
    out[c.high] = M.fromCanonical(tick >> 16);
    return out;
}
pub fn owner(comptime F: type, m: *const [MAIN]F) [19]F {
    var descriptor: [L.call.tick_high + 1]F = @splat(F.zero());
    @memcpy(descriptor[L.call.pointer..][0..4], m[c.pointer..][0..4]);
    descriptor[L.call.epoch] = m[c.epoch];
    descriptor[L.call.tick_low] = m[c.low];
    descriptor[L.call.tick_high] = m[c.high];
    return Old.ecallTuple(F, &descriptor);
}
/// An injective fixed namespace +ordinal +COMPLETE19 coordinates +14 zeros.
/// No coordinate is hashed/truncated. Ordinal is admitted independently (<256)
/// and epoch/tick remain in the original19-coordinate retirement authority.
pub fn wireTuple(comptime F: type, ordinal: F, retirement: [19]F) [35]F {
    var out: [35]F = @splat(F.zero());
    out[0] = E.qFor(F, WIRE_KIND);
    out[1] = ordinal;
    @memcpy(out[2..21], &retirement);
    return out;
}
pub fn fromDescriptor(comptime F: type, m: []const F) [35]F {
    return wireTuple(F, m[L.call.epoch].sub(F.one()), Old.ecallTuple(F, m));
}
pub fn emitRaw(comptime F: type, m: *const [MAIN]F, ordinal: F, sink: anytype) void {
    const tuple = owner(F, m);
    sink.emit(Old.OWNER, tuple, m[c.active].neg());
    sink.emit(Old.RANGE16, [1]F{m[c.low]}, F.one());
    sink.emit(Old.RANGE8, [1]F{m[c.high]}, F.one());
    sink.emit(WIRE, wireTuple(F, ordinal, tuple), m[c.active]);
}
pub fn emitMain(comptime F: type, f: *const [FIXED]F, m: *const [MAIN]F, previous_active: F, calls: F, nonempty: F, epoch: F, ordinal: F, sink: anytype) void {
    const one = F.one();
    const a = m[c.active];
    sink.emit(a.mul(a.sub(one)));
    sink.emit(f[1].mul(a.sub(nonempty)));
    sink.emit(f[2].mul(a));
    sink.emit(one.sub(f[1]).mul(a).mul(one.sub(previous_active)));
    sink.emit(one.sub(f[1]).mul(previous_active.sub(a)).mul(f[0].sub(calls)));
    sink.emit(a.mul(m[c.epoch].sub(epoch)));
    sink.emit(epoch.sub(ordinal).sub(one));
}
pub fn emitWireFor(comptime consume: bool, comptime F: type, m: *const [MAIN]F, ordinal: F, first: F, current: E.SecureFor(F), previous: E.SecureFor(F), claim: E.ConstFor(F), wire: @import("../../secp256k1/equations.zig").WireFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    const a = m[c.active];
    const raw = E.denominatorFor(F, wire.offset, &wire.coefficients, &wireTuple(F, ordinal, owner(F, m)), true);
    // Inactive rows have D=1; active unit weights exclude every denominator
    // pole through this same polynomial equation, without an inverse plane.
    const denominator = E.SecureFor(F).one().add(E.mulBaseFor(F, raw.sub(E.SecureFor(F).one()), a));
    const delta = current.sub(previous).add(E.mulBaseFor(F, E.splatFor(F, claim), first));
    sink.emit(if (consume) delta.mul(denominator).add(E.liftFor(F, a)) else delta.mul(denominator).sub(E.liftFor(F, a)));
}
