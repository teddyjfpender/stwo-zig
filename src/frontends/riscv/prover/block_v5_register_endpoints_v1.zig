//! Independently pinned block register endpoints. Native-v3 public register
//! metadata acquires access-value authority only through fresh sorted closure.
//! Intermediate PC/clock-only spans intentionally assert no register snapshot.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const sources = @import("block_v5_initial_sources_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const protocol = @import("block_v5_word_memory_protocol_v1.zig");
const Transition = @import("../air/block/memory_transition.zig").Transition;
pub const POLICY_VERSION: u32 = 1;
pub const Pins = struct {
    policy_version: u32 = POLICY_VERSION,
    first_touch_mask: u32,
    initial_registers: [32]u32,
    final_registers: [32]u32,
    final_clocks: [32]u64,
    pub fn digest(self: Pins) ![32]u8 {
        if (self.policy_version != POLICY_VERSION or self.initial_registers[0] != 0 or self.final_registers[0] != 0) return error.InvalidV5RegisterEndpointPolicy;
        for (self.initial_registers, self.final_registers, self.final_clocks, 0..) |first, last, clock, index| {
            if ((self.first_touch_mask & (@as(u32, 1) << @intCast(index))) == 0 and (first != last or clock != 0)) return error.UntouchedV5RegisterEndpointChanged;
        }
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/block-v5/global-register-endpoints/v1\x00");
        hash.update(&protocol.abiId());
        put(&hash, self.policy_version);
        put(&hash, self.first_touch_mask);
        for (self.initial_registers, self.final_registers, self.final_clocks) |first, last, clock| {
            put(&hash, first);
            put(&hash, last);
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, clock, .little);
            hash.update(&bytes);
        }
        return hash.finalResult();
    }
};
pub const Claims = struct { sum: Q, count: u64, plan_digest: [32]u8 };
/// Call only after the canonical initial-source checker has validated the
/// complete ordered touch file, its values, layout and independently pinned
/// SHA/length. This function rechecks the file pin and exact register mask.
pub fn check(a: std.mem.Allocator, pins: Pins, initial: sources.Pins, touches_file: std.fs.File, sealed: seal.Sealed, v5_pins: seal.Pins, entries: []const seal.Entry) !Claims {
    const digest = try pins.digest();
    if (!std.meta.eql(digest, sealed.register_endpoint_plan_digest) or !std.meta.eql(digest, v5_pins.register_endpoint_plan_digest) or !std.meta.eql(pins.initial_registers, initial.initial_registers)) return error.UntrustedV5RegisterEndpoints;
    try sealed.require(v5_pins, entries);
    const touches = try sources.readPinned(a, touches_file, initial.first_touches, sources.TOUCH_RECORD_BYTES);
    defer a.free(touches);
    var mask: u32 = 0;
    var prior: ?u32 = null;
    for (0..@intCast(initial.first_touches.records)) |index| {
        const record = touches[index * sources.TOUCH_RECORD_BYTES ..][0..sources.TOUCH_RECORD_BYTES];
        if (record[0] != 0) continue;
        const address = sources.readWord(record[1..5]);
        if (address >= 32 or (prior != null and address <= prior.?) or sources.readWord(record[5..9]) != pins.initial_registers[address]) return error.InvalidV5RegisterTouchRoster;
        prior = address;
        mask |= @as(u32, 1) << @intCast(address);
    }
    if (mask != pins.first_touch_mask) return error.InvalidV5RegisterTouchMask;
    const challenges = try protocol.Challenges.draw(a, sealed);
    var sum = Q.zero();
    for (pins.final_registers, pins.final_clocks, 0..) |value, clock, index| {
        if ((mask & (@as(u32, 1) << @intCast(index))) == 0) continue;
        const last = Transition{ .space = 0, .address = @intCast(index), .clock = clock, .before = 0, .after = value };
        sum = sum.add(try challenges.endpoint.combineBase(protocol.endpointTuple(last)).inv());
    }
    return .{ .sum = sum, .count = @popCount(mask), .plan_digest = digest };
}
fn put(hash: *std.crypto.hash.sha2.Sha256, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}
