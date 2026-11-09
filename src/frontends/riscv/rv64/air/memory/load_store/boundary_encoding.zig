//! Scalable public-boundary encoding; canonical RAM14 tuples, address order,
//! uniqueness and alignment are independently authorized by the accepting
//! receiver. The chip carries no local range or sortedness obligations.
const std = @import("std");
const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const L = @import("layout.zig");
pub fn identity() [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("stwo-rv64/scalable-boundary-v3/main14/inter8/public-RAM14-canonical-tuples/receiver-sorted-unique-aligned/no-range-debt/D3", &result, .{});
    return result;
}
comptime {
    if (L.BOUND_MAIN != 14 or L.BOUND_INTERACTION != 8 or L.constraints(.initial) != 25) @compileError("boundary encoding is stale");
}
pub fn mix(channel: *Channel) void {
    channel.mixU32s(&.{ 0x57425032, 3, 14, 8, 25, 0 });
    const digest = identity();
    var words: [8]u32 = undefined;
    for (&words, 0..) |*w, j| w.* = std.mem.readInt(u32, digest[4 * j ..][0..4], .little);
    channel.mixU32s(&words);
}
