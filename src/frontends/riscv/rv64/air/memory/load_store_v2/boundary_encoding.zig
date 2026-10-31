//! Scalable public-boundary encoding; canonical RAM14 tuples are independently
//! authorized by the accepting receiver. Gap ranges remain local obligations.
const std = @import("std");
const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
pub fn identity() [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("stwo-rv64/scalable-boundary-v2/main23/inter20/public-RAM14-canonical-tuples/four-U16-address-gaps/no-U8-debt/D3", &result, .{});
    return result;
}
pub fn mix(channel: *Channel) void {
    channel.mixU32s(&.{ 0x57425032, 2, 23, 20, 47, 4 });
    const digest = identity();
    var words: [8]u32 = undefined;
    for (&words, 0..) |*w, j| w.* = std.mem.readInt(u32, digest[4 * j ..][0..4], .little);
    channel.mixU32s(&words);
}
