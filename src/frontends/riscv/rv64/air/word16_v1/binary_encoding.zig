//! Physical BINARY encoding. Semantic FUNCTION13 and AND tuples are unchanged.
const std = @import("std");
const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
pub const VERSION: u32 = 2;
pub fn identity() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo-rv64/word16-binary/encoding-v2/main42/inter24/strict-AND-pairs4-FUNCTION-single/one-cyclic-prefix/combined-debt/D3");
    return h.finalResult();
}
pub fn mix(channel: *Channel) void {
    channel.mixU32s(&.{ 0x42494e45, VERSION, 42, 24, 50 });
    const digest = identity();
    var words: [8]u32 = undefined;
    for (&words, 0..) |*w, i| w.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
