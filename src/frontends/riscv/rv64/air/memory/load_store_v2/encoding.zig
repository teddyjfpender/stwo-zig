//! Concrete merged-local LS encoding; RAM14 remains a separate physical debt.
const std = @import("std");
const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
pub fn identity() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo-rv64/ls-owner19/encoding-v2/main79/inter96/ram-prefix/42-affine-local-fractions/21-strict-pairs/one-local-prefix/D3");
    return h.finalResult();
}
pub fn mix(channel: *Channel) void {
    channel.mixU32s(&.{ 0x4c534532, 2, 79, 96, 273 });
    const digest = identity();
    var words: [8]u32 = undefined;
    for (&words, 0..) |*w, j| w.* = std.mem.readInt(u32, digest[4 * j ..][0..4], .little);
    channel.mixU32s(&words);
}
