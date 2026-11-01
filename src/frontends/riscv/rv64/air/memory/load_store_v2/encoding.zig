//! Concrete merged-local LS encoding; RAM14 remains a separate physical debt.
const std = @import("std");
const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const L = @import("layout.zig");
pub fn identity() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo-rv64/ls-owner19/encoding-v5/main70/affine-virtual-write-tick-addressLow-EA4-opcode-bLow/inter48/ram-prefix/18-affine-local-fractions/9-strict-pairs/one-local-prefix/D3/closed-REG6-ROM30-OWNER19-RAM14/canonical-INIT-and-ranged-write-anchors");
    var column: [4]u8 = undefined;
    for (L.projection.STORED ++ L.LOGICAL_U16 ++ L.LOGICAL_U8) |c| {
        std.mem.writeInt(u32, &column, @intCast(c), .little);
        h.update(&column);
    }
    return h.finalResult();
}
pub fn mix(channel: *Channel) void {
    channel.mixU32s(&.{ 0x4c534532, 5, L.MAIN, L.INTERACTION, @intCast(L.constraints(.ls)) });
    const digest = identity();
    var words: [8]u32 = undefined;
    for (&words, 0..) |*w, j| w.* = std.mem.readInt(u32, digest[4 * j ..][0..4], .little);
    channel.mixU32s(&words);
}
