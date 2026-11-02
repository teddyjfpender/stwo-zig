//! Transcript identity of the LS-D64 encoding, mixed only when present.
const std = @import("std");
const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const L = @import("layout.zig");
pub const CONSTRAINTS = @import("component.zig").CONSTRAINTS;
pub fn identity() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo-rv64/ls-dword/encoding-v1/aligned-LD-SD-only/main39-affine-onto-V1-logical79/virtual-I-C-flags-opcode-offset0-tick-addr0/inter28/ram-prefix/7-affine-local-fractions/owner19-u16x4-u8x2/4-strict-pairs/one-local-prefix/D3/shared-RAM14-OWNER19-U16-U8");
    var word: [4]u8 = undefined;
    for (L.STORED ++ L.LOGICAL_U16 ++ L.LOGICAL_U8) |c| {
        std.mem.writeInt(u32, &word, @intCast(c), .little);
        h.update(&word);
    }
    return h.finalResult();
}
pub fn mix(channel: *Channel) void {
    channel.mixU32s(&.{ 0x4c534438, 1, L.MAIN, L.INTERACTION, @intCast(CONSTRAINTS) });
    const digest = identity();
    var words: [8]u32 = undefined;
    for (&words, 0..) |*w, j| w.* = std.mem.readInt(u32, digest[4 * j ..][0..4], .little);
    channel.mixU32s(&words);
}
