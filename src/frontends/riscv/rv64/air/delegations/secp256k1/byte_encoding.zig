//! Immutable query-schema authority. Legacy contexts keep their original
//! transcript; the Word16 receiver explicitly selects canonical Wire35 inputs.
const std = @import("std");
const L = @import("layout.zig");
pub const VERSION: u32 = 1;
pub fn identity(policy: L.BytePolicy) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo-rv64/secp-byte-queries/v1\x00");
    const policy_word: u32 = @intFromEnum(policy);
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, policy_word, .little);
    h.update(&bytes);
    for ([_]L.Kind{ .product, .linear }) |kind| {
        for ([_]usize{ L.main(kind), L.metadataByteCount(kind), L.byteCountFor(kind, policy), L.interactionFor(kind, policy), L.constraintsFor(kind, policy) }) |v| {
            std.mem.writeInt(u32, &bytes, @intCast(v), .little);
            h.update(&bytes);
        }
        for (0..L.byteCountFor(kind, policy)) |index| {
            std.mem.writeInt(u32, &bytes, @intCast(L.byteColumnFor(kind, policy, index)), .little);
            h.update(&bytes);
        }
    }
    return h.finalResult();
}
pub fn mix(channel: anytype, policy: L.BytePolicy) void {
    if (policy == .local) return; // exact legacy transcript compatibility
    channel.mixU32s(&.{ 0x53425131, VERSION });
    const id = identity(policy);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*v, i| v.* = std.mem.readInt(u32, id[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
