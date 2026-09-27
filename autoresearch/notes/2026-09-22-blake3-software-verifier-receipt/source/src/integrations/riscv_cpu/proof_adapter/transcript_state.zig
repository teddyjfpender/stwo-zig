//! Canonical digest of the completed production transcript state.

const std = @import("std");
const stwo = @import("stwo");

/// Legacy product reports retain their exact v1 bytes.
pub const fromChannel = stwo.core.channel.transcript_receipt.fromChannel;
pub const receiptDigest = stwo.core.channel.transcript_receipt.legacyDigest;

test "receipt digest commits the final draw count" {
    const channel_digest = [_]u8{0xab} ** 32;
    const without_draw = receiptDigest(channel_digest, 0);
    const with_draw = receiptDigest(channel_digest, 1);

    try std.testing.expect(!std.mem.eql(u8, &without_draw, &with_draw));
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{
            0x27, 0xb6, 0xef, 0x19, 0x32, 0x3b, 0xcd, 0x77,
            0x27, 0x6c, 0x52, 0x5a, 0x2a, 0x7c, 0x3f, 0x01,
            0x9b, 0x1a, 0x0d, 0x25, 0x59, 0x96, 0x94, 0x59,
            0x35, 0x4d, 0xf5, 0x7d, 0x60, 0xa8, 0x0f, 0x6d,
        },
        &without_draw,
    );
}
