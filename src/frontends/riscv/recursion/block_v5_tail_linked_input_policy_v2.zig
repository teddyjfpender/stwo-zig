//! New-only B5WM/v2 public input frontier policy. Scalar proposals here become
//! source authority only through the genuine one-provider ancestor equations.
const std = @import("std");
const Input = @import("block_v5_input_tail_public_v1.zig");
pub const Owned = Input.Owned;
pub const Expected = Input.Pin;
pub const VERSION: u32 = 2;
pub const TAG: u32 = 0x4235574d;
pub fn retain(owner: *Owned) !*Owned {
    return owner.retain();
}
pub fn supplementCells(owner: *const Owned) usize {
    return owner.prefix_count + 10 * owner.frontier.len;
}
pub fn supplementWords(owner: *const Owned) usize {
    return owner.prefix_count + 8 * owner.frontier.len;
}
pub fn supplementOffset(owner: *const Owned, ordinal: u32) !u32 {
    if (ordinal >= supplementWords(owner)) return error.InvalidTailLinkedPublicCell;
    if (ordinal < owner.prefix_count) return ordinal;
    const word = ordinal - @as(u32, @intCast(owner.prefix_count));
    return @as(u32, @intCast(owner.prefix_count)) + 10 * (word / 8) + 2 + word % 8;
}
pub fn supplementWord(owner: *const Owned, ordinal: u32) !u32 {
    return supplementCell(owner, try supplementOffset(owner, ordinal));
}
pub fn supplementCell(owner: *const Owned, ordinal: u32) !u32 {
    if (ordinal >= supplementCells(owner)) return error.InvalidTailLinkedPublicCell;
    if (ordinal < owner.prefix_count) return owner.prefix_words[ordinal];
    const relative = ordinal - @as(u32, @intCast(owner.prefix_count));
    const index = relative / 10;
    const part = relative % 10;
    const range = owner.geometry.frontier()[index];
    return switch (part) {
        0 => std.math.cast(u32, range.first) orelse return error.InvalidTailLinkedPublicCell,
        1 => std.math.cast(u32, range.count) orelse return error.InvalidTailLinkedPublicCell,
        else => owner.frontier[index][part - 2],
    };
}
pub fn mixSupplement(owner: *const Owned, channel: anytype) void {
    channel.mixU32s(owner.prefix());
    for (owner.frontier, owner.geometry.frontier()) |cv, range| {
        channel.mixU32s(&.{ @as(u32, @intCast(range.first)), @as(u32, @intCast(range.count)) });
        channel.mixU32s(&cv);
    }
}

/// Mathematical public-replay bound; no large input allocation/hash occurs.
pub fn cellsForWordCount(words: usize) !usize {
    const geometry = try @import("blake3_words_tail_v1.zig").Geometry.init(words);
    return try std.math.add(usize, @min(words, Input.PREFIX_WORDS), try std.math.mul(usize, geometry.range_count, 10));
}
