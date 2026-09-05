//! Versioned memory ABI for Ethereum secp256k1 signer recovery.
//!
//! Cryptographic byte strings retain Ethereum's big-endian convention. The
//! RV32 memory bus observes each aligned four-byte chunk as a little-endian
//! word; `wordFromBytes` and `bytesFromWord` are the sole conversion seam.

const std = @import("std");

pub const schema_version: u16 = 1;
pub const alignment: u32 = 4;

pub const digest_offset: u32 = 0;
pub const r_offset: u32 = 32;
pub const s_offset: u32 = 64;
pub const recovery_id_offset: u32 = 96;
pub const public_key_offset: u32 = 100;
pub const status_offset: u32 = 164;
pub const record_size: u32 = 168;

pub const digest_size: usize = 32;
pub const scalar_size: usize = 32;
pub const public_key_size: usize = 64;
pub const input_word_count: usize = 25;
pub const output_word_count: usize = 17;
pub const memory_word_count: usize = input_word_count + output_word_count;
pub const success_status: u32 = 1;

pub fn inputWordAddress(record_ptr: u32, index: usize) u32 {
    std.debug.assert(index < input_word_count);
    return record_ptr + @as(u32, @intCast(index * @sizeOf(u32)));
}

pub fn outputWordAddress(record_ptr: u32, index: usize) u32 {
    std.debug.assert(index < output_word_count);
    return record_ptr + public_key_offset +
        @as(u32, @intCast(index * @sizeOf(u32)));
}

pub fn wordFromBytes(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

pub fn bytesFromWord(word: u32) [4]u8 {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .little);
    return bytes;
}

test "Ethereum signer-recovery ABI geometry and word byte order are pinned" {
    try std.testing.expectEqual(@as(u32, 0), digest_offset);
    try std.testing.expectEqual(@as(u32, 32), r_offset);
    try std.testing.expectEqual(@as(u32, 64), s_offset);
    try std.testing.expectEqual(@as(u32, 96), recovery_id_offset);
    try std.testing.expectEqual(@as(u32, 100), public_key_offset);
    try std.testing.expectEqual(@as(u32, 164), status_offset);
    try std.testing.expectEqual(@as(u32, 168), record_size);
    try std.testing.expectEqual(@as(usize, 25), input_word_count);
    try std.testing.expectEqual(@as(usize, 17), output_word_count);
    try std.testing.expectEqual(@as(u32, 0x2000), inputWordAddress(0x2000, 0));
    try std.testing.expectEqual(@as(u32, 0x2060), inputWordAddress(0x2000, 24));
    try std.testing.expectEqual(@as(u32, 0x2064), outputWordAddress(0x2000, 0));
    try std.testing.expectEqual(@as(u32, 0x20a4), outputWordAddress(0x2000, 16));
    const bytes = [4]u8{ 0x01, 0x23, 0x45, 0x67 };
    try std.testing.expectEqual(@as(u32, 0x6745_2301), wordFromBytes(&bytes));
    try std.testing.expectEqual(bytes, bytesFromWord(0x6745_2301));
}
