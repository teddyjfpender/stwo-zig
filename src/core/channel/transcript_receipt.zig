//! Versioned receipts for completed canonical proof transcripts.
const std = @import("std");
const blake2 = @import("blake2s.zig");
const blake3 = @import("blake3.zig");
pub const Suite = enum { blake2s, blake3 };
pub const Receipt = struct { version: u16, suite: Suite, digest: [32]u8 };

/// Immutable legacy receipt encoding, retained for existing product reports.
pub fn legacyDigest(channel_digest: [32]u8, draw_count: u32) [32]u8 {
    var counter: [4]u8 = undefined;
    std.mem.writeInt(u32, &counter, draw_count, .little);
    var hasher = @import("../vcs/blake2_hash.zig").Blake2sHasher.init();
    hasher.update("stwo-zig/riscv/transcript-state/v1");
    hasher.update(&channel_digest);
    hasher.update(&counter);
    return hasher.finalize();
}
pub fn blake3Digest(channel_digest: [32]u8, draw_count: u64) [32]u8 {
    var counter: [8]u8 = undefined;
    std.mem.writeInt(u64, &counter, draw_count, .little);
    var length: [4]u8 = undefined;
    std.mem.writeInt(u32, &length, blake3.PROTOCOL_ID.len, .little);
    var hasher = @import("../vcs/blake3_hash.zig").Blake3Hasher.init();
    hasher.update("stwo-zig/riscv/transcript-state/v2\x00");
    hasher.update(&length);
    hasher.update(blake3.PROTOCOL_ID);
    hasher.update(&channel_digest);
    hasher.update(&counter);
    return hasher.finalize();
}
pub fn fromChannel(channel: anytype) Receipt {
    const C = @TypeOf(channel);
    if (C == blake2.Blake2sChannel) return .{ .version = 1, .suite = .blake2s, .digest = legacyDigest(channel.digestBytes(), channel.n_draws) };
    if (C == blake3.Channel) return .{ .version = 2, .suite = .blake3, .digest = blake3Digest(channel.digestBytes(), channel.n_draws) };
    @compileError("transcript receipts require a canonical admitted channel type");
}
