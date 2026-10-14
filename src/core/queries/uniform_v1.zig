//! Candidate S31NAT9F query draw. No production prover or verifier selects it.
//!
//! The caller supplies the verifier-owned transcript digest *after* the final
//! accepted FRI PoW nonce and the verifier-derived query event ordinal. Each
//! block hashes the exact S31BCS2 raw-word frame proposed for that event.
//! The legacy M31-output hash and its biased residues are never consulted.
const std = @import("std");
const Blake2sHasher = @import("../vcs/blake2_hash.zig").Blake2sHasher;

pub const words_per_block: u64 = 8;
pub const word_space: u64 = @as(u64, 1) << 32;
pub const frame_bytes: usize = 60;
pub const role_raw_word_draw: u8 = 4;

pub const Error = error{
    InvalidDomain,
    InsufficientBlockBudget,
    CounterExhausted,
};

/// Exactly `S31BCS2 || 04 || LE64(36) || LE64(event) || digest || LE32(counter)`.
/// The 36-byte payload is the digest followed by the block counter.
pub fn queryFrame(digest: [32]u8, event: u64, counter: u32) [frame_bytes]u8 {
    var frame: [frame_bytes]u8 = undefined;
    @memcpy(frame[0..7], "S31BCS2");
    frame[7] = role_raw_word_draw;
    std.mem.writeInt(u64, frame[8..16], 36, .little);
    std.mem.writeInt(u64, frame[16..24], event, .little);
    @memcpy(frame[24..56], digest[0..]);
    std.mem.writeInt(u32, frame[56..60], counter, .little);
    return frame;
}

/// Isolated query-stage channel for a future framed protocol. The event and
/// initial digest are owned by the verifier schedule, not read from the proof.
/// The `u64` cursor permits exactly 2^32 distinct u32 block counters and then
/// fails closed; there is no wrap or repeated hash preimage.
pub const FramedQueryWordChannelV1 = struct {
    digest: [32]u8,
    event: u64,
    next_block: u64 = 0,

    pub fn init(post_nonce_digest: [32]u8, query_event: u64) FramedQueryWordChannelV1 {
        return .{ .digest = post_nonce_digest, .event = query_event };
    }

    pub fn drawRawU32sChecked(self: *FramedQueryWordChannelV1) Error![8]u32 {
        if (self.next_block >= word_space) return error.CounterExhausted;
        const frame = queryFrame(self.digest, self.event, @intCast(self.next_block));
        const hash = Blake2sHasher.hash(frame[0..]);
        self.next_block += 1;
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, i| {
            word.* = std.mem.readInt(u32, hash[4 * i ..][0..4], .little);
        }
        return words;
    }
};

/// Raw query order and duplicates are retained. A drawn block always consumes
/// all eight oracle words, even when the final output uses only a prefix.
pub const SampledQueriesV1 = struct {
    raw: []usize,
    blocks_consumed: u64,
    words_examined: u64,
    words_rejected: u64,

    pub fn wordsDiscarded(self: SampledQueriesV1) u64 {
        return self.blocks_consumed * words_per_block - self.words_examined;
    }

    pub fn deinit(self: *SampledQueriesV1, allocator: std.mem.Allocator) void {
        allocator.free(self.raw);
        self.* = undefined;
    }
};

/// Draws with replacement from `2^log_domain_size`, the native FRI domain.
/// Here the generic rejection threshold is 2^32, so there are zero rejected
/// words and the optimized operation is exactly `word & (domain_size - 1)`.
pub fn drawUniformQueriesV1(
    channel: anytype,
    allocator: std.mem.Allocator,
    log_domain_size: u32,
    n_queries: usize,
    max_blocks: u64,
) (Error || std.mem.Allocator.Error)!SampledQueriesV1 {
    if (log_domain_size > 31) return error.InvalidDomain;
    const domain_size: u64 = @as(u64, 1) << @intCast(log_domain_size);
    return drawUniformBoundedV1(channel, allocator, domain_size, n_queries, max_blocks);
}

/// Exact-uniform reduction for any domain in `[1, 2^32]`. Reject words at or
/// above `floor(2^32 / domain_size) * domain_size`, then take the remainder.
/// Conditional on ideal independent uniform raw words and successful bounded
/// completion, every emitted position is uniform. The bounded failure event
/// must be included separately in a native security argument.
pub fn drawUniformBoundedV1(
    channel: anytype,
    allocator: std.mem.Allocator,
    domain_size: u64,
    n_queries: usize,
    max_blocks: u64,
) (Error || std.mem.Allocator.Error)!SampledQueriesV1 {
    if (domain_size == 0 or domain_size > word_space) return error.InvalidDomain;
    if (@as(u128, n_queries) > @as(u128, max_blocks) * words_per_block)
        return error.InsufficientBlockBudget;

    const raw = try allocator.alloc(usize, n_queries);
    errdefer allocator.free(raw);
    const limit = (word_space / domain_size) * domain_size;
    const mask = domain_size - 1;
    const power_of_two = std.math.isPowerOfTwo(domain_size);
    var result = SampledQueriesV1{
        .raw = raw,
        .blocks_consumed = 0,
        .words_examined = 0,
        .words_rejected = 0,
    };
    var produced: usize = 0;
    while (produced < n_queries) {
        if (result.blocks_consumed == max_blocks) return error.InsufficientBlockBudget;
        const words = try channel.drawRawU32sChecked();
        result.blocks_consumed += 1;
        for (words) |word| {
            result.words_examined += 1;
            if (@as(u64, word) >= limit) {
                result.words_rejected += 1;
                continue;
            }
            const position = if (power_of_two)
                @as(u64, word) & mask
            else
                @as(u64, word) % domain_size;
            raw[produced] = @intCast(position);
            produced += 1;
            if (produced == n_queries) break;
        }
    }
    return result;
}

test "framed query words use exact role and independent BLAKE2s oracle" {
    const digest = [_]u8{0x5a} ** 32;
    const frame = queryFrame(digest, 17, 3);
    try std.testing.expectEqualSlices(u8, "S31BCS2", frame[0..7]);
    try std.testing.expectEqual(@as(u8, 4), frame[7]);
    try std.testing.expectEqual(@as(u64, 36), std.mem.readInt(u64, frame[8..16], .little));
    try std.testing.expectEqual(@as(u64, 17), std.mem.readInt(u64, frame[16..24], .little));
    try std.testing.expectEqualSlices(u8, digest[0..], frame[24..56]);
    try std.testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, frame[56..60], .little));

    var channel = FramedQueryWordChannelV1.init(digest, 17);
    channel.next_block = 3;
    const words = try channel.drawRawU32sChecked();
    const Oracle = std.crypto.hash.blake2.Blake2s256;
    var expected_hash: [32]u8 = undefined;
    Oracle.hash(frame[0..], &expected_hash, .{});
    const python_hash = [_]u8{
        0x25, 0xb8, 0x98, 0x88, 0xee, 0xcb, 0x9c, 0x33,
        0x76, 0x07, 0x30, 0x8e, 0x8e, 0xad, 0x51, 0x57,
        0xf5, 0x9c, 0x04, 0x9d, 0xc4, 0x0d, 0x29, 0xa9,
        0x2a, 0xd3, 0x47, 0x4b, 0xf4, 0xd6, 0xc7, 0x29,
    };
    // Independently generated by Python hashlib.blake2s over the frame.
    try std.testing.expectEqualSlices(u8, &python_hash, &expected_hash);
    for (words, 0..) |word, i| {
        try std.testing.expectEqual(
            std.mem.readInt(u32, expected_hash[4 * i ..][0..4], .little),
            word,
        );
    }
    try std.testing.expectEqual(@as(u64, 4), channel.next_block);
    try std.testing.expect(!std.mem.eql(u8, &frame, &queryFrame(digest, 18, 3)));
    try std.testing.expect(!std.mem.eql(u8, &frame, &queryFrame(digest, 17, 4)));
}

test "power of two queries mask raw words, retaining order and duplicates" {
    const Fixture = struct {
        blocks: [2][8]u32 = .{
            .{ 0xffff_ffff, 0x7fff_ffff, 0, 1, 9, 9, 8, 7 },
            .{ 0xffff_fffe, 0, 0, 0, 0, 0, 0, 0 },
        },
        cursor: usize = 0,
        pub fn drawRawU32sChecked(self: *@This()) Error![8]u32 {
            if (self.cursor == self.blocks.len) return error.CounterExhausted;
            defer self.cursor += 1;
            return self.blocks[self.cursor];
        }
    };
    var fixture = Fixture{};
    var sampled = try drawUniformQueriesV1(&fixture, std.testing.allocator, 3, 9, 2);
    defer sampled.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(usize, &.{ 7, 7, 0, 1, 1, 1, 0, 7, 6 }, sampled.raw);
    try std.testing.expectEqual(@as(u64, 2), sampled.blocks_consumed);
    try std.testing.expectEqual(@as(u64, 9), sampled.words_examined);
    try std.testing.expectEqual(@as(u64, 0), sampled.words_rejected);
    try std.testing.expectEqual(@as(u64, 7), sampled.wordsDiscarded());
}

test "non power of two rejection is exact and capped" {
    const Fixture = struct {
        cursor: usize = 0,
        pub fn drawRawU32sChecked(self: *@This()) Error![8]u32 {
            self.cursor += 1;
            if (self.cursor == 1) return .{ 0xffff_ffff, 0xffff_fffe, 0, 5, 6, 1, 2, 3 };
            return .{ 0xffff_fffd, 4, 2, 0, 0, 0, 0, 0 };
        }
    };
    var fixture = Fixture{};
    // floor(2^32 / 3) * 3 = 2^32 - 1: only maxInt(u32) rejects.
    var sampled = try drawUniformBoundedV1(&fixture, std.testing.allocator, 3, 8, 2);
    defer sampled.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(usize, &.{ 2, 0, 2, 0, 1, 2, 0, 1 }, sampled.raw);
    try std.testing.expectEqual(@as(u64, 1), sampled.words_rejected);
    try std.testing.expectEqual(@as(u64, 2), sampled.blocks_consumed);
    try std.testing.expectEqual(@as(u64, 9), sampled.words_examined);

    var capped = Fixture{};
    try std.testing.expectError(error.InsufficientBlockBudget, drawUniformBoundedV1(&capped, std.testing.allocator, 3, 8, 1));
    try std.testing.expectEqual(@as(usize, 1), capped.cursor);
}

test "empty, invalid, budget and counter boundaries fail closed" {
    const digest = [_]u8{0} ** 32;
    var channel = FramedQueryWordChannelV1.init(digest, 0);
    var empty = try drawUniformQueriesV1(&channel, std.testing.allocator, 31, 0, 0);
    defer empty.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 0), channel.next_block);
    try std.testing.expectError(error.InvalidDomain, drawUniformQueriesV1(&channel, std.testing.allocator, 32, 1, 1));
    try std.testing.expectError(error.InvalidDomain, drawUniformBoundedV1(&channel, std.testing.allocator, 0, 1, 1));
    try std.testing.expectError(error.InsufficientBlockBudget, drawUniformQueriesV1(&channel, std.testing.allocator, 2, 9, 1));
    try std.testing.expectEqual(@as(u64, 0), channel.next_block);
    channel.next_block = word_space - 1;
    _ = try channel.drawRawU32sChecked();
    try std.testing.expectEqual(word_space, channel.next_block);
    try std.testing.expectError(error.CounterExhausted, channel.drawRawU32sChecked());
    try std.testing.expectEqual(word_space, channel.next_block);
}
