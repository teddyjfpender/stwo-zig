//! Chunked, parallel SHA-256 integrity digest for large cache artifacts.
//!
//! Each payload slice is cut into fixed-size chunks (an empty slice counts as
//! one empty chunk), every chunk is hashed independently and in parallel, and
//! the digest is SHA-256 over the header followed by the chunk digests in
//! order. Every payload byte is covered exactly once under a
//! collision-resistant construction; the chunk size and the slice boundaries
//! are fixed by the caller's header, so the construction is unambiguous for a
//! given header. This is an integrity check for caller-owned artifacts only:
//! it never selects protocol authority.
//!
//! Shared by the Cairo preprocessed product cache (`tree_digest_cache.zig`,
//! which defines the historical byte format) and the RV64 setup cache.

const std = @import("std");
const work_pool = @import("work_pool.zig");

pub const default_chunk_bytes: usize = 4 * 1024 * 1024;
const max_hash_workers: usize = 16;

const ChunkPlan = struct {
    slices: []const []const u8,
    digests: [][32]u8,
    chunk_bytes: usize,
    next: std.atomic.Value(usize),

    fn chunkAt(self: *const ChunkPlan, wanted: usize) ?[]const u8 {
        var remaining = wanted;
        for (self.slices) |slice| {
            const count = chunkCount(slice.len, self.chunk_bytes);
            if (remaining < count) {
                const start = remaining * self.chunk_bytes;
                const end = @min(slice.len, start + self.chunk_bytes);
                return slice[start..end];
            }
            remaining -= count;
        }
        return null;
    }

    fn run(self: *ChunkPlan) void {
        while (true) {
            const index = self.next.fetchAdd(1, .monotonic);
            if (index >= self.digests.len) return;
            const chunk = self.chunkAt(index) orelse return;
            std.crypto.hash.sha2.Sha256.hash(chunk, &self.digests[index], .{});
        }
    }
};

fn chunkCount(length: usize, chunk_bytes: usize) usize {
    if (length == 0) return 1;
    return (length + chunk_bytes - 1) / chunk_bytes;
}

/// SHA-256 over `header` followed by every chunk digest of `slices` in order.
pub fn digest(
    allocator: std.mem.Allocator,
    header: []const u8,
    slices: []const []const u8,
    chunk_bytes: usize,
) ![32]u8 {
    if (chunk_bytes == 0) return error.InvalidChunkSize;
    var count: usize = 0;
    for (slices) |slice| count += chunkCount(slice.len, chunk_bytes);
    const digests = try allocator.alloc([32]u8, count);
    defer allocator.free(digests);

    var plan = ChunkPlan{
        .slices = slices,
        .digests = digests,
        .chunk_bytes = chunk_bytes,
        .next = std.atomic.Value(usize).init(0),
    };

    const worker_target = @min(
        @min(count, max_hash_workers),
        @max(@as(usize, 1), std.Thread.getCpuCount() catch 1),
    );
    if (work_pool.getGlobalPool()) |pool| {
        var group: std.Thread.WaitGroup = .{};
        for (1..@min(worker_target, pool.workerCount())) |_| pool.spawnWg(&group, ChunkPlan.run, .{&plan});
        plan.run();
        group.wait();
    } else {
        var threads: [max_hash_workers]std.Thread = undefined;
        var spawned: usize = 0;
        while (spawned + 1 < worker_target) : (spawned += 1) {
            threads[spawned] = std.Thread.spawn(.{}, ChunkPlan.run, .{&plan}) catch break;
        }
        plan.run();
        for (threads[0..spawned]) |thread| thread.join();
    }

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(header);
    for (digests) |chunk_digest| hasher.update(&chunk_digest);
    return hasher.finalResult();
}

test "chunked digest covers every byte and binds slice boundaries" {
    const a = std.testing.allocator;
    var bytes: [1000]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @truncate(i *% 131 +% 7);
    const whole = [_][]const u8{&bytes};
    const split = [_][]const u8{ bytes[0..500], bytes[500..] };
    const base = try digest(a, "h", &whole, 64);
    try std.testing.expect(!std.mem.eql(u8, &base, &(try digest(a, "h", &split, 64))));
    try std.testing.expect(!std.mem.eql(u8, &base, &(try digest(a, "g", &whole, 64))));
    // Reference: SHA(header || SHA(chunk_i)...).
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("h");
    var at: usize = 0;
    while (at < bytes.len) : (at += 64) {
        var d: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes[at..@min(bytes.len, at + 64)], &d, .{});
        h.update(&d);
    }
    try std.testing.expectEqualSlices(u8, &h.finalResult(), &base);
    var flipped = bytes;
    flipped[999] ^= 1;
    const tampered = [_][]const u8{&flipped};
    try std.testing.expect(!std.mem.eql(u8, &base, &(try digest(a, "h", &tampered, 64))));
}
