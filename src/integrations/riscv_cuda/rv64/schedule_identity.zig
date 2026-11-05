//! Content identity for immutable assignment-generation metadata, not a proof
//! transcript. Every byte remains bound, but independent SHA-256 chunks can be
//! hashed on the existing bounded proof pool. Worker count never changes keys.
const std = @import("std");
const work = @import("stwo_prover_engine").lookups.row_work;
const Sha = std.crypto.hash.sha2.Sha256;
pub const chunk_bytes = 1 << 20;
pub const Segments = [3][]const u8;

fn count(bytes: usize) usize {
    return bytes / chunk_bytes + @intFromBool(bytes % chunk_bytes != 0);
}
fn word(hash: *Sha, value: usize) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
const Context = struct {
    segments: Segments,
    ends: [3]usize,
    digests: [][32]u8,
    pub fn runRange(self: *@This(), _: usize, start: usize, end: usize) void {
        for (start..end) |ordinal| {
            var segment: usize = 0;
            while (ordinal >= self.ends[segment]) segment += 1;
            const local = ordinal - (if (segment == 0) @as(usize, 0) else self.ends[segment - 1]);
            const input = self.segments[segment];
            const begin = local * chunk_bytes;
            const bytes = input[begin .. begin + @min(chunk_bytes, input.len - begin)];
            var hash = Sha.init(.{});
            hash.update("circuit/original-witness-schedule/chunk/v2\x00");
            word(&hash, segment);
            word(&hash, local);
            word(&hash, input.len);
            word(&hash, bytes.len);
            hash.update(bytes);
            self.digests[ordinal] = hash.finalResult();
        }
    }
};
pub fn digest(a: std.mem.Allocator, segments: Segments) ![32]u8 {
    return digestWithOptions(a, segments, .{ .max_shards = 8, .min_rows_per_shard = 1 });
}
fn digestWithOptions(a: std.mem.Allocator, segments: Segments, options: work.RangeOptions) ![32]u8 {
    var ends: [3]usize = undefined;
    var total: usize = 0;
    for (segments, &ends) |bytes, *end| {
        total = try std.math.add(usize, total, count(bytes.len));
        end.* = total;
    }
    const digests = try a.alloc([32]u8, total);
    defer a.free(digests);
    var context = Context{ .segments = segments, .ends = ends, .digests = digests };
    _ = work.forEachRange(total, &context, options);
    var root = Sha.init(.{});
    root.update("circuit/original-witness-schedule/chunked-sha256/v2\x00");
    word(&root, chunk_bytes);
    for (segments) |bytes| word(&root, bytes.len);
    word(&root, total);
    root.update(std.mem.sliceAsBytes(digests));
    return root.finalResult();
}

test "schedule content identity binds segment boundaries ordering and every chunk" {
    const a = std.testing.allocator;
    const input = try a.alloc(u8, chunk_bytes * 2 + 1);
    defer a.free(input);
    @memset(input, 7);
    const baseline = try digest(a, .{ input, "indices", "levels" });
    for ([_]usize{ 0, chunk_bytes - 1, chunk_bytes, input.len - 1 }) |index| {
        input[index] ^= 1;
        try std.testing.expect(!std.mem.eql(u8, &baseline, &(try digest(a, .{ input, "indices", "levels" }))));
        input[index] ^= 1;
    }
    try std.testing.expect(!std.mem.eql(u8, &baseline, &(try digest(a, .{ input, "levels", "indices" }))));
    try std.testing.expect(!std.mem.eql(u8, &(try digest(a, .{ "a", "bc", "" })), &(try digest(a, .{ "ab", "c", "" }))));
    try std.testing.expect(!std.mem.eql(u8, &(try digest(a, .{ "", "", "a" })), &(try digest(a, .{ "", "a", "" }))));
    try std.testing.expect(!std.mem.eql(u8, &(try digest(a, .{ "", "", "" })), &(try digest(a, .{ "\x00", "", "" }))));
    try std.testing.expect(!std.mem.eql(u8, &baseline, &(try digest(a, .{ input[0 .. input.len - 1], "indices", "levels" }))));
}

test "schedule identity is identical with serial and bounded parallel hashing" {
    const a = std.testing.allocator;
    const pools = @import("stwo_prover_engine").work_pool;
    const input = try a.alloc(u8, 8 * chunk_bytes + 17);
    defer a.free(input);
    for (input, 0..) |*byte, i| byte.* = @truncate(i *% 131);
    const segments = Segments{ input[0 .. 3 * chunk_bytes + 3], input[3 * chunk_bytes + 3 .. 7 * chunk_bytes], input[7 * chunk_bytes ..] };
    const serial = try digestWithOptions(a, segments, .{ .max_shards = 1, .min_rows_per_shard = 1 });
    var pool: pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 64 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try std.testing.expectEqualSlices(u8, &serial, &(try digest(a, segments)));
    // An unavailable lease must keep the same content identity via serial work.
    var held = try pool.acquire(try pools.WorkerBudget.init(4));
    defer held.deinit();
    try std.testing.expectEqualSlices(u8, &serial, &(try digest(a, segments)));
}
