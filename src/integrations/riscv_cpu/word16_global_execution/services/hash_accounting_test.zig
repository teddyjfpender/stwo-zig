//! Scaled-height counter oracle, not a wall-time benchmark or protocol change.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const Hash = core.crypto.blake2s_backend;
const Tree = engine.vcs_lifted.prover.MerkleProverLifted(H);
const Group = struct { log: u32, columns: usize };
fn count() u64 {
    const c = Hash.testCompressionCounts();
    return c.scalar + c.simd + 4 * c.parallel_simd_4;
}
fn measure(groups: []const Group) !void {
    const a = std.testing.allocator;
    var storage: std.ArrayList([]const M) = .empty;
    defer {
        for (storage.items) |s| a.free(s);
        storage.deinit(a);
    }
    var expected: u64 = 0;
    var total: usize = 0;
    for (groups) |g| {
        const before = (total + 15) / 16;
        total += g.columns;
        expected += @as(u64, @intCast((total + 15) / 16 - before)) * (@as(u64, 1) << @intCast(g.log));
        for (0..g.columns) |_| {
            const s = try a.alloc(M, @as(usize, 1) << @intCast(g.log));
            @memset(s, M.fromCanonical(17));
            storage.append(a, s) catch |err| {
                a.free(s);
                return err;
            };
        }
    }
    const refs = try Tree.sortColumnsByLogSizeAsc(a, storage.items);
    defer a.free(refs);
    var streaming = Tree.StreamingCommitter.init(a);
    defer streaming.deinit();
    Hash.resetTestCompressionCounts();
    try streaming.addColumns(refs);
    try std.testing.expectEqual(expected, count());
    for (streaming.leaf_hashers) |*h| {
        const digest = h.finalize();
        std.mem.doNotOptimizeAway(digest);
    }
    expected += streaming.leaf_hashers.len;
    try std.testing.expectEqual(expected, count());
}
test "native-height prefixed BLAKE2 leaf compression ledger matches backend counters" {
    // Exact current packet0 column histograms, with heights compressed into
    // 2..9 for a bounded counter test. Payload/height ordering and every hash
    // block boundary are preserved. Full-height costs are arithmetic, not timing.
    try measure(&.{ .{ .log = 2, .columns = 34 }, .{ .log = 3, .columns = 3 }, .{ .log = 4, .columns = 3 }, .{ .log = 5, .columns = 2 }, .{ .log = 6, .columns = 32 }, .{ .log = 7, .columns = 3 }, .{ .log = 8, .columns = 47 }, .{ .log = 9, .columns = 3 } });
    try measure(&.{ .{ .log = 3, .columns = 1 }, .{ .log = 4, .columns = 87 }, .{ .log = 5, .columns = 18 }, .{ .log = 6, .columns = 20 }, .{ .log = 7, .columns = 79 }, .{ .log = 8, .columns = 273 }, .{ .log = 9, .columns = 53 } });
    try measure(&.{ .{ .log = 2, .columns = 8 }, .{ .log = 3, .columns = 8 }, .{ .log = 4, .columns = 200 }, .{ .log = 5, .columns = 12 }, .{ .log = 6, .columns = 60 }, .{ .log = 7, .columns = 96 }, .{ .log = 8, .columns = 252 }, .{ .log = 9, .columns = 40 } });
}
