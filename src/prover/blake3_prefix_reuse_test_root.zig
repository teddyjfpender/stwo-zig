const std = @import("std");
const core = @import("stwo_core");
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const M = core.fields.m31.M31;
const Tree = @import("vcs_lifted/prover.zig").MerkleProverLifted(H);
const workers = @import("work_pool.zig");

test "BLAKE3 bounded prefix reuse preserves every layer across caps chunks and workers" {
    const a = std.testing.allocator;
    var columns: [285]Tree.ColumnRef = undefined;
    var allocated: usize = 0;
    defer for (columns[0..allocated]) |column| a.free(column.values);
    for (&columns, 0..) |*column, i| {
        const log: u32 = if (i < 8) 1 else if (i < 271) 3 else if (i < 276) 6 else 13;
        const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
        for (values, 0..) |*v, j| v.* = M.fromCanonical(@intCast(i * 31 + j * 19));
        column.* = .{ .values = values, .log_size = log, .original_index = i };
        allocated += 1;
    }
    var rejected = Tree.StreamingCommitter.init(a);
    defer rejected.deinit();
    try std.testing.expectError(error.PrefixStateBudgetTooSmall, rejected.commitColumnsWithReusedBoundedPrefix(&columns, 0, null));
    var reference_builder = Tree.StreamingCommitter.init(a);
    defer reference_builder.deinit();
    var reference = try reference_builder.commitColumnsWithBoundedPrefix(&columns, 2 * @sizeOf(H), null);
    defer reference.deinit(a);
    // Successful commit invalidates its builder, which must not be deinitialized.
    reference_builder = Tree.StreamingCommitter.init(a);
    for ([_]usize{ 1, 3 }) |count| {
        var pool: workers.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = count });
        defer pool.deinit();
        var binding = try workers.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        for ([_]usize{ 2, 8, 64, 8192 }) |cap| {
            var builder = Tree.StreamingCommitter.init(a);
            errdefer builder.deinit();
            var stats: Tree.BoundedPrefixStats = .{};
            var actual = try builder.commitColumnsWithReusedBoundedPrefix(&columns, cap * @sizeOf(H), &stats);
            builder = Tree.StreamingCommitter.init(a);
            defer actual.deinit(a);
            try std.testing.expectEqual(reference.layers.len, actual.layers.len);
            for (reference.layers, actual.layers) |expected, got| try std.testing.expectEqualSlices(H.Hash, expected, got);
            try std.testing.expect(stats.prefix_state_bytes <= @max(cap, 2) * @sizeOf(H));
            try std.testing.expect(stats.tail_absorptions <= stats.tail_column_count * 8192);
            if (count == 1) try std.testing.expectEqual(@as(usize, 0), stats.repeated_tail_absorptions);
        }
    }
}
