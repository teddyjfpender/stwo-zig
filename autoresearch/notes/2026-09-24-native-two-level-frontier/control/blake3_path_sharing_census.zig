//! Read-only topology census. Equal node positions are candidates, not permission
//! to remove constraints: shared inputs and every query route must still be proved.
const std = @import("std");
const core = @import("stwo_core");
pub const Counts = struct {
    openings: usize,
    unique_groups: usize,
    upper_hashes: usize,
    unique_upper_hashes: usize,
};
pub fn inspect(a: std.mem.Allocator, positions: []const usize, depth: u32, group_shift: u32) !Counts {
    if (depth > 31 or group_shift > 31 or depth + group_shift > @bitSizeOf(usize)) return error.InvalidPathCensusGeometry;
    var groups = std.AutoHashMap(usize, void).init(a);
    defer groups.deinit();
    var nodes = std.AutoHashMap(u64, void).init(a);
    defer nodes.deinit();
    for (positions) |position| {
        const index = position >> @intCast(group_shift);
        if (index >= @as(usize, 1) << @intCast(depth)) return error.InvalidPathCensusGeometry;
        try groups.put(index, {});
        for (0..depth) |level| {
            const parent = index >> @intCast(level + 1);
            // Different heights remain distinct even when their index is zero.
            try nodes.put((@as(u64, @intCast(level)) << 32) | @as(u64, @intCast(parent)), {});
        }
    }
    return .{ .openings = positions.len, .unique_groups = groups.count(), .upper_hashes = try std.math.mul(usize, positions.len, depth), .unique_upper_hashes = nodes.count() };
}
pub fn report(a: std.mem.Allocator, capture: anytype, path_g_rows: usize, shared_root_g_rows: usize) !void {
    var total: usize = 0;
    var unique: usize = 0;
    // Reset the census for every authenticated tree; never merge by digest alone.
    for (capture.trace_paths, 0..) |path, i| {
        const counts = try inspect(a, path.positions, path.path_depth, 0);
        print("trace", i, path.path_depth, counts);
        total += counts.upper_hashes;
        unique += counts.unique_upper_hashes;
    }
    for (capture.fri.layers, 0..) |layer, i| {
        const counts = try inspect(a, layer.positions, layer.path_depth, layer.fold_step);
        print("fri", i, layer.path_depth, counts);
        total += counts.upper_hashes;
        unique += counts.unique_upper_hashes;
    }
    const len = try (core.channel.blake3.Frame{ .node = .{ .left = @splat(0), .right = @splat(0) } }).encodedSize();
    var plan = try @import("blake3_hash_plan.zig").build(a, len);
    defer plan.deinit();
    const gross = try std.math.mul(usize, total - unique, plan.g.len);
    std.debug.print("BLAKE3_PATH_SHARING_TOTAL upper_hashes={d} unique_upper_hashes={d} node_g_rows={d} gross_candidate_g_rows={d} path_g_rows={d} shared_root_g_rows={d} remaining_sharing_implemented=false\n", .{ total, unique, plan.g.len, try std.math.sub(usize, gross, shared_root_g_rows), path_g_rows, shared_root_g_rows });
}
fn print(kind: []const u8, tree: usize, depth: u32, c: Counts) void {
    std.debug.print("BLAKE3_PATH_SHARING kind={s} tree={d} depth={d} openings={d} unique_groups={d} upper_hashes={d} unique_upper_hashes={d}\n", .{ kind, tree, depth, c.openings, c.unique_groups, c.upper_hashes, c.unique_upper_hashes });
}
test "PCS fusion path census separates heights and counts duplicate groups" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(Counts{ .openings = 4, .unique_groups = 4, .upper_hashes = 12, .unique_upper_hashes = 6 }, try inspect(a, &.{ 0, 1, 2, 7 }, 3, 0));
    try std.testing.expectEqual(Counts{ .openings = 2, .unique_groups = 1, .upper_hashes = 6, .unique_upper_hashes = 3 }, try inspect(a, &.{ 0, 0 }, 3, 0));
    try std.testing.expectEqual(Counts{ .openings = 4, .unique_groups = 2, .upper_hashes = 8, .unique_upper_hashes = 2 }, try inspect(a, &.{ 0, 1, 4, 7 }, 2, 2));
    try std.testing.expectEqual(Counts{ .openings = 2, .unique_groups = 1, .upper_hashes = 0, .unique_upper_hashes = 0 }, try inspect(a, &.{ 0, 0 }, 0, 0));
    try std.testing.expectEqual(@as(usize, 0), (try inspect(a, &.{}, 3, 0)).unique_upper_hashes);
    try std.testing.expectError(error.InvalidPathCensusGeometry, inspect(a, &.{8}, 3, 0));
    try std.testing.expectError(error.InvalidPathCensusGeometry, inspect(a, &.{}, 32, 0));
}
