const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const Family = @import("combined_setup_family.zig").ForCoordinates;
const Pools = @import("../../work_pool.zig");
const a = std.testing.allocator;
fn check(comptime D: usize, allocator: std.mem.Allocator, n: usize) !void {
    const View = struct { coordinates: [D][]M };
    const C = Family(D, View);
    const sizes = [_]usize{ n, n, n / 2, n };
    var views: [4]View = undefined;
    var rows: usize = 0;
    var coords: usize = 0;
    defer for (views[0..rows]) |view| for (view.coordinates) |column| allocator.free(column);
    errdefer if (rows < views.len) {
        for (views[rows].coordinates[0..coords]) |column| allocator.free(column);
    };
    for (&views, sizes) |*view, size| {
        coords = 0;
        for (&view.coordinates) |*column| {
            column.* = try allocator.alloc(M, size);
            @memset(column.*, M.fromCanonical(99));
            coords += 1;
        }
        rows += 1;
    }
    var sources: [12][]M = undefined;
    var done: usize = 0;
    defer for (sources[0..done]) |source| allocator.free(source);
    var members: [12]C.Member = undefined;
    for (&sources, &members, 0..) |*source, *member, i| {
        const view: usize = if (i < 4) 0 else if (i < 6) 1 else if (i == 6) 0 else if (i < 11) 2 else 1;
        const size = if (i == 5) n / 2 else if (i == 6) n / 3 else if (i == 11) 0 else sizes[view];
        source.* = try allocator.alloc(M, size);
        done += 1;
        for (source.*, 0..) |*v, j| v.* = if (i < 4) M.one().neg() else M.fromCanonical(@intCast((i * 7919 + j * 977) % 1048573));
        var cs: [D]M = undefined;
        for (&cs, 0..) |*c, j| c.* = if (i < 4) M.one().neg() else if (j % 3 == 0) M.zero() else M.fromCanonical(@intCast((j * 7919 + i * 977) % 1048573));
        member.* = .{ .source = source.*, .coefficients = cs, .view_index = view };
    }
    try C.combine(allocator, &views, &members);
    for (views, 0..) |view, vi| {
        for (view.coordinates, 0..) |column, c| for (column, 0..) |value, row| {
            var expected = if (vi == 3) M.fromCanonical(99) else M.zero();
            for (members) |member| if (member.view_index == vi and row < member.source.len) {
                expected = expected.add(member.source[row].mul(member.coefficients[c]));
            };
            try std.testing.expectEqualDeep(expected, value);
        };
    }
}
fn lifecycle(allocator: std.mem.Allocator) !void {
    try check(8, allocator, 33);
}
test "DEEP dot4 combined coordinates match scalar authority for Q OM partial mixed views empty members and tails" {
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    inline for (.{ 4, 8 }) |d| for ([_]usize{ 1, 3, 4, 7, 17, 1031 }) |n| try check(d, a, n);
    try std.testing.checkAllAllocationFailures(a, lifecycle, .{});
}
test "DEEP dot4 combination has disjoint pooled rows across full and partial chunks" {
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try check(4, a, 16391);
    try check(8, a, 16391);
}
