//! Independent canonical ordering and allocation-failure custody for gathering.
const std = @import("std");
const inputs = @import("gathered_inputs.zig");
const plans = @import("../proof_plan.zig");
const pools = @import("pool_split.zig").work_pool;

test "Cairo witness final storage gather preserves full packs, multi-producer remainders and selectors" {
    const allocator = std.testing.allocator;
    const width = 11;
    const active = [_]u32{ 17, 33, 15 };
    const instances = [_]u32{ 2, 3, 1 };
    const names = [_][]const u8{ "a", "b", "c" };
    var producers: [3]inputs.Producer = undefined;
    var edges: [3]plans.ProducerEdge = undefined;
    var words: [3][33 * width * 3]u32 = undefined;
    for (&producers, &edges, 0..) |*producer, *edge, source| {
        const stride = width * instances[source];
        for (0..active[source]) |row| for (0..instances[source]) |instance| for (0..width) |word| {
            words[source][row * stride + instance * width + word] = @intCast(source * 10000 + instance * 1000 + row * 100 + word);
        };
        producer.* = .{ .label = names[source], .row_count = active[source], .active_rows = active[source], .words_per_row = stride, .words = words[source][0 .. active[source] * stride] };
        edge.* = .{ .producer = names[source], .word_base = 0, .words_per_instance = width, .instances = instances[source] };
    }
    // Oracle row map: complete packs from A then B, followed by each
    // producer's real tail. It intentionally uses row maps rather than the
    // production algorithm's column traversal.
    var expected = std.ArrayList(u32).empty;
    defer expected.deinit(allocator);
    for (0..3) |source| for (0..instances[source]) |instance| for (0..active[source] / 16 * 16) |row| {
        try expected.append(allocator, @intCast(source * 10000 + instance * 1000 + row * 100));
    };
    const remainder_start = expected.items.len;
    for (0..3) |source| for (0..instances[source]) |instance| for (active[source] / 16 * 16..active[source]) |row| {
        try expected.append(allocator, @intCast(source * 10000 + instance * 1000 + row * 100));
    };
    const real_rows = expected.items.len;
    while (expected.items.len % 16 != 0) try expected.append(allocator, expected.items[remainder_start]);
    while (expected.items.len < 256) try expected.append(allocator, expected.items[expected.items.len & 15]);

    for ([_]usize{ 1, 2, 7 }) |worker_count| {
        var pool: pools.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = worker_count });
        defer pool.deinit();
        var binding = try pools.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var gathered = try inputs.materializeDerived(allocator, &edges, &producers);
        defer gathered.deinit();
        for (0..width) |word| {
            const column = try gathered.borrowColumn(word);
            for (expected.items, column) |value, actual| try std.testing.expectEqual(value + word, actual);
        }
        const selector = try gathered.borrowColumn(width);
        for (selector, 0..) |actual, row| try std.testing.expectEqual(@as(u32, @intFromBool(row < real_rows)), actual);
    }
}

test "Cairo witness final storage large gather matches serial ordering with joined column workers" {
    const allocator = std.testing.allocator;
    const rows = 8193;
    const width = 11;
    const words = try allocator.alloc(u32, rows * width * 2);
    defer allocator.free(words);
    for (words, 0..) |*word, index| word.* = @intCast(index);
    const edges = [_]plans.ProducerEdge{.{ .producer = "a", .word_base = 0, .words_per_instance = width, .instances = 2 }};
    const producers = [_]inputs.Producer{.{ .label = "a", .row_count = rows, .active_rows = rows, .words_per_row = width * 2, .words = words }};
    var serial = try inputs.materializeDerived(allocator, &edges, &producers);
    defer serial.deinit();
    for ([_]usize{ 2, 7 }) |worker_count| {
        var pool: pools.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = worker_count });
        defer pool.deinit();
        var binding = try pools.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var parallel = try inputs.materializeDerived(allocator, &edges, &producers);
        defer parallel.deinit();
        try std.testing.expectEqualSlices(u32, serial.storage, parallel.storage);
    }
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    const words = [_]u32{ 1, 2, 3, 4 };
    const edges = [_]plans.ProducerEdge{.{ .producer = "a", .word_base = 0, .words_per_instance = 1, .instances = 2 }};
    const producers = [_]inputs.Producer{.{ .label = "a", .row_count = 2, .active_rows = 2, .words_per_row = 2, .words = &words }};
    var gathered = try inputs.materializeDerived(allocator, &edges, &producers);
    defer gathered.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 1, 3, 2, 4 }, (try gathered.borrowColumn(0))[0..4]);
}

test "Cairo witness final storage gather releases output slabs when source admission allocation fails" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}
