const std = @import("std");
const F = @import("fixture.zig");
const E = @import("execution.zig");
const Store = @import("../retained_main_store.zig").Store;
const a = std.testing.allocator;
test "mapped native2n CPU evaluations preserve all five proofs and shared closure with compact truths" {
    var expected = try F.Case.init(a);
    defer expected.deinit();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.init(path, 256 << 20);
    defer store.deinit();
    for ([_]u8{ 1, 2 }) |lanes| {
        var captured = try F.Captured.init(a);
        defer captured.deinit();
        var candidate = try E.produceWithOptions(a, &expected.keys(), &expected.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected.expected(), .{ .retained_main = &store, .retained_cpu_lde = true, .schedule = .{ .lanes = lanes, .workers_per_lane = 2 }, .consume_memory_events = true });
        defer candidate.deinit(a);
        try E.verify(a, &expected.keys(), &expected.truths(), expected.expected(), &candidate);
        try std.testing.expectEqualDeep(expected.bundle.manifest.digest, candidate.manifest.digest);
        for (expected.bundle.cpus, candidate.cpus) |x, y| {
            try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
            try std.testing.expectEqualDeep(x.claims, y.claims);
        }
        for (expected.bundle.truths, candidate.truths) |x, y| {
            try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
            try std.testing.expectEqualDeep(x.claims, y.claims);
        }
        try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    }
    try std.testing.expect(store.stats().total_bytes > 0);
    var files = tmp.dir.iterate();
    try std.testing.expectEqual(null, try files.next());
}
test "partial mapped evaluation budget failure joins both lanes and releases every retained column" {
    var expected = try F.Case.init(a);
    defer expected.deinit();
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.init(path, 4 * std.heap.pageSize());
    defer store.deinit();
    try std.testing.expectError(error.OutOfMemory, E.produceWithOptions(a, &expected.keys(), &expected.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected.expected(), .{ .retained_main = &store, .retained_cpu_lde = true, .schedule = .{ .lanes = 2, .workers_per_lane = 2 } }));
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expect(store.stats().total_bytes > 0);
}

test "foreign retained allocators reject before reading undefined allocator contexts or tree fields" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.init(path, 65536);
    defer store.deinit();
    for ([_]std.mem.Allocator{ std.heap.page_allocator, std.heap.smp_allocator }) |allocator| {
        // These allocators intentionally have undefined contexts. The rest of
        // the unsupported tree is also uninitialized and must remain unread.
        var tree: @import("../protocol.zig").T.Scheme.CommittedTree = undefined;
        tree.retained_column_allocator = allocator;
        try std.testing.expectError(error.UnsupportedRetainedMainTree, store.retireEvaluations(&tree));
    }
}
