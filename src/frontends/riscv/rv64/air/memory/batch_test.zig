const std = @import("std");
const a = std.testing.allocator;
const batch = @import("batch.zig");
const values = @import("values.zig");
const graph = @import("graph_model.zig");
fn verifyGraph(witness: *const batch.Witness) !void {
    const before = try a.alloc(graph.Node, witness.before_nodes.len);
    defer a.free(before);
    const after = try a.alloc(graph.Node, witness.after_nodes.len);
    defer a.free(after);
    const leaves = try a.alloc(graph.Leaf, witness.leaves.len);
    defer a.free(leaves);
    for (before, witness.before_nodes) |*out, node| out.* = node.graph;
    for (after, witness.after_nodes) |*out, node| out.* = node.graph;
    for (leaves, witness.leaves) |*out, leaf| out.* = leaf.graph;
    try graph.verify(a, witness.geometry.depth(), witness.before, witness.after, before, after, leaves, witness.sides);
}
test "RV64 private frontier: shared changed paths read-only reuse and high addresses preserve authenticated roots" {
    var before_words: [3][64]u64 = @splat(@splat(0));
    before_words[0][7] = 19;
    before_words[1][63] = std.math.maxInt(u64);
    before_words[2][1] = 31;
    var after_words = before_words;
    after_words[0][7] = 23;
    after_words[2][1] = 0;
    const indices = [_]u64{ 1, 2, (@as(u64, 1) << 55) - 1 };
    var entries: [3]values.Entry = undefined;
    for (&entries, indices, before_words) |*entry, index, words| entry.* = .{ .index = index, .digest = try values.hashValues(.chunk512, &words, null) };
    var cache = try values.Cache.fromEntries(a, .chunk512, &entries);
    defer cache.deinit();
    const initial = cache.root();
    var clocks: [3][64]u32 = @splat(@splat(0));
    clocks[0][7] = 4;
    clocks[1][63] = 8;
    clocks[2][1] = 12;
    const rights: [64]u2 = @splat(3);
    var openings: [3]batch.Opening = undefined;
    for (&openings, indices, &before_words, &after_words, &clocks) |*opening, index, *before, *after, *clock| opening.* = .{ .index = index, .before = before, .after = after, .terminal_clocks = clock, .rights = &rights };
    const counts = try batch.count(a, .chunk512, &openings);
    var recorder = values.Recorder{ .allocator = a };
    defer recorder.deinit();
    var witness = try batch.Witness.init(a, &cache, &openings, &recorder);
    defer witness.deinit();
    try verifyGraph(&witness);
    try std.testing.expect(values.equal(initial, cache.root()));
    try std.testing.expectEqual(try counts.permutations(.chunk512), recorder.calls.items.len);
    try std.testing.expect(counts.before_nodes < 3 * 55);
    try witness.publish(&cache);
    entries[0].digest = try values.hashValues(.chunk512, &after_words[0], null);
    var expected = try values.Cache.fromEntries(a, .chunk512, entries[0..2]);
    defer expected.deinit();
    try std.testing.expect(values.equal(expected.root(), cache.root()));
    try std.testing.expectError(error.PrivateRamBeforeRootMismatch, witness.publish(&cache));
    // Pure reads keep the actual before root while proving all touched openings.
    openings[0].before = &after_words[0];
    openings[0].after = &after_words[0];
    var reads = values.Recorder{ .allocator = a };
    defer reads.deinit();
    var read_witness = try batch.Witness.init(a, &cache, openings[0..2], &reads);
    defer read_witness.deinit();
    try verifyGraph(&read_witness);
    try std.testing.expectEqual(@as(usize, 0), read_witness.after_nodes.len);
    try std.testing.expectEqual(@as(usize, 0), read_witness.patches.len);
    try std.testing.expect(values.equal(read_witness.before, read_witness.after));
}
fn failure(allocator: std.mem.Allocator, cache: *const values.Cache, openings: []const batch.Opening) !void {
    var recorder = values.Recorder{ .allocator = allocator };
    defer recorder.deinit();
    var witness = try batch.Witness.init(allocator, cache, openings, &recorder);
    defer witness.deinit();
}
test "RV64 private frontier: every construction allocation failure preserves prior sparse state" {
    var cache = try values.Cache.empty(a, .chunk512);
    defer cache.deinit();
    const initial = cache.root();
    const before: [64]u64 = @splat(0);
    var after = before;
    after[0] = 9;
    var clocks: [64]u32 = @splat(0);
    clocks[0] = 4;
    const rights: [64]u2 = @splat(3);
    const openings = [_]batch.Opening{.{ .index = 1, .before = &before, .after = &after, .terminal_clocks = &clocks, .rights = &rights }};
    try std.testing.checkAllAllocationFailures(a, failure, .{ &cache, &openings });
    try std.testing.expect(values.equal(initial, cache.root()));
    try std.testing.expectEqual(@as(usize, 0), cache.count());
    const duplicates = [_]batch.Opening{ openings[0], openings[0] };
    try std.testing.expectError(error.InvalidPrivateRamBatch, batch.count(a, .chunk512, &duplicates));
    clocks[0] = 0;
    try std.testing.expectError(error.InvalidPrivateRamBatch, batch.count(a, .chunk512, &openings));
}
