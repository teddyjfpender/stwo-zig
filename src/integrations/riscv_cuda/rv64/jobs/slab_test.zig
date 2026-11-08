const std = @import("std");
const S = @import("slab.zig");
const api = @import("api.zig");

test "layout assigns dense offsets in insertion order and rejects duplicates" {
    var l: S.ProofLayout = .{};
    try std.testing.expectEqual(@as(usize, 0), try l.add(.root, 0, 8));
    try std.testing.expectEqual(@as(usize, 8), try l.add(.root, 1, 8));
    try std.testing.expectEqual(@as(usize, 16), try l.add(.pow_nonce, 0, 2));
    try std.testing.expectError(error.DuplicateProofField, l.add(.root, 1, 8));
    try std.testing.expectEqual(@as(usize, 18), l.words);
    var words: [32]u32 = undefined;
    for (&words, 0..) |*w, i| w.* = @intCast(i);
    var slab = S.ProofSlab{ .device = .{ .ptr = &words, .words = 32 } };
    try slab.bind(&l);
    const r1 = try slab.field(.root, 1);
    try std.testing.expectEqual(@as(u32, 8), r1.ptr[0]);
    const view = api.SlabView{ .words = &words, .layout = &l };
    try std.testing.expectEqualSlices(u32, &.{ 16, 17 }, try S.read(view, .pow_nonce, 0));
    const bytes = try S.encodePhysical(std.testing.allocator, &l, &words);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, 72), bytes.len);
    try std.testing.expectEqual(@as(u32, 17), std.mem.readInt(u32, bytes[68..72], .little));
}

test "PCS layout reproduces today's readback plane order and sizes" {
    const traces = [_]S.PcsGeometry.Trace{ .{ .columns = 3, .log = 5 }, .{ .columns = 2, .log = 4 } };
    const fri = [_]S.PcsGeometry.FriLayer{ .{ .count = 32, .steps = 1, .leaf = 0 }, .{ .count = 16, .steps = 1, .leaf = 0 } };
    const g = S.PcsGeometry{ .source_count = 5, .term_count = 7, .group_count = 2, .source_group_count = 2, .sample_count = 6, .log = 5, .queries = 4, .degree = 2, .last_layer_log = 2, .traces = &traces, .fri = &fri };
    const l = try g.layout();
    const order = [_]S.Kind{ .status, .channel_state, .root, .root, .sampled_values, .pow_nonce, .fri_last_layer, .query_positions, .fri_root, .fri_values, .fri_paths, .fri_root, .fri_values, .fri_paths, .trace_values, .trace_paths, .trace_values, .trace_paths };
    try std.testing.expectEqual(order.len, l.count);
    for (order, l.slice()) |k, f| try std.testing.expectEqual(k, f.kind);
    // pcs_pipeline.cuh: s.value_words = (q << steps) * 8, s.path_words = (q << (steps-leaf)) * (ctz(count)-leaf) * 8
    try std.testing.expectEqual(@as(usize, (4 << 1) * 8), (try l.get(.fri_values, 0)).words);
    try std.testing.expectEqual(@as(usize, (4 << 1) * 5 * 8), (try l.get(.fri_paths, 0)).words);
    try std.testing.expectEqual(@as(usize, (4 << 1) * 4 * 8), (try l.get(.fri_paths, 1)).words);
    try std.testing.expectEqual(@as(usize, 3 * 4), (try l.get(.trace_values, 0)).words);
    try std.testing.expectEqual(@as(usize, 4 * 4 * 8), (try l.get(.trace_paths, 1)).words);
    const slab = try std.testing.allocator.alloc(u32, l.words);
    defer std.testing.allocator.free(slab);
    for (slab, 0..) |*w, i| w.* = @intCast(i * 3);
    const result = try S.encodePcsResult(std.testing.allocator, g, &l, slab, 41);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualSlices(u32, &.{ 0x52564d4f, 2, 0, 5, 7, 2, 2, 2, 6, 2, 5, 4, 2, 41 }, result[0..14]);
    try std.testing.expectEqualSlices(u32, slab, result[14..]);
}
