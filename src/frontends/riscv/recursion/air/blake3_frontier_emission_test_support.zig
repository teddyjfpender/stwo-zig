//! Focused final-layout and capture-discovery checks for the shared frontier.
const std = @import("std");
const core = @import("stwo_core");
const frontier = @import("blake3_two_level_frontier.zig");
const group = @import("blake3_merkle_group_witness.zig");
const M = core.fields.m31.M31;
const Digest = [32]u8;
pub fn columns(a: std.mem.Allocator) !void {
    const context = frontier.Context{ .plan = .{ .namespace = 1000, .queries = 3, .root_source = .{ .circuit = 800, .first_wire = 0 } }, .witness = .{ .inputs = .{ .{ @splat(17), @splat(29) }, .{ @splat(37), @splat(43) } }, .opaque_digests = .{ @splat(53), @splat(61) }, .active = .{ 1, 0 } } };
    var full = try frontier.prepare(a, context.plan, context.witness);
    defer full.deinit();
    const counts = @import("../blake3_native_hash_layout.zig").Counts{ .g = full.g_rows.len, .xor = full.xor_rows.len };
    const prefix = @import("../blake3_native_hash_layout.zig").Counts{ .g = 13, .xor = 5 };
    const total = @import("../blake3_native_hash_layout.zig").Counts{ .g = counts.g + prefix.g, .xor = counts.xor + prefix.xor };
    var owner = try @import("../blake3_native_hash_columns.zig").Owner.init(a, .{ .transcript = prefix, .paths = counts, .total = total, .logs = .{ std.math.log2_int_ceil(usize, total.g), std.math.log2_int_ceil(usize, total.xor) } });
    defer owner.deinit();
    var compact = try frontier.emit(a, context, true, null, try owner.paths());
    defer compact.deinit();
    try std.testing.expectEqual(full.root, compact.root);
    try std.testing.expectEqual(@as(usize, 0), compact.g_rows.len + compact.xor_rows.len);
    var metadata = try @import("blake3_hash_metadata.zig").Rows.allocate(a, counts.g, counts.xor);
    defer metadata.free(a);
    var trusted = try frontier.emit(a, context, false, .{ .fixed = metadata }, null);
    defer trusted.deinit();
    inline for (.{ group.g, group.xor }, .{ full.g_rows, full.xor_rows }, .{ metadata.g_rows, metadata.xor_rows }, .{ prefix.g, prefix.xor }, 0..) |Air, rows, fixed, start, cohort| {
        for (rows, fixed, 0..) |row, tail, i| {
            try std.testing.expectEqualSlices(M, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], &tail);
            for (owner.main[cohort], 0..) |column, c| try std.testing.expectEqual(row[c], column.values[@import("framework_interaction.zig").committedRow(start + i, column.log_size)]);
        }
        for (owner.main[cohort]) |column| for (0..start) |i| try std.testing.expect(column.values[@import("framework_interaction.zig").committedRow(i, column.log_size)].isZero());
    }
}
fn node(left: Digest, right: Digest) Digest {
    return (core.channel.blake3.Frame{ .node = .{ .left = left, .right = right } }).hash();
}
pub fn capture(a: std.mem.Allocator) !void {
    const discovery = @import("blake3_frontier_capture.zig");
    const directions = [_]group.select.Endpoint{ .{ .circuit = 700, .wire = 0 }, .{ .circuit = 700, .wire = 1 } };
    for ([_]u32{ 1, 2 }) |leaves| {
        const values = try a.alloc(M, 4 * leaves * 2);
        for (values, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i + 17));
        var roots: [4]Digest = undefined;
        for (&roots, 0..) |*root, i| {
            var leaf_hashes: [2]Digest = undefined;
            for (0..leaves) |l| leaf_hashes[l] = (core.channel.blake3.Frame{ .leaf = values[(i * leaves + l) * 2 ..][0..2] }).hash();
            root.* = if (leaves == 1) leaf_hashes[0] else node(leaf_hashes[0], leaf_hashes[1]);
        }
        const upper = [2]Digest{ node(roots[0], roots[1]), node(roots[2], roots[3]) };
        const root = node(upper[0], upper[1]);
        const paths = [2][2]Digest{ .{ roots[1], upper[1] }, .{ roots[2], upper[0] } };
        const plan = frontier.Plan{ .namespace = 1000, .queries = 2, .root_source = .{ .circuit = 800, .first_wire = 0 } };
        var openings = [2]discovery.Opening{
            .{ .leaves = leaves, .words = 2, .index = 0, .values = values[0 .. leaves * 2], .siblings = &paths[0], .directions = &directions },
            .{ .leaves = leaves, .words = 2, .index = 3, .values = values[3 * leaves * 2 ..], .siblings = &paths[1], .directions = &directions },
        };
        const both = try discovery.collect(a, plan, &openings, root);
        try std.testing.expectEqual([2]u1{ 1, 1 }, both.witness.active);
        try std.testing.expectEqual([2][2]Digest{ .{ roots[0], roots[1] }, .{ roots[2], roots[3] } }, both.witness.inputs);
        var prepared = try frontier.prepare(a, plan, both.witness);
        defer prepared.deinit();
        try std.testing.expectEqual(root, prepared.root);
        openings[1] = openings[0];
        const one = try discovery.collect(a, plan, &openings, root);
        try std.testing.expectEqual([2]u1{ 1, 0 }, one.witness.active);
        var single = try frontier.prepare(a, plan, one.witness);
        defer single.deinit();
        try std.testing.expectEqual(root, single.root);
        var bad = root;
        bad[0] ^= 1;
        try std.testing.expectError(error.InvalidFrontierCapture, discovery.collect(a, plan, &openings, bad));
    }
}
