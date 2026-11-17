//! Recorded-node association for the piece-only parity harness. The parent
//! seed tape and each child's PCS root pair are the only association inputs.
const std = @import("std");
pub const Node = struct { ordinal: u32, roots: [16]u32 };

pub fn fromSeeds(a: std.mem.Allocator, seeds: []const u32, nodes: []const Node, parent: u32, max_children: usize) ![]u32 {
    if (seeds.len % 5 != 0) return error.InvalidRecordedSeedShape;
    var children: std.ArrayList(u32) = .empty;
    errdefer children.deinit(a);
    var at: usize = 0;
    while (at + 32 <= seeds.len / 5) : (at += 1) {
        var matched: ?u32 = null;
        for (nodes) |node| {
            if (node.ordinal >= parent) continue;
            var same = true;
            for (node.roots, 0..) |word, i| {
                if (seeds[5 * (at + 2 * i) + 1] != word & 0xffff or
                    seeds[5 * (at + 2 * i + 1) + 1] != word >> 16)
                {
                    same = false;
                    break;
                }
            }
            if (!same) continue;
            if (matched != null) return error.AmbiguousRecordedChild;
            matched = node.ordinal;
        }
        if (matched) |ordinal| {
            if (std.mem.indexOfScalar(u32, children.items, ordinal) != null) return error.DuplicateRecordedChild;
            if (children.items.len == max_children) return error.TooManyRecordedChildren;
            try children.append(a, ordinal);
        }
    }
    if (children.items.len == 0) return error.MissingRecordedChildren;
    return children.toOwnedSlice(a);
}

fn rootSeeds(roots: [16]u32) [32 * 5]u32 {
    var out: [32 * 5]u32 = @splat(0);
    for (roots, 0..) |word, i| {
        out[5 * (2 * i) + 1] = word & 0xffff;
        out[5 * (2 * i + 1) + 1] = word >> 16;
    }
    return out;
}

test "recorded association follows seed order rather than directory order" {
    const a = std.testing.allocator;
    const nodes = [_]Node{ .{ .ordinal = 3, .roots = @splat(0xffff4321) }, .{ .ordinal = 1, .roots = @splat(0x1234abcd) } };
    const seeds = rootSeeds(nodes[1].roots) ++ rootSeeds(nodes[0].roots);
    const children = try fromSeeds(a, &seeds, &nodes, 4, 8);
    defer a.free(children);
    try std.testing.expectEqualSlices(u32, &.{ 1, 3 }, children);
    try std.testing.expectError(error.TooManyRecordedChildren, fromSeeds(a, &seeds, &nodes, 4, 1));
    try std.testing.checkAllAllocationFailures(a, struct {
        fn run(alloc: std.mem.Allocator, s: []const u32, ns: []const Node) !void {
            const owned = try fromSeeds(alloc, s, ns, 4, 8);
            defer alloc.free(owned);
        }
    }.run, .{ &seeds, &nodes });
}

test "recorded association refuses ambiguous missing duplicate and malformed sources" {
    const a = std.testing.allocator;
    const nodes = [_]Node{ .{ .ordinal = 1, .roots = @splat(0x1234abcd) }, .{ .ordinal = 2, .roots = @splat(0x1234abcd) } };
    const seeds = rootSeeds(nodes[0].roots);
    try std.testing.expectError(error.AmbiguousRecordedChild, fromSeeds(a, &seeds, &nodes, 3, 8));
    try std.testing.expectError(error.MissingRecordedChildren, fromSeeds(a, &seeds, &nodes, 1, 8));
    try std.testing.expectError(error.MissingRecordedChildren, fromSeeds(a, &seeds, &.{}, 3, 8));
    try std.testing.expectError(error.InvalidRecordedSeedShape, fromSeeds(a, seeds[0 .. seeds.len - 1], &nodes, 3, 8));
    const repeated = seeds ++ seeds;
    try std.testing.expectError(error.DuplicateRecordedChild, fromSeeds(a, &repeated, nodes[0..1], 3, 8));
    var changed = seeds;
    changed[1] ^= 1;
    try std.testing.expectError(error.MissingRecordedChildren, fromSeeds(a, &changed, nodes[0..1], 3, 8));
}
