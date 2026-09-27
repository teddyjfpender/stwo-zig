//! Canonical sparse path topology. Coordinates come from caller-admitted leaf
//! addresses, never proof-provided edges. Hash/AIR emission remains a caller duty.
const std = @import("std");
pub const DEPTH: u32 = 30;
pub const Coordinate = struct { level: u32, index: u32 };
pub const Child = union(enum) { computed: usize, frontier: usize };
pub const Node = struct {
    coordinate: Coordinate,
    source: union(enum) { leaf: usize, children: [2]Child },
};
pub const Graph = struct {
    allocator: std.mem.Allocator,
    nodes: []Node,
    frontier: []Coordinate,
    leaf_count: usize,
    pub fn deinit(self: *Graph) void {
        self.allocator.free(self.nodes);
        self.allocator.free(self.frontier);
        self.* = undefined;
    }
    pub fn compressionCount(self: Graph) !usize {
        return std.math.add(usize, self.leaf_count, try std.math.mul(usize, 2, self.nodes.len - self.leaf_count));
    }
    pub fn init(a: std.mem.Allocator, addresses: []const u32) !Graph {
        if (addresses.len == 0) return error.EmptySharedPath;
        for (addresses, 0..) |address, i| {
            if (address >= (@as(u32, 1) << DEPTH) or (i != 0 and addresses[i - 1] >= address)) return error.InvalidSharedPathAddresses;
        }
        var nodes: std.ArrayList(Node) = .empty;
        defer nodes.deinit(a);
        var frontier: std.ArrayList(Coordinate) = .empty;
        defer frontier.deinit(a);
        for (addresses, 0..) |address, i| try nodes.append(a, .{ .coordinate = .{ .level = 0, .index = address }, .source = .{ .leaf = i } });
        var begin: usize = 0;
        var end: usize = nodes.items.len;
        for (1..DEPTH + 1) |level| {
            var current = begin;
            while (current < end) {
                const parent = nodes.items[current].coordinate.index >> 1;
                var children: [2]Child = undefined;
                for (&children, 0..) |*child, side| {
                    const index = parent * 2 + @as(u32, @intCast(side));
                    if (current < end and nodes.items[current].coordinate.index == index) {
                        child.* = .{ .computed = current };
                        current += 1;
                    } else {
                        child.* = .{ .frontier = frontier.items.len };
                        try frontier.append(a, .{ .level = @intCast(level - 1), .index = index });
                    }
                }
                try nodes.append(a, .{ .coordinate = .{ .level = @intCast(level), .index = parent }, .source = .{ .children = children } });
            }
            begin = end;
            end = nodes.items.len;
        }
        std.debug.assert(end - begin == 1 and nodes.items[begin].coordinate.index == 0);
        const owned_nodes = try nodes.toOwnedSlice(a);
        errdefer a.free(owned_nodes);
        return .{ .allocator = a, .nodes = owned_nodes, .frontier = try frontier.toOwnedSlice(a), .leaf_count = addresses.len };
    }
};

test "shared path topology folds adjacent leaves and authenticates every edge coordinate" {
    var graph = try Graph.init(std.testing.allocator, &.{ 0, 1, 2, 3 });
    defer graph.deinit();
    try std.testing.expectEqual(@as(usize, 35), graph.nodes.len);
    try std.testing.expectEqual(@as(usize, 28), graph.frontier.len);
    try std.testing.expectEqual(@as(usize, 66), try graph.compressionCount());
    for (graph.nodes, 0..) |node, at| switch (node.source) {
        .leaf => |source| try std.testing.expectEqual(@as(u32, @intCast(source)), node.coordinate.index),
        .children => |children| for (children, 0..) |child, side| {
            const coordinate = switch (child) {
                .computed => |index| blk: {
                    try std.testing.expect(index < at);
                    break :blk graph.nodes[index].coordinate;
                },
                .frontier => |index| graph.frontier[index],
            };
            try std.testing.expectEqual(node.coordinate.level - 1, coordinate.level);
            try std.testing.expectEqual(node.coordinate.index * 2 + @as(u32, @intCast(side)), coordinate.index);
        },
    };
}
fn allocationCase(a: std.mem.Allocator) !void {
    var graph = try Graph.init(a, &.{ 0, 3, 17, (1 << DEPTH) - 1 });
    defer graph.deinit();
}
test "shared path topology rejects ambiguous inputs and cleans allocation failures" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.EmptySharedPath, Graph.init(a, &.{}));
    try std.testing.expectError(error.InvalidSharedPathAddresses, Graph.init(a, &.{ 1, 1 }));
    try std.testing.expectError(error.InvalidSharedPathAddresses, Graph.init(a, &.{ 3, 2 }));
    try std.testing.expectError(error.InvalidSharedPathAddresses, Graph.init(a, &.{1 << DEPTH}));
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}
