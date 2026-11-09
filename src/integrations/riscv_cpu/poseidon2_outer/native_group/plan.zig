//! Receiver-owned grouping topology. Group only complete aligned subtrees;
//! preserve the original odd-carry binary digest and exact inventory coverage.
const std = @import("std");
const Fold = @import("../pure_p2_fold.zig");
pub const MAX_LEAVES = 256;
pub const MAX_NODES = 2 * MAX_LEAVES - 1;
pub const Span = struct {
    first: u32,
    count: u32,
    pub fn end(self: Span) !u32 {
        return std.math.add(u32, self.first, self.count) catch error.NativeGroupSpanOverflow;
    }
    pub fn requireGroup(self: Span, total: u32, maximum: u32) !void {
        try requireMaximum(maximum);
        if (total == 0 or total > MAX_LEAVES) return error.NativeGroupLeafCount;
        if (self.count != 1 and self.count != 2 and self.count != 4) return error.NativeGroupSpanCount;
        if (self.count > maximum or self.first % self.count != 0) return error.NativeGroupSpanAlignment;
        if (try self.end() > total) return error.NativeGroupSpanCoverage;
    }
};
pub const Edge = struct { left: u16, right: u16 };
pub const Node = struct { span: Span, operation: union(enum) { group: void, fold: Edge } };
pub const Plan = struct {
    leaf_count: u32,
    maximum_group: u32,
    nodes: [MAX_NODES]Node = undefined,
    node_count: u16 = 0,
    root: u16 = 0,
    pub fn init(leaf_count: u32, maximum_group: u32) !Plan {
        if (leaf_count == 0 or leaf_count > MAX_LEAVES) return error.NativeGroupLeafCount;
        try requireMaximum(maximum_group);
        var self = Plan{ .leaf_count = leaf_count, .maximum_group = maximum_group };
        self.root = try self.append(.{ .first = 0, .count = leaf_count });
        return self;
    }
    pub fn ordered(self: *const Plan) []const Node {
        return self.nodes[0..self.node_count];
    }
    fn append(self: *Plan, span: Span) !u16 {
        const complete = std.math.isPowerOfTwo(span.count);
        const operation: @FieldType(Node, "operation") = if (complete and span.count <= self.maximum_group) blk: {
            try span.requireGroup(self.leaf_count, self.maximum_group);
            break :blk .{ .group = {} };
        } else blk: {
            // For count7: split4+3, then3→2+1. Never fold peer groups
            // ((4+2)+1), which authenticates a different ordered tree.
            var split: u32 = 1;
            while (split <= (span.count - 1) / 2) split *= 2;
            const left = try self.append(.{ .first = span.first, .count = split });
            const right = try self.append(.{ .first = try std.math.add(u32, span.first, split), .count = span.count - split });
            break :blk .{ .fold = .{ .left = left, .right = right } };
        };
        if (self.node_count >= MAX_NODES) return error.NativeGroupNodeCount;
        const index = self.node_count;
        self.nodes[index] = .{ .span = span, .operation = operation };
        self.node_count += 1;
        return index;
    }
    /// This planner is source authority, not advice. Rebuilding makes coverage,
    /// adjacency, alignment, postorder, counts and the odd-tree shape explicit.
    pub fn validate(self: *const Plan) !void {
        const expected = try Plan.init(self.leaf_count, self.maximum_group);
        if (self.node_count != expected.node_count or self.root != expected.root) return error.NativeGroupPlanTopology;
        for (self.ordered(), expected.ordered()) |actual, canonical| {
            if (!std.meta.eql(actual, canonical)) return error.NativeGroupPlanTopology;
        }
    }
    pub fn digest(self: *const Plan, a: std.mem.Allocator, leaves: []const Fold.Digest) !Fold.Digest {
        try self.validate();
        if (leaves.len != self.leaf_count) return error.NativeGroupLeafCount;
        var values: [MAX_NODES]Fold.Digest = undefined;
        for (self.ordered(), 0..) |node, index| values[index] = switch (node.operation) {
            .group => try Fold.treeDigest(a, leaves[node.span.first..try node.span.end()]),
            .fold => |edge| try Fold.digest(values[edge.left], values[edge.right]),
        };
        return values[self.root];
    }
};
fn requireMaximum(maximum: u32) !void {
    if (maximum != 1 and maximum != 2 and maximum != 4) return error.NativeGroupMaximum;
}
test "native group canonical planner exhaustive 1 through 256 matches original odd carry tree" {
    const a = std.testing.allocator;
    const Q = @import("../full_p2_common.zig").Q;
    var leaves: [MAX_LEAVES]Fold.Digest = undefined;
    for (&leaves, 0..) |*leaf, i| for (leaf, 0..) |*port, j| {
        port.* = Q.fromBase(@import("stwo_core").fields.m31.M31.fromCanonical(@intCast(1 + i * 9 + j)));
    };
    for (1..MAX_LEAVES + 1) |count| {
        const reference = try Fold.treeDigest(a, leaves[0..count]);
        for ([_]u32{ 1, 2, 4 }) |maximum| {
            const plan = try Plan.init(@intCast(count), maximum);
            try plan.validate();
            try std.testing.expectEqualDeep(reference, try plan.digest(a, leaves[0..count]));
            var covered = [_]bool{false} ** MAX_LEAVES;
            for (plan.ordered(), 0..) |node, index| switch (node.operation) {
                .group => {
                    try node.span.requireGroup(@intCast(count), maximum);
                    for (node.span.first..try node.span.end()) |i| {
                        try std.testing.expect(!covered[i]);
                        covered[i] = true;
                    }
                },
                .fold => |edge| {
                    try std.testing.expect(edge.left < index and edge.right < index);
                    const left = plan.nodes[edge.left].span;
                    const right = plan.nodes[edge.right].span;
                    try std.testing.expectEqual(try left.end(), right.first);
                    try std.testing.expectEqual(node.span.first, left.first);
                    try std.testing.expectEqual(node.span.count, left.count + right.count);
                },
            };
            for (covered[0..count]) |present| try std.testing.expect(present);
        }
    }
}
test "native group planner rejects malformed count alignment overflow coverage and edges" {
    try std.testing.expectError(error.NativeGroupLeafCount, Plan.init(0, 4));
    try std.testing.expectError(error.NativeGroupLeafCount, Plan.init(257, 4));
    for ([_]u32{ 0, 3, 8, std.math.maxInt(u32) }) |maximum| try std.testing.expectError(error.NativeGroupMaximum, Plan.init(7, maximum));
    try std.testing.expectError(error.NativeGroupSpanOverflow, (Span{ .first = std.math.maxInt(u32), .count = 1 }).end());
    try std.testing.expectError(error.NativeGroupSpanAlignment, (Span{ .first = 1, .count = 2 }).requireGroup(7, 4));
    try std.testing.expectError(error.NativeGroupSpanCount, (Span{ .first = 0, .count = 3 }).requireGroup(7, 4));
    try std.testing.expectError(error.NativeGroupSpanCoverage, (Span{ .first = 6, .count = 2 }).requireGroup(7, 4));
    var plan = try Plan.init(7, 4);
    try std.testing.expectEqual(@as(u16, 5), plan.node_count);
    try std.testing.expectEqualDeep(Edge{ .left = 0, .right = 3 }, plan.nodes[4].operation.fold);
    try std.testing.expectEqualDeep(Edge{ .left = 1, .right = 2 }, plan.nodes[3].operation.fold);
    plan.nodes[4].operation.fold = .{ .left = 3, .right = 0 };
    try std.testing.expectError(error.NativeGroupPlanTopology, plan.validate());
    plan = try Plan.init(7, 4);
    plan.nodes[2].span.first = 5;
    try std.testing.expectError(error.NativeGroupPlanTopology, plan.validate());
    plan = try Plan.init(7, 4);
    plan.root = 3;
    try std.testing.expectError(error.NativeGroupPlanTopology, plan.validate());
    plan = try Plan.init(7, 4);
    plan.node_count = 511;
    try std.testing.expectError(error.NativeGroupPlanTopology, plan.validate());
}
