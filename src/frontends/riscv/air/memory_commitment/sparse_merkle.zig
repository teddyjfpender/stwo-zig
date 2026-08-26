//! Deterministic sparse Merkle claims for pinned Stark-V memory commitments.
//!
//! Leaves are scalar M31 values at raw byte addresses. Only paths containing
//! a committed leaf are materialized; absent siblings use the pinned default
//! hash for that depth with multiplicity zero.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const poseidon2 = @import("poseidon2.zig");
const poseidon_work = @import("../../prover/poseidon_witness_work.zig");

pub const LEAF_DEPTH: u32 = 30;
pub const LEAF_COUNT: u32 = @as(u32, 1) << @intCast(LEAF_DEPTH);

pub const Error = error{
    DuplicateLeaf,
    IndexOutOfRange,
    NonCanonicalValue,
    InvalidTree,
    OutOfMemory,
};

pub const Leaf = struct {
    index: u32,
    value: u32,

    pub fn relationTuple(self: Leaf, root: u32) [4]u32 {
        return .{ self.index, LEAF_DEPTH, self.value, root };
    }
};

pub const NodeValue = struct {
    value: u32,
    multiplicity: u2,
};

/// One exact row of Stark-V's `merkle` table.
pub const Node = struct {
    index: u32,
    depth: u32,
    left: NodeValue,
    right: NodeValue,
    current: NodeValue,

    pub fn leftTuple(self: Node, root: u32) [4]u32 {
        return .{ self.index, self.depth, self.left.value, root };
    }

    pub fn rightTuple(self: Node, root: u32) [4]u32 {
        return .{ self.index + 1, self.depth, self.right.value, root };
    }

    pub fn parentTuple(self: Node, root: u32) [4]u32 {
        return .{ self.index / 2, self.depth - 1, self.current.value, root };
    }
};

pub const Tree = struct {
    leaves: []Leaf,
    nodes: []Node,
    root: u32,

    pub fn deinit(self: *Tree, allocator: std.mem.Allocator) void {
        allocator.free(self.leaves);
        allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn rootTuple(self: Tree) [4]u32 {
        return .{ 0, 0, self.root, self.root };
    }

    /// Rebuild the tree from its leaves and reject any altered claim row.
    pub fn validate(self: Tree, allocator: std.mem.Allocator) Error!void {
        var rebuilt = try build(allocator, self.leaves);
        defer rebuilt.deinit(allocator);
        if (self.root != rebuilt.root or self.nodes.len != rebuilt.nodes.len)
            return error.InvalidTree;
        for (self.nodes, rebuilt.nodes) |actual, expected| {
            if (!std.meta.eql(actual, expected)) return error.InvalidTree;
        }
    }

    /// Profiled validation returns the exact completed rebuild receipt only
    /// after every root and node comparison succeeds.  Rejected trees publish
    /// no work into the request coordinator.
    pub fn validateWithWorkReceipt(
        self: Tree,
        allocator: std.mem.Allocator,
        authority: *const poseidon_work.Authority,
    ) (Error || error{
        PoseidonWorkOverflow,
        PoseidonWorkSourceMismatch,
    })!poseidon_work.ProducerReceipt {
        var rebuilt = try buildWithWorkReceipt(allocator, self.leaves, authority);
        defer rebuilt.tree.deinit(allocator);
        if (self.root != rebuilt.tree.root or
            self.nodes.len != rebuilt.tree.nodes.len)
        {
            return error.InvalidTree;
        }
        for (self.nodes, rebuilt.tree.nodes) |actual, expected| {
            if (!std.meta.eql(actual, expected)) return error.InvalidTree;
        }
        return rebuilt.receipt;
    }
};

pub const BuildWithWorkReceipt = struct {
    tree: Tree,
    receipt: poseidon_work.ProducerReceipt,
};

pub fn build(allocator: std.mem.Allocator, input: []const Leaf) Error!Tree {
    const leaves = try allocator.dupe(Leaf, input);
    errdefer allocator.free(leaves);
    std.mem.sort(Leaf, leaves, {}, lessLeaf);

    var current = std.AutoHashMap(u32, NodeValue).init(allocator);
    defer current.deinit();
    for (leaves, 0..) |leaf, index| {
        try validateLeaf(leaf);
        if (index != 0 and leaves[index - 1].index == leaf.index)
            return error.DuplicateLeaf;
        try current.put(leaf.index, .{ .value = leaf.value, .multiplicity = 1 });
    }

    var nodes: std.ArrayList(Node) = .{};
    errdefer nodes.deinit(allocator);

    var depth: u32 = LEAF_DEPTH;
    while (depth > 0) : (depth -= 1) {
        var indices = try allocator.alloc(u32, current.count());
        defer allocator.free(indices);
        var iterator = current.keyIterator();
        var index_cursor: usize = 0;
        while (iterator.next()) |index| : (index_cursor += 1) {
            indices[index_cursor] = index.*;
        }
        std.mem.sort(u32, indices, {}, std.sort.asc(u32));

        var next = std.AutoHashMap(u32, NodeValue).init(allocator);
        errdefer next.deinit();
        for (indices) |index| {
            if ((index & 1) == 1 and current.contains(index - 1)) continue;
            const left_index = index & ~@as(u32, 1);
            const default = NodeValue{
                .value = poseidon2.DEFAULT_HASHES[depth],
                .multiplicity = 0,
            };
            const left = current.get(left_index) orelse default;
            const right = current.get(left_index + 1) orelse default;
            const parent = NodeValue{
                .value = poseidon2.hashPair(left.value, right.value),
                .multiplicity = 1,
            };
            try nodes.append(allocator, .{
                .index = left_index,
                .depth = depth,
                .left = left,
                .right = right,
                .current = parent,
            });
            try next.put(left_index / 2, parent);
        }
        current.deinit();
        current = next;
    }

    const root = if (leaves.len == 0)
        poseidon2.DEFAULT_HASHES[0]
    else
        (current.get(0) orelse return error.InvalidTree).value;
    return .{
        .leaves = leaves,
        .nodes = try nodes.toOwnedSlice(allocator),
        .root = root,
    };
}

/// Exact producer-returned sparse-tree receipt.  The ordinary `build` route is
/// unchanged and has no profiling branch in its node loop.
pub fn buildWithWorkReceipt(
    allocator: std.mem.Allocator,
    input: []const Leaf,
    authority: *const poseidon_work.Authority,
) (Error || error{
    PoseidonWorkOverflow,
    PoseidonWorkSourceMismatch,
})!BuildWithWorkReceipt {
    var tree = try build(allocator, input);
    errdefer tree.deinit(allocator);
    return .{
        .tree = tree,
        .receipt = try poseidon_work.complete(
            authority,
            .sparse_tree_permutation,
            @intCast(tree.nodes.len),
        ),
    };
}

fn validateLeaf(leaf: Leaf) Error!void {
    if (leaf.index >= LEAF_COUNT) return error.IndexOutOfRange;
    if (leaf.value >= m31.Modulus) return error.NonCanonicalValue;
}

fn lessLeaf(_: void, lhs: Leaf, rhs: Leaf) bool {
    return lhs.index < rhs.index;
}

test "sparse Merkle: empty tree has pinned default root and no claims" {
    var tree = try build(std.testing.allocator, &.{});
    defer tree.deinit(std.testing.allocator);
    try std.testing.expectEqual(poseidon2.DEFAULT_HASHES[0], tree.root);
    try std.testing.expectEqual(@as(usize, 0), tree.leaves.len);
    try std.testing.expectEqual(@as(usize, 0), tree.nodes.len);
}

test "sparse Merkle: leaves sort deterministically and use default siblings" {
    var tree = try build(std.testing.allocator, &.{
        .{ .index = 9, .value = 7 },
        .{ .index = 8, .value = 6 },
        .{ .index = 4, .value = 5 },
    });
    defer tree.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u32, &.{ 4, 8, 9 }, &.{
        tree.leaves[0].index,
        tree.leaves[1].index,
        tree.leaves[2].index,
    });
    try std.testing.expectEqual(@as(u32, 4), tree.nodes[0].index);
    try std.testing.expectEqual(@as(u2, 1), tree.nodes[0].left.multiplicity);
    try std.testing.expectEqual(@as(u2, 0), tree.nodes[0].right.multiplicity);
    try tree.validate(std.testing.allocator);
}

test "sparse Merkle: duplicate and out-of-domain leaves fail closed" {
    try std.testing.expectError(error.DuplicateLeaf, build(std.testing.allocator, &.{
        .{ .index = 1, .value = 2 },
        .{ .index = 1, .value = 3 },
    }));
    try std.testing.expectError(error.IndexOutOfRange, build(std.testing.allocator, &.{
        .{ .index = LEAF_COUNT, .value = 2 },
    }));
}

test "sparse Merkle: leaf and internal-node mutations are rejected" {
    var tree = try build(std.testing.allocator, &.{
        .{ .index = 0x1000, .value = 0xaa },
        .{ .index = 0x1001, .value = 0xbb },
    });
    defer tree.deinit(std.testing.allocator);

    tree.leaves[0].value ^= 1;
    try std.testing.expectError(error.InvalidTree, tree.validate(std.testing.allocator));
    tree.leaves[0].value ^= 1;
    tree.nodes[0].current.value ^= 1;
    try std.testing.expectError(error.InvalidTree, tree.validate(std.testing.allocator));
}
