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

/// Counts the exact canonical node rows for a strictly increasing leaf-index
/// stream without evaluating a single hash or retaining any node value.
///
/// This is a geometry authority, not a commitment authority: callers must
/// separately authenticate the corresponding leaf values and root.  The
/// frontier transition is the same sibling merge as `buildLinearBatched`, so
/// the returned count is exactly `Tree.nodes.len` for the same indices.  A
/// private mutable copy lets every level compact in place and caps temporary
/// storage at one `u32` per leaf.
pub fn countCanonicalNodeRowsFromSortedIndices(
    allocator: std.mem.Allocator,
    sorted_indices: []const u32,
) Error!usize {
    if (sorted_indices.len == 0) return 0;

    var frontier = try allocator.dupe(u32, sorted_indices);
    defer allocator.free(frontier);
    for (frontier, 0..) |index, position| {
        if (index >= LEAF_COUNT) return error.IndexOutOfRange;
        if (position != 0 and frontier[position - 1] >= index) {
            return if (frontier[position - 1] == index)
                error.DuplicateLeaf
            else
                error.InvalidTree;
        }
    }

    var frontier_len = frontier.len;
    var node_rows: usize = 0;
    var depth: u32 = LEAF_DEPTH;
    while (depth > 0) : (depth -= 1) {
        var source: usize = 0;
        var destination: usize = 0;
        while (source < frontier_len) {
            const parent = frontier[source] >> 1;
            source += 1;
            if (source < frontier_len and frontier[source] >> 1 == parent)
                source += 1;
            frontier[destination] = parent;
            destination += 1;
        }
        node_rows = std.math.add(usize, node_rows, destination) catch
            return error.InvalidTree;
        frontier_len = destination;
    }
    if (frontier_len != 1 or frontier[0] != 0) return error.InvalidTree;
    return node_rows;
}

/// Research candidate for the same canonical sparse tree as `build`.
///
/// The compatibility builder above materializes every level in a hash map,
/// copies its keys, and sorts them again.  Inputs are already canonical and
/// sorted, and parent indices preserve that order, so none of those maps or
/// repeated sorts carry protocol information.  This candidate keeps each
/// level as one sorted frontier, performs a linear sibling merge, and hashes
/// four independent parents through the pinned SIMD-equivalent permutation.
/// Node order remains depth-major and index-major, exactly like `build`.
///
/// The retained reference builder and parity tests pin every output byte.
pub fn buildLinearBatched(
    allocator: std.mem.Allocator,
    input: []const Leaf,
) Error!Tree {
    const LevelEntry = struct {
        index: u32,
        value: NodeValue,
    };
    const PendingNode = struct {
        left_index: u32,
        left: NodeValue,
        right: NodeValue,
    };

    const leaves = try allocator.dupe(Leaf, input);
    errdefer allocator.free(leaves);
    std.mem.sort(Leaf, leaves, {}, lessLeaf);
    for (leaves, 0..) |leaf, index| {
        try validateLeaf(leaf);
        if (index != 0 and leaves[index - 1].index == leaf.index)
            return error.DuplicateLeaf;
    }

    var current = try allocator.alloc(LevelEntry, leaves.len);
    defer allocator.free(current);
    for (leaves, current) |leaf, *entry| {
        entry.* = .{
            .index = leaf.index,
            .value = .{ .value = leaf.value, .multiplicity = 1 },
        };
    }

    var nodes: std.ArrayList(Node) = .{};
    errdefer nodes.deinit(allocator);
    var depth: u32 = LEAF_DEPTH;
    while (depth > 0) : (depth -= 1) {
        const pending = try allocator.alloc(PendingNode, current.len);
        defer allocator.free(pending);
        var pending_count: usize = 0;
        var cursor: usize = 0;
        const default = NodeValue{
            .value = poseidon2.DEFAULT_HASHES[depth],
            .multiplicity = 0,
        };
        while (cursor < current.len) {
            const first = current[cursor];
            const left_index = first.index & ~@as(u32, 1);
            var left = default;
            var right = default;
            if ((first.index & 1) == 0) {
                left = first.value;
                cursor += 1;
                if (cursor < current.len and
                    current[cursor].index == left_index + 1)
                {
                    right = current[cursor].value;
                    cursor += 1;
                }
            } else {
                right = first.value;
                cursor += 1;
            }
            pending[pending_count] = .{
                .left_index = left_index,
                .left = left,
                .right = right,
            };
            pending_count += 1;
        }

        const next = try allocator.alloc(LevelEntry, pending_count);
        errdefer allocator.free(next);
        try nodes.ensureUnusedCapacity(allocator, pending_count);
        var parent_index: usize = 0;
        while (parent_index + 4 <= pending_count) : (parent_index += 4) {
            var left: [4]u32 = undefined;
            var right: [4]u32 = undefined;
            inline for (0..4) |lane| {
                left[lane] = pending[parent_index + lane].left.value;
                right[lane] = pending[parent_index + lane].right.value;
            }
            const hashes = poseidon2.hashPairs4(left, right);
            inline for (0..4) |lane| {
                appendLinearParent(
                    &nodes,
                    next,
                    pending[parent_index + lane],
                    hashes[lane],
                    depth,
                    parent_index + lane,
                );
            }
        }
        while (parent_index < pending_count) : (parent_index += 1) {
            const item = pending[parent_index];
            appendLinearParent(
                &nodes,
                next,
                item,
                poseidon2.hashPair(item.left.value, item.right.value),
                depth,
                parent_index,
            );
        }

        allocator.free(current);
        current = next;
    }

    const root = if (leaves.len == 0)
        poseidon2.DEFAULT_HASHES[0]
    else if (current.len == 1 and current[0].index == 0)
        current[0].value.value
    else
        return error.InvalidTree;
    return .{
        .leaves = leaves,
        .nodes = try nodes.toOwnedSlice(allocator),
        .root = root,
    };
}

fn appendLinearParent(
    nodes: *std.ArrayList(Node),
    next: anytype,
    pending: anytype,
    hash: u32,
    depth: u32,
    index: usize,
) void {
    const parent = NodeValue{ .value = hash, .multiplicity = 1 };
    nodes.appendAssumeCapacity(.{
        .index = pending.left_index,
        .depth = depth,
        .left = pending.left,
        .right = pending.right,
        .current = parent,
    });
    next[index] = .{
        .index = pending.left_index / 2,
        .value = parent,
    };
}

/// Canonical production builder. The linear frontier preserves the exact
/// leaf/node/root bytes of the retained map-and-sort implementation while
/// removing its repeated level maps and sorts.
pub fn build(allocator: std.mem.Allocator, input: []const Leaf) Error!Tree {
    return buildLinearBatched(allocator, input);
}

fn buildReference(allocator: std.mem.Allocator, input: []const Leaf) Error!Tree {
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

/// Exact producer-returned sparse-tree receipt. The production `build` route
/// has no profiling branch in its node loop.
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

test "sparse Merkle: linear batched frontier is byte-identical" {
    const allocator = std.testing.allocator;
    const fixtures = [_][]const Leaf{
        &.{},
        &.{.{ .index = 7, .value = 11 }},
        &.{
            .{ .index = 9, .value = 7 },
            .{ .index = 8, .value = 6 },
            .{ .index = 4, .value = 5 },
        },
        &.{
            .{ .index = 0, .value = 1 },
            .{ .index = 1, .value = 2 },
            .{ .index = 2, .value = 3 },
            .{ .index = 17, .value = 4 },
            .{ .index = (1 << 29) + 3, .value = 5 },
            .{ .index = LEAF_COUNT - 1, .value = 6 },
        },
    };
    for (fixtures) |fixture| {
        var reference = try buildReference(allocator, fixture);
        defer reference.deinit(allocator);
        var linear = try buildLinearBatched(allocator, fixture);
        defer linear.deinit(allocator);
        try std.testing.expectEqual(reference.root, linear.root);
        try std.testing.expectEqualSlices(Leaf, reference.leaves, linear.leaves);
        try std.testing.expectEqualSlices(Node, reference.nodes, linear.nodes);

        const indices = try allocator.alloc(u32, linear.leaves.len);
        defer allocator.free(indices);
        for (linear.leaves, indices) |leaf, *index| index.* = leaf.index;
        try std.testing.expectEqual(
            linear.nodes.len,
            try countCanonicalNodeRowsFromSortedIndices(allocator, indices),
        );
    }
}

test "sparse Merkle: count-only frontier rejects noncanonical index order" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.DuplicateLeaf,
        countCanonicalNodeRowsFromSortedIndices(allocator, &.{ 4, 4 }),
    );
    try std.testing.expectError(
        error.InvalidTree,
        countCanonicalNodeRowsFromSortedIndices(allocator, &.{ 5, 4 }),
    );
    try std.testing.expectError(
        error.IndexOutOfRange,
        countCanonicalNodeRowsFromSortedIndices(allocator, &.{LEAF_COUNT}),
    );
}

test "sparse Merkle: linear batched frontier preserves validation errors" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.DuplicateLeaf,
        buildLinearBatched(allocator, &.{
            .{ .index = 3, .value = 1 },
            .{ .index = 3, .value = 2 },
        }),
    );
    try std.testing.expectError(
        error.IndexOutOfRange,
        buildLinearBatched(allocator, &.{.{
            .index = LEAF_COUNT,
            .value = 1,
        }}),
    );
    try std.testing.expectError(
        error.NonCanonicalValue,
        buildLinearBatched(allocator, &.{.{
            .index = 0,
            .value = m31.Modulus,
        }}),
    );
}

test "sparse Merkle autoresearch: compare reference and linear batched frontier" {
    if (!std.process.hasEnvVarConstant("STWO_SPARSE_MERKLE_AUTORESEARCH"))
        return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const leaf_count: usize = 1 << 18;
    const leaves = try allocator.alloc(Leaf, leaf_count);
    defer allocator.free(leaves);
    for (leaves, 0..) |*leaf, index| {
        leaf.* = .{
            // Spread leaves over the 30-bit address space while retaining a
            // one-to-one deterministic index map.
            .index = @bitReverse(@as(u32, @intCast(index))) >> 2,
            .value = @intCast(index + 1),
        };
    }

    var reference_timer = try std.time.Timer.start();
    var reference = try buildReference(allocator, leaves);
    defer reference.deinit(allocator);
    const reference_ns = reference_timer.read();
    var linear_timer = try std.time.Timer.start();
    var linear = try buildLinearBatched(allocator, leaves);
    defer linear.deinit(allocator);
    const linear_ns = linear_timer.read();
    try std.testing.expectEqual(reference.root, linear.root);
    try std.testing.expectEqualSlices(Node, reference.nodes, linear.nodes);
    std.debug.print(
        "SPARSE_MERKLE_AUTORESEARCH leaves={d} nodes={d} reference_ns={d} linear_batched_ns={d}\n",
        .{ leaf_count, reference.nodes.len, reference_ns, linear_ns },
    );
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
