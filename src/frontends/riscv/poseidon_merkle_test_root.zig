//! Small protocol/parity gate, without the native or recursive prover graph.
test {
    _ = @import("recursion/poseidon2_channel.zig");
}

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const channel = @import("recursion/poseidon2_channel.zig");
const merkle = @import("stwo_prover_engine").vcs_lifted.prover;

/// Deliberately exposes only the scalar contract: optional SIMD hooks must
/// never silently turn the reference into the optimized implementation.
const ScalarHasher = struct {
    inner: channel.MerkleHasher,
    pub const Hash = channel.MerkleHasher.Hash;
    pub const NodeSeed = void;
    pub const Children = struct { left: Hash, right: Hash };

    pub fn nodeSeed() NodeSeed {
        return {};
    }
    pub fn hashChildrenWithSeed(_: NodeSeed, children: Children) Hash {
        return hashChildren(children);
    }

    pub fn defaultWithInitialState() ScalarHasher {
        return .{ .inner = channel.MerkleHasher.defaultWithInitialState() };
    }
    pub fn hashChildren(children: Children) Hash {
        return channel.MerkleHasher.hashChildren(.{ .left = children.left, .right = children.right });
    }
    pub fn updateLeaf(self: *ScalarHasher, values: []const M31) void {
        self.inner.updateLeaf(values);
    }
    pub fn finalize(self: *ScalarHasher) Hash {
        return self.inner.finalize();
    }
};

const ScalarTree = merkle.MerkleProverLifted(ScalarHasher);
const OptimizedTree = merkle.MerkleProverLifted(channel.MerkleHasher);

fn expectLayers(expected: ScalarTree, actual: anytype) !void {
    try std.testing.expectEqual(expected.layers.len, actual.layers.len);
    for (expected.layers, actual.layers) |left, right| {
        try std.testing.expectEqual(left.len, right.len);
        for (left, right) |left_hash, right_hash| try std.testing.expectEqualSlices(u32, &left_hash, &right_hash);
    }
}

fn stream(comptime Tree: type, columns: []const Tree.ColumnRef, chunk: usize) !Tree {
    var committer = Tree.StreamingCommitter.init(std.testing.allocator);
    errdefer committer.deinit();
    var start: usize = 0;
    while (start < columns.len) {
        const end = @min(start + chunk, columns.len);
        try committer.addColumns(columns[start..end]);
        start = end;
    }
    return committer.finalize();
}

test "recursion Poseidon2: complete mixed-domain trees match scalar layers across streaming groups" {
    var storage: [15][1024]M31 = undefined;
    var random = std.Random.DefaultPrng.init(0x5ca1_a4e2);
    for (&storage, 0..) |*column, column_index| for (column, 0..) |*value, row| {
        value.* = M31.fromCanonical(switch ((column_index + row) % 7) {
            0 => 0,
            1 => 1,
            2 => m31.Modulus - 1,
            else => random.random().int(u32) % m31.Modulus,
        });
    };
    for ([_]u32{ 1, 3, 10 }) |maximum_log| {
        var columns: [storage.len][]const M31 = undefined;
        var references: [storage.len]OptimizedTree.ColumnRef = undefined;
        for (&columns, &references, &storage, 0..) |*column, *reference, *values, index| {
            const log = @min(maximum_log, @as(u32, if (index < 3) 1 else if (index < 8) 3 else 10));
            column.* = values[0 .. @as(usize, 1) << @intCast(log)];
            reference.* = .{ .values = column.*, .log_size = log, .original_index = index };
        }
        var scalar = try ScalarTree.testing.commitWithWorkerOverride(std.testing.allocator, &columns, 1);
        defer scalar.deinit(std.testing.allocator);
        var optimized = try OptimizedTree.testing.commitWithWorkerOverride(std.testing.allocator, &columns, 1);
        defer optimized.deinit(std.testing.allocator);
        try expectLayers(scalar, optimized);
        // Groups deliberately split both equal-domain columns and rate-eight
        // sponge blocks; domain expansion must preserve partial sponge state.
        for ([_]usize{ 1, 2, 5, 15 }) |chunk| {
            var scalar_stream = try stream(ScalarTree, &references, chunk);
            defer scalar_stream.deinit(std.testing.allocator);
            var optimized_stream = try stream(OptimizedTree, &references, chunk);
            defer optimized_stream.deinit(std.testing.allocator);
            try expectLayers(scalar, scalar_stream);
            try expectLayers(scalar, optimized_stream);
        }
    }
}

test "recursion Poseidon2: mixed batched leaves fail cleanly when four-way scratch allocation fails" {
    const short = [_]M31{ M31.zero(), M31.one() };
    var long: [8]M31 = undefined;
    for (&long, 0..) |*word, index| word.* = M31.fromCanonical(@intCast(index + 2));
    const columns = [_]OptimizedTree.ColumnRef{
        .{ .values = &short, .log_size = 1, .original_index = 0 },
        .{ .values = &long, .log_size = 3, .original_index = 1 },
    };
    // Leaf output uses a separate tracked allocator. The optimized branch
    // allocates zero scalar hashers, so its first nonempty work allocation is
    // exactly the four-message scratch. This is not an all-allocations sweep.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, OptimizedTree.testing.buildLeavesBatched(
        failing.allocator(),
        std.testing.allocator,
        &columns,
        4,
    ));
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    const leaves = try OptimizedTree.testing.buildLeavesBatched(std.testing.allocator, std.testing.allocator, &columns, 4);
    defer std.testing.allocator.free(leaves);
    const scalar_leaves = try ScalarTree.testing.buildLeavesBatched(std.testing.allocator, std.testing.allocator, &columns, 4);
    defer std.testing.allocator.free(scalar_leaves);
    try std.testing.expectEqual(leaves.len, scalar_leaves.len);
    for (leaves, scalar_leaves) |actual, expected| try std.testing.expectEqualSlices(u32, &expected, &actual);
}
