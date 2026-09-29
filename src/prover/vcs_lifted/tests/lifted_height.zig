//! Lifted Merkle commitments at explicit heights (proving@5a7c5ed revision).

const std = @import("std");
const core = @import("stwo_core");
const prover_mod = @import("stwo_prover_engine").vcs_lifted.prover;

const M31 = core.fields.m31.M31;
const vectors = core.vcs_lifted.lifted_height_vectors;
const Hasher = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Prover = prover_mod.MerkleProverLifted(Hasher);
const Verifier = core.vcs_lifted.verifier.MerkleVerifierLifted(Hasher);

fn sortedUnique(positions: []const usize, buffer: []usize) []const usize {
    @memcpy(buffer[0..positions.len], positions);
    std.mem.sort(usize, buffer[0..positions.len], {}, std.sort.asc(usize));
    var len: usize = 0;
    for (buffer[0..positions.len]) |position| {
        if (len != 0 and buffer[len - 1] == position) continue;
        buffer[len] = position;
        len += 1;
    }
    return buffer[0..len];
}

test "prover vcs_lifted: explicit heights reproduce proving@5a7c5ed roots and decommitments" {
    const alloc = std.testing.allocator;
    var storage: [vectors.column_log_sizes.len][8]M31 = undefined;
    const columns = vectors.columns(&storage);

    for (vectors.cases) |case| {
        var tree = try Prover.commitLifted(alloc, &columns, case.height);
        defer tree.deinit(alloc);
        try std.testing.expectEqualSlices(u8, &vectors.digest(case.root), &tree.root());
        try std.testing.expectEqual(case.height, tree.maxLogSize());

        // Upstream sorts and deduplicates the queries itself; the Zig
        // decommitment takes them ascending, as the PCS supplies them.
        var positions: [4]usize = undefined;
        const unique = sortedUnique(case.positions, &positions);
        var opened = try tree.decommit(alloc, unique, &columns);
        defer opened.deinit(alloc);
        for (opened.queried_values, case.values) |actual, expected| {
            for (actual, unique) |value, position| {
                const at = std.mem.indexOfScalar(usize, case.positions, position).?;
                try std.testing.expectEqual(expected[at], value.v);
            }
        }
        const witness = opened.decommitment.decommitment.hash_witness;
        try std.testing.expectEqual(case.witness.len, witness.len);
        for (witness, case.witness) |hash, hex| try std.testing.expectEqualSlices(u8, &vectors.digest(hex), &hash);

        var verifier = try Verifier.initWithHeight(alloc, tree.root(), &vectors.column_log_sizes, case.height);
        defer verifier.deinit(alloc);
        const queried: []const []const M31 = @ptrCast(opened.queried_values);
        try verifier.verify(alloc, unique, queried, opened.decommitment.decommitment);
    }
}

test "prover vcs_lifted: the largest-column height is the existing commitment" {
    const alloc = std.testing.allocator;
    var storage: [vectors.column_log_sizes.len][8]M31 = undefined;
    const columns = vectors.columns(&storage);
    var legacy = try Prover.commit(alloc, &columns);
    defer legacy.deinit(alloc);
    var explicit = try Prover.commitLifted(alloc, &columns, 3);
    defer explicit.deinit(alloc);
    try std.testing.expectEqualSlices(u8, &legacy.root(), &explicit.root());
    try std.testing.expectEqualSlices(u8, &vectors.digest(vectors.cases[0].root), &legacy.root());
}

test "prover vcs_lifted: explicit heights reject short and non-empty-zero trees" {
    const alloc = std.testing.allocator;
    var storage: [vectors.column_log_sizes.len][8]M31 = undefined;
    const columns = vectors.columns(&storage);
    try std.testing.expectError(error.InvalidTreeHeight, Prover.commitLifted(alloc, &columns, 2));
    try std.testing.expectError(error.InvalidTreeHeight, Prover.commitLifted(alloc, &.{}, 1));

    // An empty tree is one hash of no data at height 0.
    var empty = try Prover.commitLifted(alloc, &.{}, 0);
    defer empty.deinit(alloc);
    try std.testing.expectEqualSlices(u8, &vectors.digest(vectors.empty_root), &empty.root());
}

test "prover vcs_lifted: constant columns lift to the same root as full-height constants" {
    // Lifting replicates leaves, so constant columns of any log size lifted to
    // height h commit exactly like constant columns already of size 2^h.
    const alloc = std.testing.allocator;
    const seven = M31.fromCanonical(7);
    const short = [_]M31{seven} ** 4;
    const full = [_]M31{seven} ** 32;
    var lifted = try Prover.commitLifted(alloc, &.{ &short, &short }, 5);
    defer lifted.deinit(alloc);
    var reference = try Prover.commit(alloc, &.{ &full, &full });
    defer reference.deinit(alloc);
    try std.testing.expectEqualSlices(u8, &reference.root(), &lifted.root());
}

test "prover vcs_lifted: lifted commitment equals committing explicitly lifted columns" {
    // Independent reference: expand every column to 2^height with the lifting
    // map, then commit at the (now common) largest-column height. A leaf
    // absorbs columns in ascending original log size (stable), so the
    // reference lists the expanded columns in that order. Sizes cross the
    // batched-leaf and parallel-layer paths.
    const alloc = std.testing.allocator;
    const height: u32 = 13;
    const log_sizes = [_]u32{ 4, 10, 7, 10, 1 };
    const absorb_position = [_]usize{ 1, 3, 2, 4, 0 };
    var prng = std.Random.DefaultPrng.init(0x5a7c_5ede_0000_0001);
    const rng = prng.random();

    var columns: [log_sizes.len][]const M31 = undefined;
    var expanded: [log_sizes.len][]const M31 = undefined;
    var initialized: usize = 0;
    defer for (columns[0..initialized], expanded[0..initialized]) |column, lifted| {
        alloc.free(column);
        alloc.free(lifted);
    };
    for (log_sizes, 0..) |log_size, index| {
        const column = try alloc.alloc(M31, @as(usize, 1) << @intCast(log_size));
        for (column) |*value| value.* = M31.fromU64(rng.int(u32));
        const lifted = alloc.alloc(M31, @as(usize, 1) << height) catch |err| {
            alloc.free(column);
            return err;
        };
        const shift: std.math.Log2Int(usize) = @intCast(height - log_size + 1);
        for (lifted, 0..) |*value, i| value.* = column[((i >> shift) << 1) + (i & 1)];
        columns[index] = column;
        expanded[index] = lifted;
        initialized += 1;
    }
    var absorbed: [log_sizes.len][]const M31 = undefined;
    for (expanded, absorb_position) |lifted, position| absorbed[position] = lifted;

    var tree = try Prover.commitLifted(alloc, &columns, height);
    defer tree.deinit(alloc);
    var reference = try Prover.commit(alloc, &absorbed);
    defer reference.deinit(alloc);
    try std.testing.expectEqualSlices(u8, &reference.root(), &tree.root());
}

test "prover vcs_lifted: a lifted tree with pruned leaves refuses to decommit" {
    const alloc = std.testing.allocator;
    var storage: [vectors.column_log_sizes.len][8]M31 = undefined;
    const columns = vectors.columns(&storage);
    var tree = try Prover.commitLifted(alloc, &columns, 6);
    defer tree.deinit(alloc);
    tree.pruneBottomLayers(1);
    try std.testing.expectError(error.InvalidColumnSize, tree.decommit(alloc, &.{ 1, 63 }, &columns));
}
