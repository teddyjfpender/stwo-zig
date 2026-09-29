//! Host-backed Metal trees must retain compact-query reconstruction.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const metal = @import("merkle_tree.zig");

test "Metal host-backed compact Merkle openings match the complete tree" {
    const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
    const M31 = core.fields.m31.M31;
    const Host = prover.vcs_lifted.prover.MerkleProverLifted(H);
    const allocator = std.testing.allocator;
    var short: [32]M31 = undefined;
    var long: [256]M31 = undefined;
    for (&short, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(3 + row * 17));
    for (&long, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(9 + row * 13));
    const columns = [_][]const M31{ &long, &short };
    const positions = [_]usize{ 0, 19, 255 };
    var complete = try Host.commit(allocator, &columns);
    defer complete.deinit(allocator);
    var expected = try complete.decommit(allocator, &positions, &columns);
    defer expected.deinit(allocator);
    var compact = try Host.commit(allocator, &columns);
    compact.pruneBottomLayers(4);
    var wrapped = metal.MetalMerkleTree(H).fromHost(compact);
    defer wrapped.deinit(allocator);
    var actual = try wrapped.decommit(allocator, &positions, &columns);
    defer actual.deinit(allocator);
    try std.testing.expectEqualSlices(H.Hash, expected.decommitment.decommitment.hash_witness, actual.decommitment.decommitment.hash_witness);
    for (expected.queried_values, actual.queried_values) |lhs, rhs|
        try std.testing.expectEqualSlices(M31, lhs, rhs);
}

test "Metal host-backed compact Merkle query cache preserves ownership under every allocation failure" {
    const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
    const M31 = core.fields.m31.M31;
    const Host = prover.vcs_lifted.prover.MerkleProverLifted(H);
    const a = std.testing.allocator;
    var values: [256]M31 = undefined;
    for (&values, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(row * 19 + 3));
    const columns = [_][]const M31{ &values, values[0..32] };
    const positions = [_]usize{ 0, 1, 19, 31, 255 };
    var complete = try Host.commit(a, &columns);
    defer complete.deinit(a);
    var expected = try complete.decommit(a, &positions, &columns);
    defer expected.deinit(a);
    var compact = try Host.commit(a, &columns);
    compact.pruneBottomLayers(4);
    var wrapped = metal.MetalMerkleTree(H).fromHost(compact);
    defer wrapped.deinit(a);
    const Check = struct {
        fn run(allocator: std.mem.Allocator, tree: metal.MetalMerkleTree(H), cols: []const []const M31, queries: []const usize, witness: []const H.Hash) !void {
            var result = try tree.decommit(allocator, queries, cols);
            defer result.deinit(allocator);
            try std.testing.expectEqualSlices(H.Hash, witness, result.decommitment.decommitment.hash_witness);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Check.run, .{ wrapped, &columns, &positions, expected.decommitment.decommitment.hash_witness });
}
