//! Device custody and proof parity for bounded resident Merkle storage.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const metal = @import("merkle_tree.zig");
const runtime_mod = @import("runtime.zig");
const M31 = core.fields.m31.M31;

test "Metal resident compact Merkle preserves roots mixed-height openings and bounded custody" {
    const a = std.testing.allocator;
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    const long = try a.alloc(M31, 4096);
    defer a.free(long);
    const medium = try a.alloc(M31, 256);
    defer a.free(medium);
    const short = try a.alloc(M31, 16);
    defer a.free(short);
    for (long, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(3 + row * 17));
    for (medium, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(9 + row * 13));
    for (short, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(7 + row * 31));
    const columns = [_][]const M31{ long, short, medium, long };
    const positions = [_]usize{ 0, 1, 19, 31, 128, 2999, 4095 };
    inline for (.{ core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher, core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher, core.vcs_lifted.blake3_merkle.MerkleHasher }) |H| {
        const Host = prover.vcs_lifted.prover.MerkleProverLifted(H);
        var complete = try Host.commit(a, &columns);
        defer complete.deinit(a);
        var expected = try complete.decommit(a, &positions, &columns);
        defer expected.deinit(a);
        const budget = try prover.host_budget_allocator.SharedHostBudget.create(a, 4 * 1024 * 1024);
        defer budget.destroy();
        var compact = try metal.MetalMerkleTree(H).commit(&runtime, a, &columns);
        defer compact.deinit(a);
        const tree = &compact.storage.resident.tree;
        // The legacy standalone commit is uncapped. Give its completed owner
        // an explicit reservation to exercise compaction's admission contract.
        tree.external_reservation = try budget.reserveExternal(512 * 1024);
        const initial_root = compact.root();
        try std.testing.expectEqualSlices(u8, &complete.root(), &initial_root);
        // Exhaust temporary headroom: admission must leave the complete tree
        // usable, rather than silently allocating outside the shared budget.
        var occupied = try budget.reserveExternal(budget.snapshot().limit - budget.snapshot().live_bytes);
        try std.testing.expect(!tree.pruneBottomLayers(4));
        try std.testing.expectEqual(@as(u32, 0), tree.pruned_bottom_layers);
        occupied.deinit();
        try std.testing.expect(!@import("runtime/resident_data.zig").stwo_zig_metal_tree_prune_bottom_v1(runtime.handle, tree.handle, 4, 1));
        try std.testing.expect(tree.pruneBottomLayers(4));
        try std.testing.expect(!tree.pruneBottomLayers(4));
        try std.testing.expectEqualSlices(u8, &initial_root, &(try tree.root()).hash);
        try std.testing.expectError(error.RootReadFailed, tree.copyHashes(a, 12, &.{0}));
        var actual = try compact.decommit(a, &positions, &columns);
        defer actual.deinit(a);
        try std.testing.expectEqualSlices(H.Hash, expected.decommitment.decommitment.hash_witness, actual.decommitment.decommitment.hash_witness);
        for (expected.queried_values, actual.queried_values) |lhs, rhs|
            try std.testing.expectEqualSlices(M31, lhs, rhs);
        for (expected.decommitment.aux.all_node_values, actual.decommitment.aux.all_node_values) |lhs, rhs|
            try std.testing.expectEqualDeep(lhs, rhs);
    }
}
