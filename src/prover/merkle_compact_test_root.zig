//! Exact proof equivalence for bounded retained Merkle layers.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const merkle = @import("vcs_lifted/prover.zig");

test "compact Merkle layers preserve mixed-height query proofs exactly" {
    inline for (.{ core.vcs_lifted.blake3_merkle.MerkleHasher, core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher }) |H| {
        const a = std.testing.allocator;
        const Tree = merkle.MerkleProverLifted(H);
        var values: [128]M = undefined;
        for (&values, 0..) |*v, i| v.* = M.fromCanonical(@intCast(17 * i + 3));
        // Deliberately unsorted with equal-height columns: replay must use
        // canonical stable column ordering and parity-preserving lifting.
        const columns = [_][]const M{ &values, values[0..4], values[16..32], values[0..16] };
        var reference = try Tree.commit(a, &columns);
        defer reference.deinit(a);
        const queries = [_]usize{ 0, 1, 3, 4, 15, 16, 63, 64, 126, 127 };
        var expected = try reference.decommit(a, &queries, &columns);
        defer expected.deinit(a);
        for (0..8) |depth| {
            var compact = try Tree.commit(a, &columns);
            defer compact.deinit(a);
            compact.pruneBottomLayers(depth);
            compact.pruneBottomLayers(depth); // Repeated adoption is safe.
            try std.testing.expectEqual(reference.root(), compact.root());
            var actual = try compact.decommit(a, &queries, &columns);
            defer actual.deinit(a);
            try std.testing.expectEqualDeep(expected, actual);
            if (depth > 0) {
                try std.testing.expectEqual(@as(usize, 0), compact.layers[7].len);
                try std.testing.expectError(error.InvalidColumnSize, compact.readHashes(a, 7, &.{0}));
                try std.testing.expectError(error.InvalidColumnSize, compact.decommit(a, &queries, &.{values[0..16]}));
            }
        }
    }
}
