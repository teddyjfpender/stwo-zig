//! Backend-independent PCS commitment-tree tests.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const vcs_verifier = @import("stwo_core").vcs_lifted.verifier;
const pcs_prover = @import("stwo_prover_engine").pcs;

const M31 = m31.M31;
const ColumnEvaluation = pcs_prover.ColumnEvaluation;
const CommitmentTreeProver = pcs_prover.CommitmentTreeProver;

test "prover pcs: commitment tree decommit verifies" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const Verifier = vcs_verifier.MerkleVerifierLifted(Hasher);
    const alloc = std.testing.allocator;

    const col0 = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(4),
        M31.fromCanonical(5),
        M31.fromCanonical(6),
        M31.fromCanonical(7),
        M31.fromCanonical(8),
    };
    const col1 = [_]M31{
        M31.fromCanonical(9),
        M31.fromCanonical(10),
        M31.fromCanonical(11),
        M31.fromCanonical(12),
    };

    var tree = try CommitmentTreeProver(Hasher).init(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = col0[0..] },
            .{ .log_size = 2, .values = col1[0..] },
        },
    );
    defer tree.deinit(alloc);

    const queries = [_]usize{ 1, 3, 6 };
    var decommit = try tree.decommit(alloc, queries[0..]);
    defer decommit.deinit(alloc);

    const log_sizes = try tree.columnLogSizes(alloc);
    defer alloc.free(log_sizes);

    var verifier = try Verifier.init(alloc, tree.root(), log_sizes);
    defer verifier.deinit(alloc);

    try verifier.verify(
        alloc,
        queries[0..],
        decommit.queried_values,
        decommit.decommitment.decommitment,
    );
}
