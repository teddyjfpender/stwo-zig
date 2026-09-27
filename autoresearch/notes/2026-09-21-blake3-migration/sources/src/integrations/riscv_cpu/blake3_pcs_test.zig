//! PCS sampled opening and FRI proof integration tests.

const std = @import("std");
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs_core = @import("stwo_core").pcs;
const vcs_verifier = @import("stwo_core").vcs_lifted.verifier;
const pcs_prover = @import("stwo_prover_engine").pcs;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const PcsConfig = pcs_core.PcsConfig;
const TreeVec = pcs_core.TreeVec;
const ColumnEvaluation = pcs_prover.ColumnEvaluation;
const CommitmentSchemeProver = pcs_prover.CommitmentSchemeProver;

test "BLAKE3 CPU PCS and FRI roundtrip with core verifier" {
    try pcsRoundtrip(false);
    try pcsRoundtrip(true);
}

fn pcsRoundtrip(tamper: bool) !void {
    const Hasher = @import("stwo_core").vcs_lifted.blake3_merkle.MerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake3_merkle.MerkleChannel;
    const Channel = @import("stwo_core").channel.blake3.Channel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const Verifier = @import("stwo_core").pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = PcsConfig{
        .pow_bits = 4,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    var prover_channel = Channel{};
    var scheme = try Scheme.init(alloc, config);

    const column_values = [_]M31{ M31.fromCanonical(19), M31.fromCanonical(20), M31.fromCanonical(21), M31.fromCanonical(22), M31.fromCanonical(23), M31.fromCanonical(24), M31.fromCanonical(25), M31.fromCanonical(26) };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = column_values[0..] },
        },
        &prover_channel,
    );

    const sample_point = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN.mul(73);
    const sampled_points_col_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
    });
    const sampled_points_tree_prover = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col_prover,
    });
    const sampled_points_prover = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_prover}),
    );

    var extended_proof = try scheme.proveValues(
        alloc,
        sampled_points_prover,
        &prover_channel,
    );
    defer extended_proof.aux.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), extended_proof.proof.sampled_values.items.len);
    try std.testing.expectEqual(@as(usize, 1), extended_proof.proof.sampled_values.items[0].len);
    try std.testing.expectEqual(@as(usize, 1), extended_proof.proof.sampled_values.items[0][0].len);
    const sampled_points_col_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
    });
    const sampled_points_tree_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col_verify,
    });
    const sampled_points_verify = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_verify}),
    );

    var verifier_channel = Channel{};
    var verifier = try Verifier.init(alloc, config);
    defer verifier.deinit(alloc);
    try verifier.commit(
        alloc,
        extended_proof.proof.commitments.items[0],
        &[_]u32{3},
        &verifier_channel,
    );
    if (tamper) {
        const sample = &extended_proof.proof.sampled_values.items[0][0][0];
        sample.* = sample.add(QM31.one());
        if (verifier.verifyValues(alloc, sampled_points_verify, extended_proof.proof, &verifier_channel)) |_| {
            return error.TamperedOpeningAccepted;
        } else |err| {
            if (err == error.OutOfMemory) return err;
        }
    } else {
        try verifier.verifyValues(alloc, sampled_points_verify, extended_proof.proof, &verifier_channel);
        try std.testing.expectEqualSlices(u8, &prover_channel.digestBytes(), &verifier_channel.digestBytes());
        try std.testing.expectEqual(prover_channel.n_draws, verifier_channel.n_draws);
    }
}

test "BLAKE3 CPU commitments reject tampered roots and wrong hash family" {
    const Hasher = @import("stwo_core").vcs_lifted.blake3_merkle.MerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake3_merkle.MerkleChannel;
    const Channel = @import("stwo_core").channel.blake3.Channel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const Verifier = vcs_verifier.MerkleVerifierLifted(Hasher);
    const alloc = std.testing.allocator;

    var scheme = try Scheme.init(alloc, PcsConfig.default());
    defer scheme.deinit(alloc);

    var channel = Channel{};

    const tree0 = [_]M31{ M31.fromCanonical(1), M31.fromCanonical(2), M31.fromCanonical(3), M31.fromCanonical(4) };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 2, .values = tree0[0..] }},
        &channel,
    );

    const tree1 = [_]M31{
        M31.fromCanonical(10),
        M31.fromCanonical(11),
        M31.fromCanonical(12),
        M31.fromCanonical(13),
        M31.fromCanonical(14),
        M31.fromCanonical(15),
        M31.fromCanonical(16),
        M31.fromCanonical(17),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 3, .values = tree1[0..] }},
        &channel,
    );

    const tree0_queries = try alloc.dupe(usize, &[_]usize{ 3, 0, 3, 1 });
    const tree1_queries = try alloc.dupe(usize, &[_]usize{ 6, 1, 6, 0 });
    var query_tree = TreeVec([]const usize).initOwned(
        try alloc.dupe([]const usize, &[_][]const usize{ tree0_queries, tree1_queries }),
    );
    defer query_tree.deinitDeep(alloc);

    var decommit = try scheme.decommitByTreePositions(alloc, query_tree);
    defer decommit.deinit(alloc);

    try std.testing.expectEqualSlices(M31, &[_]M31{
        scheme.trees.items[0].columns[0].values[3],
        scheme.trees.items[0].columns[0].values[0],
        scheme.trees.items[0].columns[0].values[3],
        scheme.trees.items[0].columns[0].values[1],
    }, decommit.queried_values.items[0][0]);
    try std.testing.expectEqualSlices(M31, &[_]M31{
        scheme.trees.items[1].columns[0].values[6],
        scheme.trees.items[1].columns[0].values[1],
        scheme.trees.items[1].columns[0].values[6],
        scheme.trees.items[1].columns[0].values[0],
    }, decommit.queried_values.items[1][0]);

    var sizes = try scheme.columnLogSizes(alloc);
    defer sizes.deinitDeep(alloc);

    var verifier0 = try Verifier.init(alloc, scheme.trees.items[0].root(), sizes.items[0]);
    defer verifier0.deinit(alloc);
    try verifier0.verify(
        alloc,
        tree0_queries,
        decommit.queried_values.items[0],
        decommit.decommitments.items[0],
    );

    var verifier1 = try Verifier.init(alloc, scheme.trees.items[1].root(), sizes.items[1]);
    defer verifier1.deinit(alloc);
    try verifier1.verify(
        alloc,
        tree1_queries,
        decommit.queried_values.items[1],
        decommit.decommitments.items[1],
    );
    const root = scheme.trees.items[0].root();
    for (0..32) |i| {
        var changed = root;
        changed[i] ^= 0x80;
        var invalid = try Verifier.init(alloc, changed, sizes.items[0]);
        defer invalid.deinit(alloc);
        try std.testing.expectError(error.RootMismatch, invalid.verify(alloc, tree0_queries, decommit.queried_values.items[0], decommit.decommitments.items[0]));
    }
    const OldHasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const OldVerifier = vcs_verifier.MerkleVerifierLifted(OldHasher);
    var old = try OldVerifier.init(alloc, root, sizes.items[0]);
    defer old.deinit(alloc);
    try std.testing.expectError(error.RootMismatch, old.verify(alloc, tree0_queries, decommit.queried_values.items[0], .{ .hash_witness = decommit.decommitments.items[0].hash_witness }));
}
