//! PCS sampled opening and FRI proof integration tests.

const std = @import("std");
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs_core = @import("stwo_core").pcs;
const pcs_utils = @import("stwo_core").pcs.utils;
const core_quotients = @import("stwo_core").pcs.quotients;
const vcs_verifier = @import("stwo_core").vcs_lifted.verifier;
const canonic = @import("stwo_core").poly.circle.canonic;
const component_prover = @import("stwo_prover_impl").air.component_prover;
const prover_circle = @import("stwo_prover_impl").poly.circle;
const prover_fri = @import("stwo_prover_impl").fri;
const pcs_prover = @import("stwo_prover_impl").pcs;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const PcsConfig = pcs_core.PcsConfig;
const TreeVec = pcs_core.TreeVec;
const ColumnEvaluation = pcs_prover.ColumnEvaluation;
const CommitmentSchemeError = pcs_prover.CommitmentSchemeError;
const CommitmentSchemeProver = pcs_prover.CommitmentSchemeProver;

test "prover pcs: prove values from samples roundtrip with core verifier" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const Verifier = @import("stwo_core").pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    var prover_channel = Channel{};
    var scheme = try Scheme.init(alloc, config);

    const column_values = [_]M31{
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = column_values[0..] },
        },
        &prover_channel,
    );

    const sample_point = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN.mul(13);
    const sample_value = QM31.fromBase(M31.fromCanonical(5));

    const sampled_points_col_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
    });
    const sampled_points_tree_prover = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col_prover,
    });
    const sampled_points_prover = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_prover}),
    );

    const sampled_values_col = try alloc.dupe(QM31, &[_]QM31{sample_value});
    const sampled_values_tree = try alloc.dupe([]QM31, &[_][]QM31{sampled_values_col});
    const sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{sampled_values_tree}),
    );

    var extended_proof = try scheme.proveValuesFromSamples(
        alloc,
        sampled_points_prover,
        sampled_values,
        &prover_channel,
    );
    defer extended_proof.aux.deinit(alloc);

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
    try verifier.verifyValues(
        alloc,
        sampled_points_verify,
        extended_proof.proof,
        &verifier_channel,
    );
}

test "prover pcs: prove values computes sampled values in prover" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const Verifier = @import("stwo_core").pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    var prover_channel = Channel{};
    var scheme = try Scheme.init(alloc, config);

    const column_values = [_]M31{
        M31.fromCanonical(19),
        M31.fromCanonical(19),
        M31.fromCanonical(19),
        M31.fromCanonical(19),
        M31.fromCanonical(19),
        M31.fromCanonical(19),
        M31.fromCanonical(19),
        M31.fromCanonical(19),
    };
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
    try std.testing.expect(extended_proof.proof.sampled_values.items[0][0][0].eql(
        QM31.fromBase(M31.fromCanonical(19)),
    ));

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
    try verifier.verifyValues(
        alloc,
        sampled_points_verify,
        extended_proof.proof,
        &verifier_channel,
    );
}

test "prover pcs: stored coefficients fast path computes sampled values" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const Verifier = @import("stwo_core").pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 2, 3),
    };

    var prover_channel = Channel{};
    var scheme = try Scheme.init(alloc, config);
    scheme.setStorePolynomialsCoefficients();

    const column_values = [_]M31{
        M31.fromCanonical(31),
        M31.fromCanonical(31),
        M31.fromCanonical(31),
        M31.fromCanonical(31),
        M31.fromCanonical(31),
        M31.fromCanonical(31),
        M31.fromCanonical(31),
        M31.fromCanonical(31),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = column_values[0..] },
        },
        &prover_channel,
    );

    const coeffs = scheme.trees.items[0].coefficients orelse return CommitmentSchemeError.ShapeMismatch;
    try std.testing.expectEqual(@as(usize, 1), coeffs.len);
    try std.testing.expectEqual(@as(u32, 3), coeffs[0].logSize());

    const sample_point = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN.mul(59);
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
    try verifier.verifyValues(
        alloc,
        sampled_points_verify,
        extended_proof.proof,
        &verifier_channel,
    );
}

test "prover pcs: prove values handles repeated sampled points across columns" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const Verifier = @import("stwo_core").pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    var prover_channel = Channel{};
    var scheme = try Scheme.init(alloc, config);

    const col0 = [_]M31{
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
    };
    const col1 = [_]M31{
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = col0[0..] },
            .{ .log_size = 3, .values = col1[0..] },
        },
        &prover_channel,
    );

    const sample_point = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN.mul(97);
    const sampled_points_col0_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_col1_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_tree_prover = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col0_prover,
        sampled_points_col1_prover,
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
    try std.testing.expectEqual(@as(usize, 2), extended_proof.proof.sampled_values.items[0].len);
    try std.testing.expectEqual(@as(usize, 3), extended_proof.proof.sampled_values.items[0][0].len);
    try std.testing.expectEqual(@as(usize, 3), extended_proof.proof.sampled_values.items[0][1].len);
    for (extended_proof.proof.sampled_values.items[0][0]) |value| {
        try std.testing.expect(value.eql(QM31.fromBase(M31.fromCanonical(9))));
    }
    for (extended_proof.proof.sampled_values.items[0][1]) |value| {
        try std.testing.expect(value.eql(QM31.fromBase(M31.fromCanonical(13))));
    }

    const sampled_points_col0_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_col1_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_tree_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col0_verify,
        sampled_points_col1_verify,
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
        &[_]u32{ 3, 3 },
        &verifier_channel,
    );
    try verifier.verifyValues(
        alloc,
        sampled_points_verify,
        extended_proof.proof,
        &verifier_channel,
    );
}

test "prover pcs: prove values handles repeated sampled points across mixed log sizes" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const Verifier = @import("stwo_core").pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    var prover_channel = Channel{};
    var scheme = try Scheme.init(alloc, config);

    const col0 = [_]M31{
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
    };
    const col1 = [_]M31{
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
        M31.fromCanonical(13),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = col0[0..] },
            .{ .log_size = 2, .values = col1[0..] },
        },
        &prover_channel,
    );

    const sample_point = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN.mul(131);
    const sampled_points_col0_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_col1_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_tree_prover = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col0_prover,
        sampled_points_col1_prover,
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
    try std.testing.expectEqual(@as(usize, 2), extended_proof.proof.sampled_values.items[0].len);
    try std.testing.expectEqual(@as(usize, 3), extended_proof.proof.sampled_values.items[0][0].len);
    try std.testing.expectEqual(@as(usize, 3), extended_proof.proof.sampled_values.items[0][1].len);
    for (extended_proof.proof.sampled_values.items[0][0]) |value| {
        try std.testing.expect(value.eql(QM31.fromBase(M31.fromCanonical(9))));
    }
    for (extended_proof.proof.sampled_values.items[0][1]) |value| {
        try std.testing.expect(value.eql(QM31.fromBase(M31.fromCanonical(13))));
    }

    const sampled_points_col0_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_col1_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
        sample_point,
        sample_point,
    });
    const sampled_points_tree_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col0_verify,
        sampled_points_col1_verify,
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
        &[_]u32{ 3, 2 },
        &verifier_channel,
    );
    try verifier.verifyValues(
        alloc,
        sampled_points_verify,
        extended_proof.proof,
        &verifier_channel,
    );
}

test "prover pcs: prove values from samples rejects shape mismatch" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    var scheme = try Scheme.init(alloc, .{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 2),
    });

    const column_values = [_]M31{
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
    };
    var channel = Channel{};
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 2, .values = column_values[0..] }},
        &channel,
    );

    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(try alloc.alloc([][]CirclePointQM31, 0));
    const sampled_values = TreeVec([][]QM31).initOwned(try alloc.alloc([][]QM31, 0));
    try std.testing.expectError(
        CommitmentSchemeError.ShapeMismatch,
        scheme.proveValuesFromSamples(
            alloc,
            sampled_points,
            sampled_values,
            &channel,
        ),
    );
}

test "prover pcs: prove values paths support non-zero blowup" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const Verifier = @import("stwo_core").pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    var scheme_samples = try Scheme.init(alloc, .{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 2, 2),
    });

    const column_values = [_]M31{
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
    };
    var channel = Channel{};
    try scheme_samples.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 2, .values = column_values[0..] }},
        &channel,
    );
    try std.testing.expectEqual(@as(u32, 4), scheme_samples.trees.items[0].columns[0].log_size);
    try std.testing.expectEqual(@as(usize, 16), scheme_samples.trees.items[0].columns[0].values.len);

    const sample_point = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN.mul(31);
    const sampled_points_col = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col});
    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree}),
    );
    const sampled_points_col_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col_verify});
    const sampled_points_verify = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_verify}),
    );

    const sampled_values_col = try alloc.dupe(QM31, &[_]QM31{QM31.fromBase(M31.fromCanonical(5))});
    const sampled_values_tree = try alloc.dupe([]QM31, &[_][]QM31{sampled_values_col});
    const sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{sampled_values_tree}),
    );

    var proof_samples = try scheme_samples.proveValuesFromSamples(
        alloc,
        sampled_points,
        sampled_values,
        &channel,
    );
    defer proof_samples.aux.deinit(alloc);

    var verifier_samples = try Verifier.init(alloc, .{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 2, 2),
    });
    defer verifier_samples.deinit(alloc);

    var verifier_channel = Channel{};
    try verifier_samples.commit(
        alloc,
        proof_samples.proof.commitments.items[0],
        &[_]u32{2},
        &verifier_channel,
    );
    try verifier_samples.verifyValues(
        alloc,
        sampled_points_verify,
        proof_samples.proof,
        &verifier_channel,
    );

    var scheme_points = try Scheme.init(alloc, .{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 2, 2),
    });
    try scheme_points.commit(
        alloc,
        &[_]ColumnEvaluation{.{ .log_size = 2, .values = column_values[0..] }},
        &channel,
    );

    const sampled_points_col_only = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree_only = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col_only});
    const sampled_points_only = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_only}),
    );
    const sampled_points_col_only_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree_only_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col_only_verify});
    const sampled_points_only_verify = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_only_verify}),
    );

    var proof_points = try scheme_points.proveValues(
        alloc,
        sampled_points_only,
        &channel,
    );
    defer proof_points.aux.deinit(alloc);

    var verifier_points = try Verifier.init(alloc, .{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 2, 2),
    });
    defer verifier_points.deinit(alloc);

    var verifier_points_channel = Channel{};
    try verifier_points.commit(
        alloc,
        proof_points.proof.commitments.items[0],
        &[_]u32{2},
        &verifier_points_channel,
    );
    try verifier_points.verifyValues(
        alloc,
        sampled_points_only_verify,
        proof_points.proof,
        &verifier_points_channel,
    );
}

test "prover pcs: inconsistent sampled values are rejected by fri degree check" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    var prover_channel = Channel{};
    var scheme = try Scheme.init(alloc, config);

    const column_values = [_]M31{
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = column_values[0..] },
        },
        &prover_channel,
    );

    const sample_point = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN.mul(13);
    const bad_sample_value = QM31.fromBase(M31.fromCanonical(6));

    const sampled_points_col = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
    });
    const sampled_points_tree = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col,
    });
    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree}),
    );

    const sampled_values_col = try alloc.dupe(QM31, &[_]QM31{bad_sample_value});
    const sampled_values_tree = try alloc.dupe([]QM31, &[_][]QM31{sampled_values_col});
    const sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{sampled_values_tree}),
    );

    try std.testing.expectError(
        prover_fri.FriProverError.InvalidLastLayerDegree,
        scheme.proveValuesFromSamples(
            alloc,
            sampled_points,
            sampled_values,
            &prover_channel,
        ),
    );
}

test "prover pcs: prove values rejects sampled point on domain" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const alloc = std.testing.allocator;
    const canonic_domain = canonic.CanonicCoset.new(3).circleDomain();

    var prover_channel = Channel{};
    var scheme = try Scheme.init(alloc, .{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    });

    const column_values = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
    };
    try scheme.commit(
        alloc,
        &[_]ColumnEvaluation{
            .{ .log_size = 3, .values = column_values[0..] },
        },
        &prover_channel,
    );

    const sampled_points_col = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        .{
            .x = QM31.fromBase(canonic_domain.at(0).x),
            .y = QM31.fromBase(canonic_domain.at(0).y),
        },
    });
    const sampled_points_tree = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col,
    });
    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree}),
    );

    const prove_result = scheme.proveValues(alloc, sampled_points, &prover_channel);
    try std.testing.expectError(
        error.DegenerateLine,
        prove_result,
    );
}
