//! PCS lifting-domain integration tests.

const std = @import("std");
const stwo_core = @import("stwo_core");
const stwo_prover = @import("stwo_prover_engine");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;

const Hasher = stwo_core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
const MerkleChannel = stwo_core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
const Channel = stwo_core.channel.blake2s.Blake2sChannel;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const CirclePointQM31 = stwo_core.circle.CirclePointQM31;
const TreeVec = stwo_core.pcs.TreeVec;
const ColumnEvaluation = stwo_prover.pcs.ColumnEvaluation;
const Scheme = stwo_prover.pcs.CommitmentSchemeProver(
    CpuBackend,
    Hasher,
    MerkleChannel,
);
const Verifier = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
    Hasher,
    MerkleChannel,
);

test "unsampled high-domain tree does not lift the proof domain" {
    const allocator = std.testing.allocator;
    const config = stwo_core.pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try stwo_core.fri.FriConfig.init(0, 1, 3),
    };
    var prover_channel = Channel{};
    var scheme = try Scheme.init(allocator, config);

    const high_values = [_]M31{M31.fromCanonical(23)} ** 32;
    try scheme.commit(
        allocator,
        &[_]ColumnEvaluation{.{ .log_size = 5, .values = high_values[0..] }},
        &prover_channel,
    );
    const composition_values = [_]M31{M31.fromCanonical(29)} ** 8;
    try scheme.commit(
        allocator,
        &[_]ColumnEvaluation{.{
            .log_size = 3,
            .values = composition_values[0..],
        }},
        &prover_channel,
    );

    const sample_point = stwo_core.circle.SECURE_FIELD_CIRCLE_GEN.mul(47);
    const prover_points = try sampleShape(allocator, sample_point);
    var extended_proof = try scheme.proveValues(
        allocator,
        prover_points,
        &prover_channel,
    );
    defer extended_proof.aux.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, 0),
        extended_proof.proof.sampled_values.items[0][0].len,
    );
    try std.testing.expect(
        extended_proof.proof.sampled_values.items[1][0][0].eql(
            QM31.fromBase(M31.fromCanonical(29)),
        ),
    );

    var verifier_channel = Channel{};
    var verifier = try Verifier.init(allocator, config);
    defer verifier.deinit(allocator);
    try verifier.commit(
        allocator,
        extended_proof.proof.commitments.items[0],
        &[_]u32{5},
        &verifier_channel,
    );
    try verifier.commit(
        allocator,
        extended_proof.proof.commitments.items[1],
        &[_]u32{3},
        &verifier_channel,
    );
    try verifier.verifyValues(
        allocator,
        try sampleShape(allocator, sample_point),
        extended_proof.proof,
        &verifier_channel,
    );
}

fn sampleShape(
    allocator: std.mem.Allocator,
    sample_point: CirclePointQM31,
) !TreeVec([][]CirclePointQM31) {
    const empty_points = try allocator.alloc(CirclePointQM31, 0);
    errdefer allocator.free(empty_points);
    const high_tree = try allocator.dupe(
        []CirclePointQM31,
        &[_][]CirclePointQM31{empty_points},
    );
    errdefer allocator.free(high_tree);

    const composition_points = try allocator.dupe(
        CirclePointQM31,
        &[_]CirclePointQM31{sample_point},
    );
    errdefer allocator.free(composition_points);
    const composition_tree = try allocator.dupe(
        []CirclePointQM31,
        &[_][]CirclePointQM31{composition_points},
    );
    errdefer allocator.free(composition_tree);

    return .initOwned(try allocator.dupe(
        [][]CirclePointQM31,
        &[_][][]CirclePointQM31{ high_tree, composition_tree },
    ));
}
