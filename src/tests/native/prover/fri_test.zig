//! Native CPU FRI commit/decommit integration tests.

const std = @import("std");
const fri = @import("stwo_prover_engine").fri;
const circle = @import("stwo_core").circle;
const core_fri = @import("stwo_core").fri;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const circle_domain = @import("stwo_core").poly.circle.domain;
const secure_column = @import("stwo_prover_engine").secure_column;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const FriProverError = fri.FriProverError;
const FriProver = fri.FriProver;

test "prover fri: commit and decommit roundtrip with verifier" {
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const Prover = FriProver(CpuBackend, Hasher, MerkleChannel);
    const Verifier = core_fri.FriVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = try core_fri.FriConfig.init(0, 1, 4);
    const column_log_size: u32 = 3;
    const domain = @import("stwo_core").poly.circle.canonic.CanonicCoset
        .new(column_log_size)
        .circleDomain();

    const constant_value = QM31.fromU32Unchecked(7, 0, 0, 0);
    const values = try alloc.alloc(QM31, domain.size());
    defer alloc.free(values);
    @memset(values, constant_value);

    const column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values);

    var prover_channel = Channel{};
    var prover = try Prover.commit(
        alloc,
        &prover_channel,
        config,
        domain,
        column,
    );
    var decommit_result = try prover.decommit(alloc, &prover_channel);
    defer decommit_result.deinit(alloc);

    var verifier_channel = Channel{};
    const bound = core_fri.CirclePolyDegreeBound.init(column_log_size - config.log_blowup_factor);
    var verifier = try Verifier.commit(
        alloc,
        &verifier_channel,
        config,
        decommit_result.fri_proof.proof,
        bound,
    );
    defer verifier.deinit(alloc);

    const query_positions = try verifier.sampleQueryPositions(alloc, &verifier_channel);
    defer alloc.free(query_positions);
    try std.testing.expectEqualSlices(usize, decommit_result.query_positions, query_positions);

    const first_layer_answers = try alloc.alloc(QM31, query_positions.len);
    defer alloc.free(first_layer_answers);
    @memset(first_layer_answers, constant_value);
    try verifier.decommit(alloc, first_layer_answers);
}

test "prover fri: commit rejects non-canonic domain" {
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const Prover = FriProver(CpuBackend, Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const invalid_domain = circle_domain.CircleDomain.new(
        circle.Coset.new(circle.CirclePointIndex.generator(), 3),
    );
    try std.testing.expect(!invalid_domain.isCanonic());

    const values = try alloc.alloc(QM31, invalid_domain.size());
    defer alloc.free(values);
    @memset(values, QM31.one());

    const column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values);
    var channel = Channel{};
    try std.testing.expectError(
        FriProverError.NotCanonicDomain,
        Prover.commit(
            alloc,
            &channel,
            try core_fri.FriConfig.init(0, 1, 3),
            invalid_domain,
            column,
        ),
    );
}

test "prover fri: commit rejects high-degree last layer" {
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const Prover = FriProver(CpuBackend, Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = try core_fri.FriConfig.init(0, 1, 3);
    const domain = @import("stwo_core").poly.circle.canonic.CanonicCoset
        .new(3)
        .circleDomain();

    const values = try alloc.alloc(QM31, domain.size());
    defer alloc.free(values);
    for (values, 0..) |*v, i| {
        v.* = QM31.fromBase(M31.fromCanonical(@intCast(i + 1)));
    }

    const column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values);
    var channel = Channel{};
    try std.testing.expectError(
        FriProverError.InvalidLastLayerDegree,
        Prover.commit(alloc, &channel, config, domain, column),
    );
}
