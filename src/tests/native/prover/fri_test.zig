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

test "experimental paired source and native quotient roundtrip through FRI" {
    const core = @import("stwo_core");
    const paired = core.pcs.paired_ensemble;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Hasher = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const Prover = FriProver(CpuBackend, Hasher, MerkleChannel);
    const Verifier = core_fri.FriVerifier(Hasher, MerkleChannel);
    const TreeVec = core.pcs.TreeVec;
    const alloc = std.testing.allocator;

    const shape = paired.Shape{
        .log_domain_size = 3,
        .log_degree_bound = 2,
        .original_column_count = 1,
    };
    const config = try core_fri.FriConfig.init(0, 1, 4);
    const domain = core.poly.circle.canonic.CanonicCoset.new(shape.log_domain_size).circleDomain();
    var original: [8]M31 = undefined;
    var all_positions: [8]usize = undefined;
    for (&original, &all_positions, 0..) |*value, *position, row| {
        position.* = row;
        value.* = domain.at(core.utils.bitReverseIndex(row, shape.log_domain_size)).x;
    }

    const sample_point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(13);
    var column_logs = [_]u32{shape.log_degree_bound};
    var logs_tree = [_][]u32{column_logs[0..]};
    var point_column = [_]core.circle.CirclePointQM31{sample_point};
    var points_tree = [_][]core.circle.CirclePointQM31{point_column[0..]};
    var points = [_][][]core.circle.CirclePointQM31{points_tree[0..]};
    var value_column = [_]QM31{sample_point.x};
    var values_tree = [_][]QM31{value_column[0..]};
    var sampled_values = [_][][]QM31{values_tree[0..]};
    var original_tree = [_][]M31{original[0..]};
    var original_queried = [_][][]M31{original_tree[0..]};
    const deep_randomness = QM31.fromBase(M31.fromCanonical(17));
    const all_quotient = try core.pcs.quotients.friAnswers(
        alloc,
        TreeVec([]u32).initOwned(logs_tree[0..]),
        TreeVec([][]core.circle.CirclePointQM31).initOwned(points[0..]),
        TreeVec([][]QM31).initOwned(sampled_values[0..]),
        deep_randomness,
        all_positions[0..],
        TreeVec([][]M31).initOwned(original_queried[0..]),
        shape.log_domain_size,
    );
    defer alloc.free(all_quotient);
    var nonzero_quotient = false;
    for (all_quotient) |value| {
        nonzero_quotient = nonzero_quotient or !value.eql(QM31.zero());
    }
    try std.testing.expect(nonzero_quotient);

    var prover_channel = Channel{};
    const prover_challenges = try paired.drawChallenges(&prover_channel, shape);
    const source_columns = [_][]const M31{original[0..]};
    const paired_values = try paired.foldColumns(
        alloc,
        &source_columns,
        all_quotient,
        shape,
        prover_challenges,
    );
    defer alloc.free(paired_values);
    const column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, paired_values);
    var prover = try Prover.commit(alloc, &prover_channel, config, domain, column);
    var decommit_result = try prover.decommit(alloc, &prover_channel);
    defer decommit_result.deinit(alloc);

    var verifier_channel = Channel{};
    const verifier_challenges = try paired.drawChallenges(&verifier_channel, shape);
    try std.testing.expect(prover_challenges.originals.eql(verifier_challenges.originals));
    try std.testing.expect(prover_challenges.quotient.eql(verifier_challenges.quotient));
    var verifier = try Verifier.commit(
        alloc,
        &verifier_channel,
        config,
        decommit_result.fri_proof.proof,
        core_fri.CirclePolyDegreeBound.init(shape.log_degree_bound),
    );
    defer verifier.deinit(alloc);
    const positions = try verifier.sampleQueryPositions(alloc, &verifier_channel);
    defer alloc.free(positions);
    try std.testing.expectEqualSlices(usize, decommit_result.query_positions, positions);

    const queried_original = try alloc.alloc(M31, positions.len);
    defer alloc.free(queried_original);
    for (queried_original, positions) |*value, position| value.* = original[position];
    var queried_original_tree = [_][]M31{queried_original};
    var queried_original_all = [_][][]M31{queried_original_tree[0..]};
    const queried_quotient = try core.pcs.quotients.friAnswers(
        alloc,
        TreeVec([]u32).initOwned(logs_tree[0..]),
        TreeVec([][]core.circle.CirclePointQM31).initOwned(points[0..]),
        TreeVec([][]QM31).initOwned(sampled_values[0..]),
        deep_randomness,
        positions,
        TreeVec([][]M31).initOwned(queried_original_all[0..]),
        shape.log_domain_size,
    );
    defer alloc.free(queried_quotient);
    const answers = try alloc.alloc(QM31, positions.len);
    defer alloc.free(answers);
    for (answers, queried_original, queried_quotient) |*answer, source, quotient| {
        answer.* = try paired.foldRow(&[_]M31{source}, quotient, shape, verifier_challenges);
    }
    for (answers, positions) |answer, position| {
        try std.testing.expect(answer.eql(paired_values[position]));
    }
    try verifier.decommit(alloc, answers);
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);

    // A changed paired answer must fail the same first-layer authentication.
    var bad_channel = Channel{};
    _ = try paired.drawChallenges(&bad_channel, shape);
    var bad_verifier = try Verifier.commit(
        alloc,
        &bad_channel,
        config,
        decommit_result.fri_proof.proof,
        core_fri.CirclePolyDegreeBound.init(shape.log_degree_bound),
    );
    defer bad_verifier.deinit(alloc);
    const bad_positions = try bad_verifier.sampleQueryPositions(alloc, &bad_channel);
    defer alloc.free(bad_positions);
    const bad_answers = try alloc.dupe(QM31, answers);
    defer alloc.free(bad_answers);
    bad_answers[0] = bad_answers[0].add(QM31.one());
    if (bad_verifier.decommit(alloc, bad_answers)) |_| {
        return error.ExpectedPairedAnswerRejection;
    } else |err| {
        try std.testing.expect(err != error.OutOfMemory);
    }
}

test "paired ensemble binds shape and includes each source exactly once" {
    const core = @import("stwo_core");
    const paired = core.pcs.paired_ensemble;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const alloc = std.testing.allocator;
    const shape = paired.Shape{
        .log_domain_size = 3,
        .log_degree_bound = 2,
        .original_column_count = 2,
    };
    var channel = Channel{};
    const challenges = try paired.drawChallenges(&channel, shape);
    const source0 = [_]M31{M31.fromCanonical(3)} ** 8;
    const source1 = [_]M31{M31.fromCanonical(5)} ** 8;
    const quotient = [_]QM31{QM31.fromBase(M31.fromCanonical(7))} ** 8;
    const columns = [_][]const M31{ &source0, &source1 };
    const folded = try paired.foldColumns(alloc, &columns, &quotient, shape, challenges);
    defer alloc.free(folded);
    const expected = try paired.foldRow(
        &[_]M31{ source0[0], source1[0] },
        quotient[0],
        shape,
        challenges,
    );
    for (folded) |value| try std.testing.expect(value.eql(expected));
    try std.testing.expectError(
        error.InvalidPairedShape,
        paired.foldRow(&[_]M31{source0[0]}, quotient[0], shape, challenges),
    );
    try std.testing.expectError(
        error.InvalidPairedShape,
        paired.foldColumns(alloc, columns[0..1], &quotient, shape, challenges),
    );

    var changed_channel = Channel{};
    _ = try paired.drawChallenges(&changed_channel, .{
        .log_domain_size = 4,
        .log_degree_bound = 2,
        .original_column_count = 2,
    });
    try std.testing.expect(!std.mem.eql(u8, &channel.digest, &changed_channel.digest));
}
