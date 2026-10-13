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
    var column_logs = [_]u32{shape.log_domain_size};
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

    const source_columns = [_][]const M31{original[0..]};
    const SourceProver = @import("stwo_prover_engine").vcs_lifted.prover.MerkleProverLifted(Hasher);
    var source_tree = try SourceProver.commit(alloc, &source_columns);
    defer source_tree.deinit(alloc);
    const source_root = source_tree.root();

    var prover_channel = Channel{};
    MerkleChannel.mixRoot(&prover_channel, source_root);
    prover_channel.mixFelts(&[_]QM31{ sample_point.x, sample_point.y, sample_point.x });
    const prover_challenges = try paired.drawChallenges(&prover_channel, shape);
    const quotient_columns = [_][]const QM31{all_quotient};
    const paired_values = try paired.foldColumns(
        alloc,
        &source_columns,
        &quotient_columns,
        shape,
        prover_challenges,
    );
    defer alloc.free(paired_values);
    const column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, paired_values);
    var prover = try Prover.commit(alloc, &prover_channel, config, domain, column);
    var decommit_result = try prover.decommit(alloc, &prover_channel);
    defer decommit_result.deinit(alloc);

    var verifier_channel = Channel{};
    MerkleChannel.mixRoot(&verifier_channel, source_root);
    verifier_channel.mixFelts(&[_]QM31{ sample_point.x, sample_point.y, sample_point.x });
    const verifier_challenges = try paired.drawChallenges(&verifier_channel, shape);
    try std.testing.expect(prover_challenges.batch.eql(verifier_challenges.batch));
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

    var source_opening = try source_tree.decommit(alloc, positions, &source_columns);
    defer source_opening.deinit(alloc);
    const queried_original = source_opening.queried_values[0];
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
        answer.* = try paired.foldRow(&[_]M31{source}, &[_]QM31{quotient}, shape, verifier_challenges);
    }
    for (answers, positions) |answer, position| {
        try std.testing.expect(answer.eql(paired_values[position]));
    }
    const SourceVerifier = core.vcs_lifted.verifier.MerkleVerifierLifted(Hasher);
    var source_verifier = try SourceVerifier.init(alloc, source_root, &[_]u32{shape.log_domain_size});
    defer source_verifier.deinit(alloc);
    const authenticated_sources = [_][]const M31{queried_original};
    const authenticated_answers = try core.pcs.paired_authenticated.authenticatedAnswers(
        Hasher,
        alloc,
        source_verifier,
        positions,
        &authenticated_sources,
        source_opening.decommitment.decommitment,
        &[_]core.circle.CirclePointQM31{sample_point},
        &[_]QM31{sample_point.x},
        shape,
        verifier_challenges,
    );
    defer alloc.free(authenticated_answers);
    try std.testing.expectEqualSlices(QM31, answers, authenticated_answers);
    try verifier.decommit(alloc, authenticated_answers);
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);

    // A changed authenticated source is refused before a paired answer exists.
    const corrupted_source = try alloc.dupe(M31, queried_original);
    defer alloc.free(corrupted_source);
    corrupted_source[0] = corrupted_source[0].add(M31.one());
    const corrupted_sources = [_][]const M31{corrupted_source};
    try std.testing.expectError(
        error.RootMismatch,
        core.pcs.paired_authenticated.authenticatedAnswers(
            Hasher,
            alloc,
            source_verifier,
            positions,
            &corrupted_sources,
            source_opening.decommitment.decommitment,
            &[_]core.circle.CirclePointQM31{sample_point},
            &[_]QM31{sample_point.x},
            shape,
            verifier_challenges,
        ),
    );

    // A changed paired answer must fail the same first-layer authentication.
    var bad_channel = Channel{};
    MerkleChannel.mixRoot(&bad_channel, source_root);
    bad_channel.mixFelts(&[_]QM31{ sample_point.x, sample_point.y, sample_point.x });
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
    const quotient0 = [_]QM31{QM31.fromBase(M31.fromCanonical(7))} ** 8;
    const quotient1 = [_]QM31{QM31.fromBase(M31.fromCanonical(11))} ** 8;
    const columns = [_][]const M31{ &source0, &source1 };
    const quotients = [_][]const QM31{ &quotient0, &quotient1 };
    const folded = try paired.foldColumns(alloc, &columns, &quotients, shape, challenges);
    defer alloc.free(folded);
    const expected = try paired.foldRow(
        &[_]M31{ source0[0], source1[0] },
        &[_]QM31{ quotient0[0], quotient1[0] },
        shape,
        challenges,
    );
    const lambda = challenges.batch;
    const manual = QM31.fromBase(source0[0])
        .add(lambda.mul(quotient0[0]))
        .add(lambda.square().mul(QM31.fromBase(source1[0])))
        .add(lambda.square().mul(lambda).mul(quotient1[0]));
    try std.testing.expect(expected.eql(manual));
    for (folded) |value| try std.testing.expect(value.eql(expected));
    try std.testing.expectError(
        error.InvalidPairedShape,
        paired.foldRow(&[_]M31{source0[0]}, &[_]QM31{quotient0[0]}, shape, challenges),
    );
    try std.testing.expectError(
        error.InvalidPairedShape,
        paired.foldColumns(alloc, columns[0..1], &quotients, shape, challenges),
    );

    var changed_channel = Channel{};
    _ = try paired.drawChallenges(&changed_channel, .{
        .log_domain_size = 4,
        .log_degree_bound = 2,
        .original_column_count = 2,
    });
    try std.testing.expect(!std.mem.eql(u8, &channel.digest, &changed_channel.digest));
}

test "paired authenticated bridge binds both source columns and their order" {
    const core = @import("stwo_core");
    const paired = core.pcs.paired_ensemble;
    const Hasher = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const SourceProver = @import("stwo_prover_engine").vcs_lifted.prover.MerkleProverLifted(Hasher);
    const SourceVerifier = core.vcs_lifted.verifier.MerkleVerifierLifted(Hasher);
    const alloc = std.testing.allocator;
    const shape = paired.Shape{ .log_domain_size = 3, .log_degree_bound = 2, .original_column_count = 2 };
    const original0 = [_]M31{M31.fromCanonical(3)} ** 8;
    const original1 = [_]M31{M31.fromCanonical(5)} ** 8;
    const source_columns = [_][]const M31{ &original0, &original1 };
    var source_tree = try SourceProver.commit(alloc, &source_columns);
    defer source_tree.deinit(alloc);
    const positions = [_]usize{ 0, 3, 7 };
    var source_opening = try source_tree.decommit(alloc, &positions, &source_columns);
    defer source_opening.deinit(alloc);
    var source_verifier = try SourceVerifier.init(alloc, source_tree.root(), &[_]u32{ 3, 3 });
    defer source_verifier.deinit(alloc);
    const query_columns = [_][]const M31{
        source_opening.queried_values[0],
        source_opening.queried_values[1],
    };
    const point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(13);
    const points = [_]core.circle.CirclePointQM31{ point, point };
    const claims = [_]QM31{
        QM31.fromBase(original0[0]),
        QM31.fromBase(original1[0]),
    };
    var channel = Channel{};
    MerkleChannel.mixRoot(&channel, source_tree.root());
    channel.mixFelts(&[_]QM31{ point.x, point.y, claims[0], claims[1] });
    const challenges = try paired.drawChallenges(&channel, shape);
    const answers = try core.pcs.paired_authenticated.authenticatedAnswers(
        Hasher,
        alloc,
        source_verifier,
        &positions,
        &query_columns,
        source_opening.decommitment.decommitment,
        &points,
        &claims,
        shape,
        challenges,
    );
    defer alloc.free(answers);
    for (answers, source_opening.queried_values[0], source_opening.queried_values[1]) |answer, f0, f1| {
        const expected = try paired.foldRow(
            &[_]M31{ f0, f1 },
            &[_]QM31{ QM31.zero(), QM31.zero() },
            shape,
            challenges,
        );
        try std.testing.expect(answer.eql(expected));
    }

    const swapped = [_][]const M31{
        source_opening.queried_values[1],
        source_opening.queried_values[0],
    };
    try std.testing.expectError(
        error.RootMismatch,
        core.pcs.paired_authenticated.authenticatedAnswers(
            Hasher,
            alloc,
            source_verifier,
            &positions,
            &swapped,
            source_opening.decommitment.decommitment,
            &points,
            &claims,
            shape,
            challenges,
        ),
    );
    var wrong_height = try SourceVerifier.init(alloc, source_tree.root(), &[_]u32{ 3, 2 });
    defer wrong_height.deinit(alloc);
    try std.testing.expectError(
        error.InvalidPairedShape,
        core.pcs.paired_authenticated.authenticatedAnswers(
            Hasher,
            alloc,
            wrong_height,
            &positions,
            &query_columns,
            source_opening.decommitment.decommitment,
            &points,
            &claims,
            shape,
            challenges,
        ),
    );
}

fn manualNativeEq68Row(
    previous_even: QM31,
    previous_odd: QM31,
    x: M31,
    inserted_even: QM31,
    inserted_odd: QM31,
    y: M31,
    alpha: QM31,
) !QM31 {
    // Native inverse butterflies omit division by two. This is the row-level
    // Eq. 68 relation in the existing FRI evaluation convention.
    const previous_fold = previous_even.add(previous_odd).add(
        alpha.mul(previous_even.sub(previous_odd).mulM31(try x.inv())),
    );
    const inserted_fold = inserted_even.add(inserted_odd).add(
        alpha.mul(inserted_even.sub(inserted_odd).mulM31(try y.inv())),
    );
    return previous_fold.add(alpha.square().mul(inserted_fold));
}

test "experimental multi-domain insertion matches Eq 68 at two smaller heights" {
    const core = @import("stwo_core");
    const insert = core_fri.multidomain_insertion.insertCircleBatch;
    const alloc = std.testing.allocator;
    const h0_domain = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
    const h1_domain = core.poly.circle.canonic.CanonicCoset.new(3).circleDomain();
    const h2_domain = core.poly.circle.canonic.CanonicCoset.new(2).circleDomain();
    const g0_domain = core.poly.line.LineDomain.fromCircleDomain(h0_domain);
    var h0: [16]QM31 = undefined;
    var h1: [8]QM31 = undefined;
    var h2: [4]QM31 = undefined;
    for (&h0, 0..) |*value, i| value.* = QM31.fromBase(M31.fromCanonical(@intCast(3 * i + 5)));
    for (&h1, 0..) |*value, i| value.* = QM31.fromBase(M31.fromCanonical(@intCast(5 * i + 7)));
    for (&h2, 0..) |*value, i| value.* = QM31.fromBase(M31.fromCanonical(@intCast(7 * i + 11)));
    const alpha0 = QM31.fromU32Unchecked(2, 3, 0, 1);
    const alpha1 = QM31.fromU32Unchecked(5, 0, 7, 1);
    const alpha2 = QM31.fromU32Unchecked(11, 3, 2, 0);

    // First height has no previous line layer. The following two heights
    // insert into a previously folded line word.
    var g0 = [_]QM31{QM31.zero()} ** 8;
    var circle_workspace = try core_fri.folding.FoldCircleWorkspace.init(alloc, g0.len);
    defer circle_workspace.deinit(alloc);
    try core_fri.folding.foldCircleIntoLineWithWorkspace(
        alloc,
        &g0,
        &h0,
        h0_domain,
        alpha0,
        &circle_workspace,
    );

    const g1 = try insert(alloc, &g0, g0_domain, &h1, h1_domain, alpha1);
    defer alloc.free(g1.values);
    try std.testing.expect(g1.domain.coset().eql(h1_domain.half_coset));
    for (g1.values, 0..) |actual, i| {
        const x = g0_domain.at(core.utils.bitReverseIndex(i * 2, g0_domain.logSize()));
        const y = h1_domain.at(core.utils.bitReverseIndex(i * 2, h1_domain.logSize())).y;
        const expected = try manualNativeEq68Row(
            g0[2 * i],
            g0[2 * i + 1],
            x,
            h1[2 * i],
            h1[2 * i + 1],
            y,
            alpha1,
        );
        try std.testing.expect(actual.eql(expected));
    }

    const g2 = try insert(alloc, g1.values, g1.domain, &h2, h2_domain, alpha2);
    defer alloc.free(g2.values);
    try std.testing.expect(g2.domain.coset().eql(h2_domain.half_coset));
    for (g2.values, 0..) |actual, i| {
        const x = g1.domain.at(core.utils.bitReverseIndex(i * 2, g1.domain.logSize()));
        const y = h2_domain.at(core.utils.bitReverseIndex(i * 2, h2_domain.logSize())).y;
        const expected = try manualNativeEq68Row(
            g1.values[2 * i],
            g1.values[2 * i + 1],
            x,
            h2[2 * i],
            h2[2 * i + 1],
            y,
            alpha2,
        );
        try std.testing.expect(actual.eql(expected));
    }

    // The insertion kernel may not coerce a wrong height or an unrelated
    // equal-sized circle coset into this cascade.
    try std.testing.expectError(
        error.InvalidInsertionGeometry,
        insert(alloc, &g0, g0_domain, &h2, h2_domain, alpha1),
    );
    const shifted = h1_domain.shift(h1_domain.half_coset.step_size);
    try std.testing.expectError(
        error.InvalidInsertionGeometry,
        insert(alloc, &g0, g0_domain, &h1, shifted, alpha1),
    );
    try std.testing.expectError(
        error.InvalidInsertionGeometry,
        insert(alloc, g0[0..7], g0_domain, &h1, h1_domain, alpha1),
    );
}

test "experimental multi-domain insertion preserves an explicit low-degree cascade" {
    const core = @import("stwo_core");
    const insert = core_fri.multidomain_insertion.insertCircleBatch;
    const alloc = std.testing.allocator;
    const h0_domain = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
    const h1_domain = core.poly.circle.canonic.CanonicCoset.new(3).circleDomain();
    const h2_domain = core.poly.circle.canonic.CanonicCoset.new(2).circleDomain();
    const g0_domain = core.poly.line.LineDomain.fromCircleDomain(h0_domain);
    var h0: [16]QM31 = undefined;
    var h1: [8]QM31 = undefined;
    const c = QM31.fromBase(M31.fromCanonical(9));
    const h2 = [_]QM31{c} ** 4;
    for (&h0, 0..) |*value, row| {
        value.* = QM31.fromBase(h0_domain.at(core.utils.bitReverseIndex(row, 4)).x);
    }
    for (&h1, 0..) |*value, row| {
        value.* = QM31.fromBase(h1_domain.at(core.utils.bitReverseIndex(row, 3)).x);
    }
    const alpha0 = QM31.fromBase(M31.fromCanonical(3));
    const alpha1 = QM31.fromBase(M31.fromCanonical(5));
    const alpha2 = QM31.fromBase(M31.fromCanonical(7));

    var g0 = [_]QM31{QM31.zero()} ** 8;
    var workspace = try core_fri.folding.FoldCircleWorkspace.init(alloc, g0.len);
    defer workspace.deinit(alloc);
    try core_fri.folding.foldCircleIntoLineWithWorkspace(
        alloc,
        &g0,
        &h0,
        h0_domain,
        alpha0,
        &workspace,
    );
    for (g0, 0..) |value, row| {
        const x = g0_domain.at(core.utils.bitReverseIndex(row, g0_domain.logSize()));
        try std.testing.expect(value.eql(QM31.fromBase(x).mulM31(M31.fromCanonical(2))));
    }

    const g1 = try insert(alloc, &g0, g0_domain, &h1, h1_domain, alpha1);
    defer alloc.free(g1.values);
    const g2 = try insert(alloc, g1.values, g1.domain, &h2, h2_domain, alpha2);
    defer alloc.free(g2.values);

    // Native butterflies are unnormalized: x circle-folds to 2x, then line
    // folds to 4*alpha. The second line fold and constant insertion give a
    // constant expression despite the two distinct source heights.
    const expected = QM31.fromBase(M31.fromCanonical(8)).mul(alpha1)
        .add(QM31.fromBase(M31.fromCanonical(4)).mul(alpha1.square()).mul(alpha2))
        .add(QM31.fromBase(M31.fromCanonical(2)).mul(alpha2.square()).mul(c));
    for (g2.values) |value| try std.testing.expect(value.eql(expected));
}

test "experimental versioned multi-height source openings authenticate before insertion" {
    const core = @import("stwo_core");
    const envelope_mod = core.pcs.paired_envelope;
    const projection = core.pcs.paired_projection;
    const Hasher = envelope_mod.Hasher;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const SourceProver = @import("stwo_prover_engine").vcs_lifted.prover.MerkleProverLifted(Hasher);
    const alloc = std.testing.allocator;
    const d0 = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
    const d1 = core.poly.circle.canonic.CanonicCoset.new(3).circleDomain();
    const shape0 = core.pcs.paired_ensemble.Shape{
        .log_domain_size = 4,
        .log_degree_bound = 3,
        .original_column_count = 1,
    };
    const shape1 = core.pcs.paired_ensemble.Shape{
        .log_domain_size = 3,
        .log_degree_bound = 2,
        .original_column_count = 1,
    };
    var f0: [16]M31 = undefined;
    var f1: [8]M31 = undefined;
    var queries: [16]usize = undefined;
    for (&f0, &queries, 0..) |*value, *query, row| {
        query.* = row;
        value.* = d0.at(core.utils.bitReverseIndex(row, 4)).x;
    }
    for (&f1, 0..) |*value, row| value.* = d1.at(core.utils.bitReverseIndex(row, 3)).x;
    const projected = try projection.projectPositions(alloc, &queries, 4, 3);
    defer alloc.free(projected);
    try std.testing.expectError(
        error.QueryPositionOutOfRange,
        projection.projectPositions(alloc, &[_]usize{16}, 4, 3),
    );
    try std.testing.expectError(
        error.InvalidProjectionGeometry,
        projection.projectPositions(alloc, &queries, 4, 5),
    );
    for (queries, projected) |large, small| {
        const large_point = d0.at(core.utils.bitReverseIndex(large, 4));
        const small_point = d1.at(core.utils.bitReverseIndex(small, 3));
        try std.testing.expect(large_point.double().eql(small_point));
    }

    const columns0 = [_][]const M31{&f0};
    const columns1 = [_][]const M31{&f1};
    var tree0 = try SourceProver.commit(alloc, &columns0);
    defer tree0.deinit(alloc);
    var tree1 = try SourceProver.commit(alloc, &columns1);
    defer tree1.deinit(alloc);
    var opened0 = try tree0.decommit(alloc, &queries, &columns0);
    defer opened0.deinit(alloc);
    var opened1 = try tree1.decommit(alloc, projected, &columns1);
    defer opened1.deinit(alloc);

    const point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(13);
    const points = [_]core.circle.CirclePointQM31{point};
    const claims = [_]QM31{point.x};
    const queried0 = [_][]const M31{opened0.queried_values[0]};
    const queried1 = [_][]const M31{opened1.queried_values[0]};
    const heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shape0,
            .source_root = tree0.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &queried0,
            .hash_witness = opened0.decommitment.decommitment.hash_witness,
        },
        .{
            .shape = shape1,
            .source_root = tree1.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &queried1,
            .hash_witness = opened1.decommitment.decommitment.hash_witness,
        },
    };
    const source_envelope = envelope_mod.Envelope{
        .largest_log_size = 4,
        .query_count = queries.len,
        .heights = &heights,
    };
    const encoded = try envelope_mod.encode(alloc, source_envelope);
    defer alloc.free(encoded);
    const expected_profile = envelope_mod.ExpectedProfile{
        .largest_log_size = 4,
        .query_count = queries.len,
        .shapes = &[_]core.pcs.paired_ensemble.Shape{ shape0, shape1 },
    };
    var verifier_channel = Channel{};
    var prepared = try envelope_mod.decodeAndBind(alloc, encoded, &verifier_channel, expected_profile);
    defer prepared.deinit();
    const proof = prepared.decoded.envelope;
    try std.testing.expectEqual(@as(usize, 2), proof.heights.len);
    const reencoded = try envelope_mod.encode(alloc, proof);
    defer alloc.free(reencoded);
    try std.testing.expectEqualSlices(u8, encoded, reencoded);
    var prover_channel = Channel{};
    const prover_challenges = try envelope_mod.drawChallenges(&prover_channel, source_envelope);
    const challenges = prepared.challenges;
    try std.testing.expect(prover_challenges.batch.eql(challenges.batch));

    const answers0 = try envelope_mod.authenticatedHeightAnswers(alloc, proof, 0, &queries, challenges);
    defer alloc.free(answers0);
    const answers1 = try envelope_mod.authenticatedHeightAnswers(alloc, proof, 1, &queries, challenges);
    defer alloc.free(answers1);
    var dense1: [8]QM31 = undefined;
    var seen = [_]bool{false} ** 8;
    for (projected, answers1) |position, answer| {
        if (seen[position]) {
            try std.testing.expect(dense1[position].eql(answer));
        } else {
            dense1[position] = answer;
            seen[position] = true;
        }
    }
    for (seen) |value| try std.testing.expect(value);

    var g0 = [_]QM31{QM31.zero()} ** 8;
    var workspace = try core_fri.folding.FoldCircleWorkspace.init(alloc, g0.len);
    defer workspace.deinit(alloc);
    const alpha0 = QM31.fromBase(M31.fromCanonical(3));
    const alpha1 = QM31.fromBase(M31.fromCanonical(5));
    try core_fri.folding.foldCircleIntoLineWithWorkspace(
        alloc,
        &g0,
        answers0,
        d0,
        alpha0,
        &workspace,
    );
    const g1 = try core_fri.multidomain_insertion.insertCircleBatch(
        alloc,
        &g0,
        core.poly.line.LineDomain.fromCircleDomain(d0),
        &dense1,
        d1,
        alpha1,
    );
    defer alloc.free(g1.values);
    try std.testing.expectEqual(@as(usize, 4), g1.values.len);

    const changed = try alloc.dupe(M31, proof.heights[1].queried_sources[0]);
    defer alloc.free(changed);
    changed[0] = changed[0].add(M31.one());
    const changed_columns = [_][]const M31{changed};
    var changed_heights = [_]envelope_mod.HeightOpening{ proof.heights[0], proof.heights[1] };
    changed_heights[1].queried_sources = &changed_columns;
    const changed_proof = envelope_mod.Envelope{
        .largest_log_size = proof.largest_log_size,
        .query_count = proof.query_count,
        .heights = &changed_heights,
    };
    try std.testing.expectError(
        error.DuplicateQueryMismatch,
        envelope_mod.authenticatedHeightAnswers(alloc, changed_proof, 1, &queries, challenges),
    );

    const altered_wire = try alloc.dupe(u8, encoded);
    defer alloc.free(altered_wire);
    altered_wire[8] = 2;
    var rejected_channel = Channel{};
    const digest_before = rejected_channel.digest;
    try std.testing.expectError(
        error.UnsupportedProofVersion,
        envelope_mod.decodeAndBind(alloc, altered_wire, &rejected_channel, expected_profile),
    );
    try std.testing.expectEqualSlices(u8, &digest_before, &rejected_channel.digest);
    const wrong_profile = envelope_mod.ExpectedProfile{
        .largest_log_size = 4,
        .query_count = queries.len,
        .shapes = &[_]core.pcs.paired_ensemble.Shape{ shape0, shape0 },
    };
    try std.testing.expectError(
        error.UnexpectedPairedProfile,
        envelope_mod.decodeAndBind(alloc, encoded, &rejected_channel, wrong_profile),
    );
    try std.testing.expectEqualSlices(u8, &digest_before, &rejected_channel.digest);
    @memcpy(altered_wire[0..8], "STWOPRW1");
    try std.testing.expectError(error.LegacyProofRequiresLegacyVerifier, envelope_mod.decode(alloc, altered_wire));
    @memcpy(altered_wire, encoded);
    std.mem.writeInt(u32, altered_wire[72..76], m31.Modulus, .little);
    try std.testing.expectError(error.NonCanonicalM31, envelope_mod.decode(alloc, altered_wire));
    const extended_wire = try alloc.alloc(u8, encoded.len + 1);
    defer alloc.free(extended_wire);
    @memcpy(extended_wire[0..encoded.len], encoded);
    extended_wire[encoded.len] = 0;
    try std.testing.expectError(error.InvalidPairedEnvelope, envelope_mod.decode(alloc, extended_wire));
}
