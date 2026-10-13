//! Experimental paired and multi-height FRI integration tests.

const std = @import("std");
const fri = @import("stwo_prover_engine").fri;
const core_fri = @import("stwo_core").fri;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const secure_column = @import("stwo_prover_engine").secure_column;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const FriProver = fri.FriProver;

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

fn pairedFullBatchForTest(
    allocator: std.mem.Allocator,
    source: []const M31,
    log_domain_size: u32,
    point: @import("stwo_core").circle.CirclePointQM31,
    claim: QM31,
    challenges: @import("stwo_core").pcs.paired_ensemble.Challenges,
) ![]QM31 {
    const core = @import("stwo_core");
    const shape = core.pcs.paired_ensemble.Shape{
        .log_domain_size = log_domain_size,
        .log_degree_bound = log_domain_size - 1,
        .original_column_count = 1,
    };
    const positions = try allocator.alloc(usize, source.len);
    defer allocator.free(positions);
    for (positions, 0..) |*position, i| position.* = i;
    var log_column = [_]u32{log_domain_size};
    var log_tree = [_][]u32{log_column[0..]};
    var point_column = [_]core.circle.CirclePointQM31{point};
    var point_tree = [_][]core.circle.CirclePointQM31{point_column[0..]};
    var points = [_][][]core.circle.CirclePointQM31{point_tree[0..]};
    var claim_column = [_]QM31{claim};
    var claim_tree = [_][]QM31{claim_column[0..]};
    var claims = [_][][]QM31{claim_tree[0..]};
    var source_tree = [_][]M31{@constCast(source)};
    var queried = [_][][]M31{source_tree[0..]};
    const quotient = try core.pcs.quotients.friAnswers(
        allocator,
        core.pcs.TreeVec([]u32).initOwned(log_tree[0..]),
        core.pcs.TreeVec([][]core.circle.CirclePointQM31).initOwned(points[0..]),
        core.pcs.TreeVec([][]QM31).initOwned(claims[0..]),
        QM31.one(),
        positions,
        core.pcs.TreeVec([][]M31).initOwned(queried[0..]),
        log_domain_size,
    );
    defer allocator.free(quotient);
    return core.pcs.paired_ensemble.foldColumns(
        allocator,
        &[_][]const M31{source},
        &[_][]const QM31{quotient},
        shape,
        challenges,
    );
}

fn directTwoPointQuotient(
    point: @import("stwo_core").circle.CirclePointQM31,
    claim: QM31,
    domain_point: @import("stwo_core").circle.CirclePointM31,
    value: M31,
) !QM31 {
    // This is the scalar geometric definition, independent of friAnswers'
    // sample batching, line-coefficient cache, and row accumulation.
    const CM31 = @import("stwo_core").fields.cm31.CM31;
    const conjugate = point.complexConjugate();
    const delta_y = conjugate.y.sub(point.y);
    const line_value = claim.add(try claim.complexConjugate().sub(claim)
        .mul(QM31.fromBase(domain_point.y).sub(point.y)).div(delta_y));
    const denominator = point.x.c0.sub(CM31.fromBase(domain_point.x)).mul(point.y.c1)
        .sub(point.y.c0.sub(CM31.fromBase(domain_point.y)).mul(point.x.c1));
    return QM31.fromBase(value).sub(line_value).mul(delta_y)
        .mulCM31(try denominator.inv());
}

fn directLagrangeLine(
    values: []const QM31,
    domain: @import("stwo_core").poly.line.LineDomain,
    x: QM31,
) !QM31 {
    const core = @import("stwo_core");
    var result = QM31.zero();
    for (values, 0..) |value, i| {
        const xi = QM31.fromBase(domain.at(core.utils.bitReverseIndex(i, domain.logSize())));
        var numerator = QM31.one();
        var denominator = QM31.one();
        for (values, 0..) |_, j| {
            if (j == i) continue;
            const xj = QM31.fromBase(domain.at(core.utils.bitReverseIndex(j, domain.logSize())));
            numerator = numerator.mul(x.sub(xj));
            denominator = denominator.mul(xi.sub(xj));
        }
        result = result.add(value.mul(try numerator.div(denominator)));
    }
    return result;
}

fn checkHonestAdjacentHeights(comptime largest_log: u32, n_queries: usize) !void {
    const core = @import("stwo_core");
    const envelope_mod = core.pcs.paired_envelope;
    const two_height = core.pcs.paired_two_height_fri;
    const wire = core.pcs.paired_two_height_wire;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const Hasher = envelope_mod.Hasher;
    const SourceProver = @import("stwo_prover_engine").vcs_lifted.prover.MerkleProverLifted(Hasher);
    const LineEvaluation = @import("stwo_prover_engine").line.LineEvaluation;
    const alloc = std.testing.allocator;
    const smaller_log = largest_log - 1;
    const larger_len = @as(usize, 1) << largest_log;
    const smaller_len = larger_len / 2;
    const terminal_len = smaller_len / 4;
    const d0 = core.poly.circle.canonic.CanonicCoset.new(largest_log).circleDomain();
    const d1 = core.poly.circle.canonic.CanonicCoset.new(smaller_log).circleDomain();
    const line_domain = core.poly.line.LineDomain.fromCircleDomain(d0);
    const terminal_domain = core.poly.line.LineDomain.fromCircleDomain(d1);
    const shape0 = core.pcs.paired_ensemble.Shape{
        .log_domain_size = largest_log,
        .log_degree_bound = largest_log - 1,
        .original_column_count = 1,
    };
    const shape1 = core.pcs.paired_ensemble.Shape{
        .log_domain_size = smaller_log,
        .log_degree_bound = smaller_log - 1,
        .original_column_count = 1,
    };
    var f0: [larger_len]M31 = undefined;
    var f1: [smaller_len]M31 = undefined;
    for (&f0, 0..) |*value, row| value.* = d0.at(core.utils.bitReverseIndex(row, largest_log)).x;
    for (&f1, 0..) |*value, row| value.* = d1.at(core.utils.bitReverseIndex(row, smaller_log)).x;
    const columns0 = [_][]const M31{&f0};
    const columns1 = [_][]const M31{&f1};
    var tree0 = try SourceProver.commit(alloc, &columns0);
    defer tree0.deinit(alloc);
    var tree1 = try SourceProver.commit(alloc, &columns1);
    defer tree1.deinit(alloc);

    var points = [_]core.circle.CirclePointQM31{core.circle.CirclePointQM31.zero()};
    var claims = [_]QM31{QM31.zero()};
    const dummy_values = try alloc.alloc(M31, 4 * n_queries);
    defer alloc.free(dummy_values);
    @memset(dummy_values, M31.zero());
    var empty_witness: [0]Hasher.Hash = .{};
    const dummy_columns = [_][]const M31{dummy_values};
    const header_heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shape0,
            .source_root = tree0.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &dummy_columns,
            .hash_witness = &empty_witness,
        },
        .{
            .shape = shape1,
            .source_root = tree1.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &dummy_columns,
            .hash_witness = &empty_witness,
        },
    };
    const header = envelope_mod.Envelope{
        .largest_log_size = largest_log,
        .query_count = @intCast(4 * n_queries),
        .heights = &header_heights,
    };
    var prover_channel = Channel{};
    wire.bindVersion(&prover_channel);
    const sample_point = try wire.drawOodPointFromRoots(&prover_channel, header);
    points[0] = sample_point;
    claims[0] = sample_point.x;
    const challenges = try wire.drawBatchAfterOod(&prover_channel, header, sample_point);
    const changed_claims = [_]QM31{claims[0].add(QM31.one())};
    var changed_claim_heights = header_heights;
    for (&changed_claim_heights) |*height| height.sample_values = &changed_claims;
    const changed_claim_header = envelope_mod.Envelope{
        .largest_log_size = largest_log,
        .query_count = @intCast(4 * n_queries),
        .heights = &changed_claim_heights,
    };
    var changed_claim_channel = Channel{};
    wire.bindVersion(&changed_claim_channel);
    const changed_claim_point = try wire.drawOodPointFromRoots(
        &changed_claim_channel,
        changed_claim_header,
    );
    try std.testing.expect(changed_claim_point.eql(sample_point));
    const changed_challenges = try wire.drawBatchAfterOod(
        &changed_claim_channel,
        changed_claim_header,
        changed_claim_point,
    );
    try std.testing.expect(!changed_challenges.batch.eql(challenges.batch));
    const alpha0 = prover_channel.drawSecureFelt();
    const batch0 = try pairedFullBatchForTest(alloc, &f0, largest_log, sample_point, claims[0], challenges);
    defer alloc.free(batch0);
    const batch1 = try pairedFullBatchForTest(alloc, &f1, smaller_log, sample_point, claims[0], challenges);
    defer alloc.free(batch1);
    for (batch0, f0, 0..) |actual, x, row| {
        const p = d0.at(core.utils.bitReverseIndex(row, largest_log));
        const quotient = try directTwoPointQuotient(sample_point, claims[0], p, x);
        const expected = QM31.fromBase(x).add(challenges.batch.mul(quotient));
        try std.testing.expect(actual.eql(expected));
    }
    for (batch1, f1, 0..) |actual, x, row| {
        const p = d1.at(core.utils.bitReverseIndex(row, smaller_log));
        const quotient = try directTwoPointQuotient(sample_point, claims[0], p, x);
        const expected = QM31.fromBase(x).add(challenges.batch.mul(quotient));
        try std.testing.expect(actual.eql(expected));
    }

    var g0: [smaller_len]QM31 = [_]QM31{QM31.zero()} ** smaller_len;
    var workspace = try core_fri.folding.FoldCircleWorkspace.init(alloc, smaller_len);
    defer workspace.deinit(alloc);
    try core_fri.folding.foldCircleIntoLineWithWorkspace(
        alloc,
        &g0,
        batch0,
        d0,
        alpha0,
        &workspace,
    );
    for (g0, 0..) |actual, row| {
        const y = d0.at(core.utils.bitReverseIndex(2 * row, largest_log)).y;
        const even = batch0[2 * row];
        const odd = batch0[2 * row + 1];
        const expected = even.add(odd).add(alpha0.mul(even.sub(odd).mulM31(try y.inv())));
        try std.testing.expect(actual.eql(expected));
    }
    var line_coordinates: [4][smaller_len]M31 = undefined;
    for (g0, 0..) |value, row| {
        for (value.toM31Array(), 0..) |coordinate, part| {
            line_coordinates[part][row] = coordinate;
        }
    }
    const line_columns = [_][]const M31{
        &line_coordinates[0], &line_coordinates[1],
        &line_coordinates[2], &line_coordinates[3],
    };
    var line_tree = try SourceProver.commit(alloc, &line_columns);
    defer line_tree.deinit(alloc);
    core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(&prover_channel, line_tree.root());
    const alpha1 = prover_channel.drawSecureFelt();
    const g1 = try core_fri.multidomain_insertion.insertCircleBatch(
        alloc,
        &g0,
        line_domain,
        batch1,
        d1,
        alpha1,
    );
    defer alloc.free(g1.values);
    for (g1.values, 0..) |actual, row| {
        const x = line_domain.at(core.utils.bitReverseIndex(2 * row, line_domain.logSize()));
        const y = d1.at(core.utils.bitReverseIndex(2 * row, smaller_log)).y;
        const expected = try manualNativeEq68Row(
            g0[2 * row],
            g0[2 * row + 1],
            x,
            batch1[2 * row],
            batch1[2 * row + 1],
            y,
            alpha1,
        );
        try std.testing.expect(actual.eql(expected));
    }
    var g1_evaluation = try LineEvaluation.initBorrowed(g1.domain, g1.values);
    var g1_poly = try g1_evaluation.interpolate(alloc);
    defer g1_poly.deinit(alloc);
    const ordered_coeffs = g1_poly.intoOrderedCoefficients();
    for (ordered_coeffs[terminal_len..]) |coefficient| try std.testing.expect(coefficient.isZero());
    const terminal_coeffs = ordered_coeffs[0..terminal_len];
    const terminal_copy = try alloc.dupe(QM31, terminal_coeffs);
    var terminal_poly = core.poly.line.LinePoly.fromOrderedCoefficients(terminal_copy);
    defer terminal_poly.deinit(alloc);
    for (g1.values, 0..) |actual, row| {
        const x = terminal_domain.at(core.utils.bitReverseIndex(row, terminal_domain.logSize()));
        try std.testing.expect(actual.eql(try terminal_poly.evalAtPoint(alloc, QM31.fromBase(x))));
    }
    const independent_ood_eval = try directLagrangeLine(g1.values, terminal_domain, sample_point.x);
    try std.testing.expect(independent_ood_eval.eql(try terminal_poly.evalAtPoint(alloc, sample_point.x)));
    prover_channel.mixFelts(terminal_coeffs);
    var schedule = try two_height.sampleQuerySchedule(
        alloc,
        &prover_channel,
        largest_log,
        n_queries,
    );
    defer schedule.deinit(alloc);
    const projected = try core.pcs.paired_projection.projectPositions(
        alloc,
        schedule.source_positions,
        largest_log,
        smaller_log,
    );
    defer alloc.free(projected);
    for (schedule.source_positions, projected) |large_row, small_row| {
        const large_point = d0.at(core.utils.bitReverseIndex(large_row, largest_log));
        const small_point = d1.at(core.utils.bitReverseIndex(small_row, smaller_log));
        try std.testing.expect(large_point.double().eql(small_point));
    }
    var opened0 = try tree0.decommit(alloc, schedule.source_positions, &columns0);
    defer opened0.deinit(alloc);
    var opened1 = try tree1.decommit(alloc, projected, &columns1);
    defer opened1.deinit(alloc);
    var opened_line = try line_tree.decommit(alloc, schedule.line_positions, &line_columns);
    defer opened_line.deinit(alloc);
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
    const source_wire = try envelope_mod.encode(alloc, .{
        .largest_log_size = largest_log,
        .query_count = @intCast(4 * n_queries),
        .heights = &heights,
    });
    defer alloc.free(source_wire);
    const outer_wire = try wire.encode(alloc, .{
        .source_wire = source_wire,
        .intermediate = .{
            .root = line_tree.root(),
            .queried_coordinates = .{
                opened_line.queried_values[0], opened_line.queried_values[1],
                opened_line.queried_values[2], opened_line.queried_values[3],
            },
            .hash_witness = opened_line.decommitment.decommitment.hash_witness,
        },
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    defer alloc.free(outer_wire);
    var verifier_channel = Channel{};
    try wire.verify(alloc, outer_wire, &verifier_channel, .{
        .largest_log_size = largest_log,
        .query_count = @intCast(4 * n_queries),
        .shapes = &[_]core.pcs.paired_ensemble.Shape{ shape0, shape1 },
    }, n_queries);
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);

    // Keep both honest commitments, change only the claimed OOD value, and
    // open the honest trees afresh at the changed transcript's queries.
    // Authentication succeeds; the algebraic first fold must reject.
    _ = changed_claim_channel.drawSecureFelt();
    core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(
        &changed_claim_channel,
        line_tree.root(),
    );
    _ = changed_claim_channel.drawSecureFelt();
    changed_claim_channel.mixFelts(terminal_coeffs);
    var changed_schedule = try two_height.sampleQuerySchedule(
        alloc,
        &changed_claim_channel,
        largest_log,
        n_queries,
    );
    defer changed_schedule.deinit(alloc);
    const changed_projected = try core.pcs.paired_projection.projectPositions(
        alloc,
        changed_schedule.source_positions,
        largest_log,
        smaller_log,
    );
    defer alloc.free(changed_projected);
    var changed_opened0 = try tree0.decommit(
        alloc,
        changed_schedule.source_positions,
        &columns0,
    );
    defer changed_opened0.deinit(alloc);
    var changed_opened1 = try tree1.decommit(
        alloc,
        changed_projected,
        &columns1,
    );
    defer changed_opened1.deinit(alloc);
    var changed_opened_line = try line_tree.decommit(
        alloc,
        changed_schedule.line_positions,
        &line_columns,
    );
    defer changed_opened_line.deinit(alloc);
    const changed_columns0 = [_][]const M31{changed_opened0.queried_values[0]};
    const changed_columns1 = [_][]const M31{changed_opened1.queried_values[0]};
    const changed_heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shape0,
            .source_root = tree0.root(),
            .sample_points = &points,
            .sample_values = &changed_claims,
            .queried_sources = &changed_columns0,
            .hash_witness = changed_opened0.decommitment.decommitment.hash_witness,
        },
        .{
            .shape = shape1,
            .source_root = tree1.root(),
            .sample_points = &points,
            .sample_values = &changed_claims,
            .queried_sources = &changed_columns1,
            .hash_witness = changed_opened1.decommitment.decommitment.hash_witness,
        },
    };
    const changed_source_wire = try envelope_mod.encode(alloc, .{
        .largest_log_size = largest_log,
        .query_count = @intCast(4 * n_queries),
        .heights = &changed_heights,
    });
    defer alloc.free(changed_source_wire);
    const changed_outer_wire = try wire.encode(alloc, .{
        .source_wire = changed_source_wire,
        .intermediate = .{
            .root = line_tree.root(),
            .queried_coordinates = .{
                changed_opened_line.queried_values[0], changed_opened_line.queried_values[1],
                changed_opened_line.queried_values[2], changed_opened_line.queried_values[3],
            },
            .hash_witness = changed_opened_line.decommitment.decommitment.hash_witness,
        },
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    defer alloc.free(changed_outer_wire);
    var changed_verifier_channel = Channel{};
    try std.testing.expectError(
        error.IntermediateFoldMismatch,
        wire.verify(alloc, changed_outer_wire, &changed_verifier_channel, .{
            .largest_log_size = largest_log,
            .query_count = @intCast(4 * n_queries),
            .shapes = &[_]core.pcs.paired_ensemble.Shape{ shape0, shape1 },
        }, n_queries),
    );
}

test "experimental paired FRI works at parameterized adjacent heights" {
    try checkHonestAdjacentHeights(5, 5);
    try checkHonestAdjacentHeights(6, 7);
}

test "experimental sampled two-height FRI authenticates intermediate and checks both folds" {
    const core = @import("stwo_core");
    const envelope_mod = core.pcs.paired_envelope;
    const two_height = core.pcs.paired_two_height_fri;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const Hasher = envelope_mod.Hasher;
    const SourceProver = @import("stwo_prover_engine").vcs_lifted.prover.MerkleProverLifted(Hasher);
    const LineEvaluation = @import("stwo_prover_engine").line.LineEvaluation;
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
    for (&f0, 0..) |*value, row| value.* = d0.at(core.utils.bitReverseIndex(row, 4)).x;
    for (&f1, 0..) |*value, row| value.* = d1.at(core.utils.bitReverseIndex(row, 3)).x;
    const sources0 = [_][]const M31{&f0};
    const sources1 = [_][]const M31{&f1};
    var tree0 = try SourceProver.commit(alloc, &sources0);
    defer tree0.deinit(alloc);
    var tree1 = try SourceProver.commit(alloc, &sources1);
    defer tree1.deinit(alloc);
    var points = [_]core.circle.CirclePointQM31{core.circle.CirclePointQM31.zero()};
    var claims = [_]QM31{QM31.zero()};
    const n_queries: usize = 4;
    var dummy_values = [_]M31{M31.zero()} ** (4 * n_queries);
    var empty_witness: [0]Hasher.Hash = .{};
    const dummy_columns = [_][]const M31{&dummy_values};
    const header_heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shape0,
            .source_root = tree0.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &dummy_columns,
            .hash_witness = &empty_witness,
        },
        .{
            .shape = shape1,
            .source_root = tree1.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &dummy_columns,
            .hash_witness = &empty_witness,
        },
    };
    const header = envelope_mod.Envelope{
        .largest_log_size = 4,
        .query_count = 4 * n_queries,
        .heights = &header_heights,
    };
    var prover_channel = Channel{};
    core.pcs.paired_two_height_wire.bindVersion(&prover_channel);
    const sample_point = try core.pcs.paired_two_height_wire.drawOodPointFromRoots(
        &prover_channel,
        header,
    );
    points[0] = sample_point;
    claims[0] = sample_point.x;
    const batch_challenges = try core.pcs.paired_two_height_wire.drawBatchAfterOod(
        &prover_channel,
        header,
        sample_point,
    );
    var source_only_channel = Channel{};
    const source_only_challenges = try envelope_mod.drawChallenges(&source_only_channel, header);
    try std.testing.expect(!batch_challenges.batch.eql(source_only_challenges.batch));
    const alpha0 = prover_channel.drawSecureFelt();
    const batch0 = try pairedFullBatchForTest(alloc, &f0, 4, sample_point, sample_point.x, batch_challenges);
    defer alloc.free(batch0);
    const batch1 = try pairedFullBatchForTest(alloc, &f1, 3, sample_point, sample_point.x, batch_challenges);
    defer alloc.free(batch1);
    var g0 = [_]QM31{QM31.zero()} ** 8;
    var workspace = try core_fri.folding.FoldCircleWorkspace.init(alloc, g0.len);
    defer workspace.deinit(alloc);
    try core_fri.folding.foldCircleIntoLineWithWorkspace(alloc, &g0, batch0, d0, alpha0, &workspace);
    var g0_coordinates: [4][8]M31 = undefined;
    for (g0, 0..) |value, row| {
        const parts = value.toM31Array();
        for (0..4) |part| g0_coordinates[part][row] = parts[part];
    }
    const g0_columns = [_][]const M31{
        &g0_coordinates[0], &g0_coordinates[1], &g0_coordinates[2], &g0_coordinates[3],
    };
    var g0_tree = try SourceProver.commit(alloc, &g0_columns);
    defer g0_tree.deinit(alloc);
    core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(&prover_channel, g0_tree.root());
    const alpha1 = prover_channel.drawSecureFelt();
    const g1 = try core_fri.multidomain_insertion.insertCircleBatch(
        alloc,
        &g0,
        core.poly.line.LineDomain.fromCircleDomain(d0),
        batch1,
        d1,
        alpha1,
    );
    defer alloc.free(g1.values);
    var g1_evaluation = try LineEvaluation.initBorrowed(g1.domain, g1.values);
    var g1_poly = try g1_evaluation.interpolate(alloc);
    defer g1_poly.deinit(alloc);
    const ordered_coeffs = g1_poly.intoOrderedCoefficients();
    for (ordered_coeffs[2..]) |coefficient| try std.testing.expect(coefficient.isZero());
    const terminal_coeffs = ordered_coeffs[0..2];
    prover_channel.mixFelts(terminal_coeffs);
    var schedule = try two_height.sampleQuerySchedule(alloc, &prover_channel, 4, n_queries);
    defer schedule.deinit(alloc);

    const projected1 = try core.pcs.paired_projection.projectPositions(
        alloc,
        schedule.source_positions,
        4,
        3,
    );
    defer alloc.free(projected1);
    var opened0 = try tree0.decommit(alloc, schedule.source_positions, &sources0);
    defer opened0.deinit(alloc);
    var opened1 = try tree1.decommit(alloc, projected1, &sources1);
    defer opened1.deinit(alloc);
    var opened_g0 = try g0_tree.decommit(alloc, schedule.line_positions, &g0_columns);
    defer opened_g0.deinit(alloc);
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
        .query_count = 4 * n_queries,
        .heights = &heights,
    };
    const encoded = try envelope_mod.encode(alloc, source_envelope);
    defer alloc.free(encoded);
    const expected_profile = envelope_mod.ExpectedProfile{
        .largest_log_size = 4,
        .query_count = 4 * n_queries,
        .shapes = &[_]core.pcs.paired_ensemble.Shape{ shape0, shape1 },
    };
    var verifier_channel = Channel{};
    var prepared = try core.pcs.paired_two_height_wire.bindSourceEnvelope(
        alloc,
        encoded,
        &verifier_channel,
        expected_profile,
    );
    defer prepared.deinit();
    const intermediate = two_height.IntermediateOpening{
        .root = g0_tree.root(),
        .queried_coordinates = .{
            opened_g0.queried_values[0], opened_g0.queried_values[1],
            opened_g0.queried_values[2], opened_g0.queried_values[3],
        },
        .hash_witness = opened_g0.decommitment.decommitment.hash_witness,
    };
    const two_height_wire = core.pcs.paired_two_height_wire;
    const complete_wire = try two_height_wire.encode(alloc, .{
        .source_wire = encoded,
        .intermediate = intermediate,
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    defer alloc.free(complete_wire);
    var wire_channel = Channel{};
    try two_height_wire.verify(
        alloc,
        complete_wire,
        &wire_channel,
        expected_profile,
        n_queries,
    );
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &wire_channel.digest);
    const wrong_version_wire = try alloc.dupe(u8, complete_wire);
    defer alloc.free(wrong_version_wire);
    wrong_version_wire[8] = 2;
    var untouched_channel = Channel{};
    const untouched_digest = untouched_channel.digest;
    try std.testing.expectError(
        error.UnsupportedProofVersion,
        two_height_wire.verify(
            alloc,
            wrong_version_wire,
            &untouched_channel,
            expected_profile,
            n_queries,
        ),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &untouched_channel.digest);
    const other_point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(13);
    try std.testing.expect(!other_point.eql(sample_point));
    const altered_points = [_]core.circle.CirclePointQM31{other_point};
    var altered_heights = heights;
    altered_heights[0].sample_points = &altered_points;
    const altered_source = try envelope_mod.encode(alloc, .{
        .largest_log_size = 4,
        .query_count = 4 * n_queries,
        .heights = &altered_heights,
    });
    defer alloc.free(altered_source);
    const altered_wire = try two_height_wire.encode(alloc, .{
        .source_wire = altered_source,
        .intermediate = intermediate,
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    defer alloc.free(altered_wire);
    try std.testing.expectError(
        error.UnsampledOodPoint,
        two_height_wire.verify(alloc, altered_wire, &untouched_channel, expected_profile, n_queries),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &untouched_channel.digest);
    const changed_source_values = try alloc.dupe(M31, queried0[0]);
    defer alloc.free(changed_source_values);
    for (schedule.source_positions, 0..) |position, index| {
        if (position == schedule.source_positions[0]) {
            changed_source_values[index] = changed_source_values[index].add(M31.one());
        }
    }
    const changed_source_columns = [_][]const M31{changed_source_values};
    var changed_source_heights = heights;
    changed_source_heights[0].queried_sources = &changed_source_columns;
    const changed_source_wire = try envelope_mod.encode(alloc, .{
        .largest_log_size = 4,
        .query_count = 4 * n_queries,
        .heights = &changed_source_heights,
    });
    defer alloc.free(changed_source_wire);
    const changed_source_proof = try two_height_wire.encode(alloc, .{
        .source_wire = changed_source_wire,
        .intermediate = intermediate,
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    defer alloc.free(changed_source_proof);
    var changed_source_channel = Channel{};
    try std.testing.expectError(
        error.RootMismatch,
        two_height_wire.verify(
            alloc,
            changed_source_proof,
            &changed_source_channel,
            expected_profile,
            n_queries,
        ),
    );
    try std.testing.expectError(
        error.InvalidPairedProof,
        two_height_wire.encode(alloc, .{
            .source_wire = encoded,
            .intermediate = intermediate,
            .terminal_ordered_coeffs = &[_]QM31{ terminal_coeffs[0], terminal_coeffs[1], QM31.one() },
        }),
    );
    try std.testing.expectError(
        error.UnsupportedProofFormat,
        two_height_wire.verify(alloc, encoded, &untouched_channel, expected_profile, n_queries),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &untouched_channel.digest);
    const extended_wire = try alloc.alloc(u8, complete_wire.len + 1);
    defer alloc.free(extended_wire);
    @memcpy(extended_wire[0..complete_wire.len], complete_wire);
    extended_wire[complete_wire.len] = 0;
    try std.testing.expectError(
        error.InvalidPairedProof,
        two_height_wire.verify(alloc, extended_wire, &untouched_channel, expected_profile, n_queries),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &untouched_channel.digest);
    const noncanonical_wire = try alloc.dupe(u8, complete_wire);
    defer alloc.free(noncanonical_wire);
    const terminal_offset = 20 + encoded.len + 32 + 4;
    std.mem.writeInt(u32, noncanonical_wire[terminal_offset..][0..4], m31.Modulus, .little);
    try std.testing.expectError(
        error.NonCanonicalM31,
        two_height_wire.verify(
            alloc,
            noncanonical_wire,
            &untouched_channel,
            expected_profile,
            n_queries,
        ),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &untouched_channel.digest);
    const high_degree_wire = try alloc.alloc(u8, complete_wire.len + @sizeOf(QM31));
    defer alloc.free(high_degree_wire);
    @memcpy(high_degree_wire[0 .. terminal_offset + 2 * @sizeOf(QM31)], complete_wire[0 .. terminal_offset + 2 * @sizeOf(QM31)]);
    @memset(high_degree_wire[terminal_offset + 2 * @sizeOf(QM31) ..][0..@sizeOf(QM31)], 0);
    @memcpy(high_degree_wire[terminal_offset + 3 * @sizeOf(QM31) ..], complete_wire[terminal_offset + 2 * @sizeOf(QM31) ..]);
    std.mem.writeInt(u32, high_degree_wire[12..16], @intCast(high_degree_wire.len), .little);
    std.mem.writeInt(u32, high_degree_wire[terminal_offset - 4 ..][0..4], 3, .little);
    try std.testing.expectError(
        error.InvalidPairedProof,
        two_height_wire.verify(
            alloc,
            high_degree_wire,
            &untouched_channel,
            expected_profile,
            n_queries,
        ),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &untouched_channel.digest);
    try two_height.verifyAfterSourceBinding(
        alloc,
        &verifier_channel,
        &prepared,
        intermediate,
        terminal_coeffs,
        n_queries,
    );
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);

    // A changed intermediate line word must fail its own commitment check
    // before either fold relation is considered.
    const changed_coordinate = try alloc.dupe(M31, intermediate.queried_coordinates[0]);
    defer alloc.free(changed_coordinate);
    for (changed_coordinate) |*value| value.* = value.*.add(M31.one());
    var changed_intermediate = intermediate;
    changed_intermediate.queried_coordinates[0] = changed_coordinate;
    var rejected_channel = Channel{};
    var rejected_prepared = try two_height_wire.bindSourceEnvelope(
        alloc,
        encoded,
        &rejected_channel,
        expected_profile,
    );
    defer rejected_prepared.deinit();
    try std.testing.expectError(
        error.RootMismatch,
        two_height.verifyAfterSourceBinding(
            alloc,
            &rejected_channel,
            &rejected_prepared,
            changed_intermediate,
            terminal_coeffs,
            n_queries,
        ),
    );
    const changed_line_wire = try two_height_wire.encode(alloc, .{
        .source_wire = encoded,
        .intermediate = changed_intermediate,
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    defer alloc.free(changed_line_wire);
    var changed_line_channel = Channel{};
    try std.testing.expectError(
        error.RootMismatch,
        two_height_wire.verify(
            alloc,
            changed_line_wire,
            &changed_line_channel,
            expected_profile,
            n_queries,
        ),
    );

    // A prover can commit to a different, internally consistent line tree.
    // Merkle authentication then succeeds, but the sampled source-to-line
    // relation must still reject the forged fold.
    var forged_coordinates = g0_coordinates;
    for (&forged_coordinates[0]) |*value| value.* = value.*.add(M31.one());
    const forged_columns = [_][]const M31{
        &forged_coordinates[0], &forged_coordinates[1],
        &forged_coordinates[2], &forged_coordinates[3],
    };
    var forged_tree = try SourceProver.commit(alloc, &forged_columns);
    defer forged_tree.deinit(alloc);
    var forged_prover_channel = Channel{};
    two_height_wire.bindVersion(&forged_prover_channel);
    const forged_sample = try two_height_wire.drawOodPointFromRoots(&forged_prover_channel, header);
    try std.testing.expect(forged_sample.eql(sample_point));
    _ = try two_height_wire.drawBatchAfterOod(&forged_prover_channel, header, forged_sample);
    _ = forged_prover_channel.drawSecureFelt();
    core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(
        &forged_prover_channel,
        forged_tree.root(),
    );
    _ = forged_prover_channel.drawSecureFelt();
    forged_prover_channel.mixFelts(terminal_coeffs);
    var forged_schedule = try two_height.sampleQuerySchedule(
        alloc,
        &forged_prover_channel,
        4,
        n_queries,
    );
    defer forged_schedule.deinit(alloc);
    const forged_projected = try core.pcs.paired_projection.projectPositions(
        alloc,
        forged_schedule.source_positions,
        4,
        3,
    );
    defer alloc.free(forged_projected);
    var forged_opened0 = try tree0.decommit(
        alloc,
        forged_schedule.source_positions,
        &sources0,
    );
    defer forged_opened0.deinit(alloc);
    var forged_opened1 = try tree1.decommit(
        alloc,
        forged_projected,
        &sources1,
    );
    defer forged_opened1.deinit(alloc);
    var forged_opened_line = try forged_tree.decommit(
        alloc,
        forged_schedule.line_positions,
        &forged_columns,
    );
    defer forged_opened_line.deinit(alloc);
    const forged_source0 = [_][]const M31{forged_opened0.queried_values[0]};
    const forged_source1 = [_][]const M31{forged_opened1.queried_values[0]};
    const forged_heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shape0,
            .source_root = tree0.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &forged_source0,
            .hash_witness = forged_opened0.decommitment.decommitment.hash_witness,
        },
        .{
            .shape = shape1,
            .source_root = tree1.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &forged_source1,
            .hash_witness = forged_opened1.decommitment.decommitment.hash_witness,
        },
    };
    const forged_envelope = envelope_mod.Envelope{
        .largest_log_size = 4,
        .query_count = 4 * n_queries,
        .heights = &forged_heights,
    };
    const forged_wire = try envelope_mod.encode(alloc, forged_envelope);
    defer alloc.free(forged_wire);
    var forged_verifier_channel = Channel{};
    var forged_prepared = try two_height_wire.bindSourceEnvelope(
        alloc,
        forged_wire,
        &forged_verifier_channel,
        expected_profile,
    );
    defer forged_prepared.deinit();
    const forged_intermediate = two_height.IntermediateOpening{
        .root = forged_tree.root(),
        .queried_coordinates = .{
            forged_opened_line.queried_values[0], forged_opened_line.queried_values[1],
            forged_opened_line.queried_values[2], forged_opened_line.queried_values[3],
        },
        .hash_witness = forged_opened_line.decommitment.decommitment.hash_witness,
    };
    try std.testing.expectError(
        error.IntermediateFoldMismatch,
        two_height.verifyAfterSourceBinding(
            alloc,
            &forged_verifier_channel,
            &forged_prepared,
            forged_intermediate,
            terminal_coeffs,
            n_queries,
        ),
    );
    const forged_line_wire = try two_height_wire.encode(alloc, .{
        .source_wire = forged_wire,
        .intermediate = forged_intermediate,
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    defer alloc.free(forged_line_wire);
    var forged_line_channel = Channel{};
    try std.testing.expectError(
        error.IntermediateFoldMismatch,
        two_height_wire.verify(
            alloc,
            forged_line_wire,
            &forged_line_channel,
            expected_profile,
            n_queries,
        ),
    );

    // An adversary can publish a different short terminal polynomial and
    // re-open both honest trees at the resulting Fiat-Shamir queries. Its
    // source and line Merkle proofs are then valid, but the second fold must
    // disagree with that polynomial.
    const wrong_terminal = [_]QM31{ terminal_coeffs[0].add(QM31.one()), terminal_coeffs[1] };
    var wrong_terminal_channel = Channel{};
    two_height_wire.bindVersion(&wrong_terminal_channel);
    const wrong_sample = try two_height_wire.drawOodPointFromRoots(&wrong_terminal_channel, header);
    try std.testing.expect(wrong_sample.eql(sample_point));
    _ = try two_height_wire.drawBatchAfterOod(&wrong_terminal_channel, header, wrong_sample);
    _ = wrong_terminal_channel.drawSecureFelt();
    core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(
        &wrong_terminal_channel,
        g0_tree.root(),
    );
    _ = wrong_terminal_channel.drawSecureFelt();
    wrong_terminal_channel.mixFelts(&wrong_terminal);
    var wrong_terminal_schedule = try two_height.sampleQuerySchedule(
        alloc,
        &wrong_terminal_channel,
        4,
        n_queries,
    );
    defer wrong_terminal_schedule.deinit(alloc);
    const wrong_projected = try core.pcs.paired_projection.projectPositions(
        alloc,
        wrong_terminal_schedule.source_positions,
        4,
        3,
    );
    defer alloc.free(wrong_projected);
    var wrong_source0 = try tree0.decommit(
        alloc,
        wrong_terminal_schedule.source_positions,
        &sources0,
    );
    defer wrong_source0.deinit(alloc);
    var wrong_source1 = try tree1.decommit(alloc, wrong_projected, &sources1);
    defer wrong_source1.deinit(alloc);
    var wrong_line = try g0_tree.decommit(
        alloc,
        wrong_terminal_schedule.line_positions,
        &g0_columns,
    );
    defer wrong_line.deinit(alloc);
    const wrong_columns0 = [_][]const M31{wrong_source0.queried_values[0]};
    const wrong_columns1 = [_][]const M31{wrong_source1.queried_values[0]};
    const wrong_heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shape0,
            .source_root = tree0.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &wrong_columns0,
            .hash_witness = wrong_source0.decommitment.decommitment.hash_witness,
        },
        .{
            .shape = shape1,
            .source_root = tree1.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &wrong_columns1,
            .hash_witness = wrong_source1.decommitment.decommitment.hash_witness,
        },
    };
    const wrong_source_wire = try envelope_mod.encode(alloc, .{
        .largest_log_size = 4,
        .query_count = 4 * n_queries,
        .heights = &wrong_heights,
    });
    defer alloc.free(wrong_source_wire);
    const wrong_intermediate = two_height.IntermediateOpening{
        .root = g0_tree.root(),
        .queried_coordinates = .{
            wrong_line.queried_values[0], wrong_line.queried_values[1],
            wrong_line.queried_values[2], wrong_line.queried_values[3],
        },
        .hash_witness = wrong_line.decommitment.decommitment.hash_witness,
    };
    const wrong_terminal_wire = try two_height_wire.encode(alloc, .{
        .source_wire = wrong_source_wire,
        .intermediate = wrong_intermediate,
        .terminal_ordered_coeffs = &wrong_terminal,
    });
    defer alloc.free(wrong_terminal_wire);
    var wrong_terminal_verifier = Channel{};
    try std.testing.expectError(
        error.TerminalFoldMismatch,
        two_height_wire.verify(
            alloc,
            wrong_terminal_wire,
            &wrong_terminal_verifier,
            expected_profile,
            n_queries,
        ),
    );
}
