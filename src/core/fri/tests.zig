const std = @import("std");
const fri = @import("stwo_core").fri;
const geometry = @import("stwo_core").fri.geometry;
const circle = @import("stwo_core").circle;
const fft = @import("stwo_core").fft;
const fields = @import("stwo_core").fields;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const line = @import("stwo_core").poly.line;
const canonic = @import("stwo_core").poly.circle.canonic;
const circle_domain = @import("stwo_core").poly.circle.domain;
const queries_mod = @import("stwo_core").queries;
const core_utils = @import("stwo_core").utils;
const vcs_verifier = @import("stwo_core").vcs_lifted.verifier;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const FriConfig = fri.FriConfig;
const FOLD_STEP = fri.FOLD_STEP;
const CIRCLE_TO_LINE_FOLD_STEP = fri.CIRCLE_TO_LINE_FOLD_STEP;
const FriVerificationError = fri.FriVerificationError;
const CirclePolyDegreeBound = fri.CirclePolyDegreeBound;
const LinePolyDegreeBound = fri.LinePolyDegreeBound;
const FriVerifier = fri.FriVerifier;
const FriLayerProof = fri.FriLayerProof;
const FriLayerProofAux = fri.FriLayerProofAux;
const FriProof = fri.FriProof;
const FriProofAux = fri.FriProofAux;
const ExtendedFriProof = fri.ExtendedFriProof;
const SparseEvaluation = fri.SparseEvaluation;
const computeDecommitmentPositionsAndRebuildEvals = fri.computeDecommitmentPositionsAndRebuildEvals;
const FoldLineWorkspace = fri.FoldLineWorkspace;
const FoldCircleWorkspace = fri.FoldCircleWorkspace;
const foldLine = fri.foldLine;
const foldLineSingleStep = fri.foldLineSingleStep;
const foldLineWithWorkspace = fri.foldLineWithWorkspace;
const foldLineInPlaceWithWorkspace = fri.foldLineInPlaceWithWorkspace;
const foldCircleIntoLine = fri.foldCircleIntoLine;
const foldCircleIntoLineWithWorkspace = fri.foldCircleIntoLineWithWorkspace;
const foldCircleColumnsIntoLineWithWorkspace = fri.foldCircleColumnsIntoLineWithWorkspace;
const accumulateLine = fri.accumulateLine;

test {
    std.testing.refAllDecls(geometry);
}

test "fri config: security bits" {
    const config = try FriConfig.init(10, 10, 70);
    try std.testing.expectEqual(@as(u32, 700), config.securityBits());
}

test "fri config: default values" {
    const cfg = FriConfig.default();
    try std.testing.expectEqual(@as(u32, 0), cfg.log_last_layer_degree_bound);
    try std.testing.expectEqual(@as(u32, 1), cfg.log_blowup_factor);
    try std.testing.expectEqual(@as(usize, 3), cfg.n_queries);
}

test "fri config: bounds checks" {
    try std.testing.expectError(FriConfig.Error.InvalidLastLayerDegreeBound, FriConfig.init(11, 1, 1));
    try std.testing.expectError(FriConfig.Error.InvalidBlowupFactor, FriConfig.init(0, 0, 1));
}

test "fri: degree bound folding" {
    const circle_bound = CirclePolyDegreeBound.init(7);
    const line_bound = circle_bound.foldToLine();
    try std.testing.expectEqual(@as(u32, 6), line_bound.log_degree_bound);
    try std.testing.expectEqual(@as(u32, 5), (line_bound.fold(1) orelse unreachable).log_degree_bound);
    try std.testing.expect((line_bound.fold(7)) == null);
}

test "fri: accumulate line" {
    var layer = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
    };
    const folded = [_]QM31{
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    const alpha = QM31.fromU32Unchecked(5, 0, 0, 0);
    accumulateLine(layer[0..], folded[0..], alpha);

    const alpha_sq = alpha.square();
    try std.testing.expect(layer[0].eql(QM31.fromU32Unchecked(1, 0, 0, 0).mul(alpha_sq).add(folded[0])));
    try std.testing.expect(layer[1].eql(QM31.fromU32Unchecked(2, 0, 0, 0).mul(alpha_sq).add(folded[1])));
}

test "fri: compute decommitment positions and rebuild evals" {
    const alloc = std.testing.allocator;
    const raw_queries = [_]usize{ 1, 2, 5 };
    var queries = try queries_mod.Queries.init(alloc, raw_queries[0..], 3);
    defer queries.deinit(alloc);

    const q1 = QM31.fromU32Unchecked(11, 0, 0, 0);
    const q2 = QM31.fromU32Unchecked(22, 0, 0, 0);
    const q5 = QM31.fromU32Unchecked(55, 0, 0, 0);
    const query_evals = [_]QM31{ q1, q2, q5 };
    const witness = [_]QM31{
        QM31.fromU32Unchecked(10, 0, 0, 0),
        QM31.fromU32Unchecked(30, 0, 0, 0),
        QM31.fromU32Unchecked(40, 0, 0, 0),
    };

    var result = try computeDecommitmentPositionsAndRebuildEvals(
        alloc,
        queries,
        query_evals[0..],
        witness[0..],
        1,
    );
    defer result.deinit(alloc);

    try std.testing.expectEqualSlices(usize, &[_]usize{ 0, 1, 2, 3, 4, 5 }, result.decommitment_positions);
    try std.testing.expectEqual(@as(usize, 3), result.sparse_evaluation.subset_evals.len);
    try std.testing.expectEqual(@as(usize, 3), result.consumed_witness);
    try std.testing.expect(result.sparse_evaluation.subset_evals[0][0].eql(witness[0]));
    try std.testing.expect(result.sparse_evaluation.subset_evals[0][1].eql(q1));
    try std.testing.expect(result.sparse_evaluation.subset_evals[1][0].eql(q2));
    try std.testing.expect(result.sparse_evaluation.subset_evals[1][1].eql(witness[1]));
    try std.testing.expect(result.sparse_evaluation.subset_evals[2][0].eql(witness[2]));
    try std.testing.expect(result.sparse_evaluation.subset_evals[2][1].eql(q5));
}

test "fri: compute decommitment fails on insufficient witness" {
    const alloc = std.testing.allocator;
    const raw_queries = [_]usize{ 1, 2, 5 };
    var queries = try queries_mod.Queries.init(alloc, raw_queries[0..], 3);
    defer queries.deinit(alloc);

    const query_evals = [_]QM31{
        QM31.fromU32Unchecked(11, 0, 0, 0),
        QM31.fromU32Unchecked(22, 0, 0, 0),
        QM31.fromU32Unchecked(55, 0, 0, 0),
    };
    const short_witness = [_]QM31{
        QM31.fromU32Unchecked(10, 0, 0, 0),
        QM31.fromU32Unchecked(30, 0, 0, 0),
    };

    try std.testing.expectError(
        error.InsufficientWitness,
        computeDecommitmentPositionsAndRebuildEvals(
            alloc,
            queries,
            query_evals[0..],
            short_witness[0..],
            1,
        ),
    );
}

test "fri: fold line applies FOLD_STEP sequential butterfly folds" {
    const alloc = std.testing.allocator;
    // Domain must have at least 2^FOLD_STEP elements.
    const domain = try line.LineDomain.init(circle.Coset.halfOdds(FOLD_STEP));
    const alpha = QM31.fromU32Unchecked(9, 0, 0, 0);

    const fold_factor = @as(usize, 1) << @intCast(FOLD_STEP);
    const eval_buf = try alloc.alloc(QM31, fold_factor);
    defer alloc.free(eval_buf);
    for (eval_buf, 0..) |*v, idx| {
        v.* = QM31.fromU32Unchecked(@intCast(idx + 1), @intCast(idx + 2), 0, 0);
    }

    const folded = try foldLine(alloc, eval_buf, domain, alpha);
    defer alloc.free(folded.values);

    // After FOLD_STEP halvings the domain logSize shrinks by FOLD_STEP and
    // the evaluation reduces to a single element.
    try std.testing.expectEqual(@as(u32, 0), folded.domain.logSize());
    try std.testing.expectEqual(@as(usize, 1), folded.values.len);

    // Verify by applying FOLD_STEP single-step folds manually.
    var expected = try alloc.dupe(QM31, eval_buf);
    var cur_domain = domain;
    var current_alpha = alpha;
    var step: u32 = 0;
    while (step < FOLD_STEP) : (step += 1) {
        const half = expected.len / 2;
        var ws = try FoldLineWorkspace.init(alloc, half);
        defer ws.deinit(alloc);
        const result = try foldLineSingleStep(alloc, expected, cur_domain, current_alpha, &ws);
        alloc.free(expected);
        expected = result.values;
        cur_domain = result.domain;
        current_alpha = current_alpha.square();
    }
    defer alloc.free(expected);

    try std.testing.expectEqual(@as(usize, 1), expected.len);
    try std.testing.expect(folded.values[0].eql(expected[0]));
}

test "fri: fold line workspace path matches default implementation" {
    const alloc = std.testing.allocator;
    const domain = try line.LineDomain.init(circle.Coset.halfOdds(4));
    const alpha = QM31.fromU32Unchecked(5, 7, 11, 13);
    const eval = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
        QM31.fromU32Unchecked(17, 18, 19, 20),
        QM31.fromU32Unchecked(21, 22, 23, 24),
        QM31.fromU32Unchecked(25, 26, 27, 28),
        QM31.fromU32Unchecked(29, 30, 31, 1),
        QM31.fromU32Unchecked(2, 3, 4, 5),
        QM31.fromU32Unchecked(6, 7, 8, 9),
        QM31.fromU32Unchecked(10, 11, 12, 13),
        QM31.fromU32Unchecked(14, 15, 16, 17),
        QM31.fromU32Unchecked(18, 19, 20, 21),
        QM31.fromU32Unchecked(22, 23, 24, 25),
        QM31.fromU32Unchecked(26, 27, 28, 29),
        QM31.fromU32Unchecked(30, 31, 1, 2),
    };

    const default_fold = try foldLine(alloc, eval[0..], domain, alpha);
    defer alloc.free(default_fold.values);

    var workspace = try FoldLineWorkspace.init(alloc, 1);
    defer workspace.deinit(alloc);
    const workspace_fold = try foldLineWithWorkspace(
        alloc,
        eval[0..],
        domain,
        alpha,
        &workspace,
    );
    defer alloc.free(workspace_fold.values);

    try std.testing.expectEqual(default_fold.domain.logSize(), workspace_fold.domain.logSize());
    try std.testing.expectEqual(default_fold.values.len, workspace_fold.values.len);
    for (default_fold.values, workspace_fold.values) |lhs, rhs| {
        try std.testing.expect(lhs.eql(rhs));
    }
}

test "fri: fold line in-place workspace matches default implementation" {
    const alloc = std.testing.allocator;
    const domain = try line.LineDomain.init(circle.Coset.halfOdds(4));
    const alpha = QM31.fromU32Unchecked(5, 7, 11, 13);
    const eval = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
        QM31.fromU32Unchecked(17, 18, 19, 20),
        QM31.fromU32Unchecked(21, 22, 23, 24),
        QM31.fromU32Unchecked(25, 26, 27, 28),
        QM31.fromU32Unchecked(29, 30, 31, 1),
        QM31.fromU32Unchecked(2, 3, 4, 5),
        QM31.fromU32Unchecked(6, 7, 8, 9),
        QM31.fromU32Unchecked(10, 11, 12, 13),
        QM31.fromU32Unchecked(14, 15, 16, 17),
        QM31.fromU32Unchecked(18, 19, 20, 21),
        QM31.fromU32Unchecked(22, 23, 24, 25),
        QM31.fromU32Unchecked(26, 27, 28, 29),
        QM31.fromU32Unchecked(30, 31, 1, 2),
    };

    const default_fold = try foldLine(alloc, eval[0..], domain, alpha);
    defer alloc.free(default_fold.values);

    var workspace = try FoldLineWorkspace.init(alloc, 1);
    defer workspace.deinit(alloc);
    const owned_eval = try alloc.dupe(QM31, eval[0..]);
    const in_place_fold = try foldLineInPlaceWithWorkspace(
        alloc,
        owned_eval,
        domain,
        alpha,
        &workspace,
    );
    defer alloc.free(in_place_fold.values);

    try std.testing.expectEqual(default_fold.domain.logSize(), in_place_fold.domain.logSize());
    try std.testing.expectEqual(default_fold.values.len, in_place_fold.values.len);
    for (default_fold.values, in_place_fold.values) |lhs, rhs| {
        try std.testing.expect(lhs.eql(rhs));
    }
}

test "fri: fold circle into line accumulates correctly" {
    const src_domain = canonic.CanonicCoset.new(2).circleDomain();
    const alpha = QM31.fromU32Unchecked(7, 0, 0, 0);
    const src = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    var dst = [_]QM31{ QM31.zero(), QM31.zero() };

    try foldCircleIntoLine(dst[0..], src[0..], src_domain, alpha);

    var expected = [_]QM31{ QM31.zero(), QM31.zero() };
    const alpha_sq = alpha.square();
    var i: usize = 0;
    while (i < expected.len) : (i += 1) {
        const p = src_domain.at(core_utils.bitReverseIndex(i << @intCast(CIRCLE_TO_LINE_FOLD_STEP), src_domain.logSize()));
        var f0 = src[i * 2];
        var f1 = src[i * 2 + 1];
        fft.ibutterfly(QM31, &f0, &f1, try p.y.inv());
        const f_prime = alpha.mul(f1).add(f0);
        expected[i] = expected[i].mul(alpha_sq).add(f_prime);
    }

    try std.testing.expect(dst[0].eql(expected[0]));
    try std.testing.expect(dst[1].eql(expected[1]));
}

test "fri: fold circle columns workspace path matches qm31 slice path" {
    const alloc = std.testing.allocator;
    const src_domain = canonic.CanonicCoset.new(2).circleDomain();
    const alpha = QM31.fromU32Unchecked(7, 0, 0, 0);
    const src = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
    };
    var dst_qm31 = [_]QM31{ QM31.zero(), QM31.zero() };
    var dst_cols = [_]QM31{ QM31.zero(), QM31.zero() };

    try foldCircleIntoLine(dst_qm31[0..], src[0..], src_domain, alpha);

    var c0 = [_]M31{ M31.zero(), M31.zero(), M31.zero(), M31.zero() };
    var c1 = [_]M31{ M31.zero(), M31.zero(), M31.zero(), M31.zero() };
    var c2 = [_]M31{ M31.zero(), M31.zero(), M31.zero(), M31.zero() };
    var c3 = [_]M31{ M31.zero(), M31.zero(), M31.zero(), M31.zero() };
    for (src, 0..) |value, i| {
        const coords = value.toM31Array();
        c0[i] = coords[0];
        c1[i] = coords[1];
        c2[i] = coords[2];
        c3[i] = coords[3];
    }
    const columns = [_][]const M31{ c0[0..], c1[0..], c2[0..], c3[0..] };
    var workspace = try FoldCircleWorkspace.init(alloc, dst_cols.len);
    defer workspace.deinit(alloc);
    try foldCircleColumnsIntoLineWithWorkspace(
        alloc,
        dst_cols[0..],
        columns,
        src_domain,
        alpha,
        &workspace,
    );

    try std.testing.expect(dst_cols[0].eql(dst_qm31[0]));
    try std.testing.expect(dst_cols[1].eql(dst_qm31[1]));
}

test "fri verifier: commit and sample query positions" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const Verifier = FriVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    var channel = Channel{};
    const config = try FriConfig.init(2, 1, 4);
    var last_layer_poly = line.LinePoly.initOwned(
        try alloc.dupe(QM31, &[_]QM31{QM31.one()}),
    );
    defer last_layer_poly.deinit(alloc);
    var verifier = try Verifier.commit(
        alloc,
        &channel,
        config,
        .{
            .first_layer = .{
                .fri_witness = try alloc.alloc(QM31, 0),
                .decommitment = .{ .hash_witness = try alloc.alloc(Hasher.Hash, 0) },
                .commitment = [_]u8{2} ** 32,
            },
            .inner_layers = try alloc.alloc(FriLayerProof(Hasher), 0),
            .last_layer_poly = last_layer_poly,
        },
        CirclePolyDegreeBound.init(3),
    );
    defer verifier.deinit(alloc);

    const positions = try verifier.sampleQueryPositions(alloc, &channel);
    defer alloc.free(positions);
    try std.testing.expect(positions.len <= config.n_queries);
    for (positions) |pos| {
        try std.testing.expect(pos < (@as(usize, 1) << @intCast(3 + config.log_blowup_factor)));
    }
}

test "fri verifier: invalid layer count fails commit" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const Verifier = FriVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    var channel = Channel{};
    const config = try FriConfig.init(1, 1, 2);
    var last_layer_poly = line.LinePoly.initOwned(
        try alloc.dupe(QM31, &[_]QM31{QM31.one()}),
    );
    defer last_layer_poly.deinit(alloc);
    try std.testing.expectError(
        FriVerificationError.InvalidNumFriLayers,
        Verifier.commit(
            alloc,
            &channel,
            config,
            .{
                .first_layer = .{
                    .fri_witness = try alloc.alloc(QM31, 0),
                    .decommitment = .{ .hash_witness = try alloc.alloc(Hasher.Hash, 0) },
                    .commitment = [_]u8{9} ** 32,
                },
                .inner_layers = try alloc.alloc(FriLayerProof(Hasher), 0),
                .last_layer_poly = last_layer_poly,
            },
            CirclePolyDegreeBound.init(3),
        ),
    );
}

test "fri proof containers: deinit owned buffers" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const LayerProof = FriLayerProof(Hasher);
    const LayerProofAux = FriLayerProofAux(Hasher);
    const Proof = FriProof(Hasher);
    const ProofAux = FriProofAux(Hasher);
    const Extended = ExtendedFriProof(Hasher);
    const MerkleAux = vcs_verifier.MerkleDecommitmentLiftedAux(Hasher);

    const alloc = std.testing.allocator;

    const first_witness = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
    });
    const first_decommitment = vcs_verifier.MerkleDecommitmentLifted(Hasher){
        .hash_witness = try alloc.alloc(Hasher.Hash, 0),
    };
    const first_layer = LayerProof{
        .fri_witness = first_witness,
        .decommitment = first_decommitment,
        .commitment = [_]u8{0} ** 32,
    };

    const inner_witness = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(3, 0, 0, 0),
    });
    const inner_decommitment = vcs_verifier.MerkleDecommitmentLifted(Hasher){
        .hash_witness = try alloc.alloc(Hasher.Hash, 0),
    };
    const inner_layers = try alloc.alloc(LayerProof, 1);
    inner_layers[0] = .{
        .fri_witness = inner_witness,
        .decommitment = inner_decommitment,
        .commitment = [_]u8{1} ** 32,
    };

    const poly_coeffs = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(5, 0, 0, 0),
    });
    const proof = Proof{
        .first_layer = first_layer,
        .inner_layers = inner_layers,
        .last_layer_poly = line.LinePoly.initOwned(poly_coeffs),
    };

    const first_aux = LayerProofAux{
        .all_values = try alloc.alloc([]LayerProofAux.IndexedValue, 0),
        .decommitment = MerkleAux{
            .all_node_values = try alloc.alloc([]MerkleAux.NodeValue, 0),
        },
    };
    const inner_aux_layers = try alloc.alloc(LayerProofAux, 0);
    const proof_aux = ProofAux{
        .first_layer = first_aux,
        .inner_layers = inner_aux_layers,
    };

    var extended = Extended{
        .proof = proof,
        .aux = proof_aux,
    };
    extended.deinit(alloc);
}
