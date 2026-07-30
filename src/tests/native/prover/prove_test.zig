const std = @import("std");
const prove_mod = @import("stwo_prover_engine").prove;
const circle = @import("stwo_core").circle;
const core_verifier = @import("stwo_core").verifier;
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs_core = @import("stwo_core").pcs;
const verifier_types = @import("stwo_core").verifier_types;
const component_prover = @import("stwo_prover_engine").air.component_prover;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const pcs_prover = @import("stwo_prover_engine").pcs;
const secure_column = @import("stwo_prover_engine").secure_column;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const PREPROCESSED_TRACE_IDX = verifier_types.PREPROCESSED_TRACE_IDX;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;
const TreeVec = pcs_core.TreeVec;
const prove = prove_mod.prove;
const proveEx = prove_mod.proveEx;

test "prover prove: early component and sampled-point errors consume schemes" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = pcs_prover.CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    var components_scheme = try Scheme.init(alloc, pcs_core.PcsConfig.default());
    _ = try components_scheme.twiddle_source.get(alloc, 6);
    var components_channel = Channel{};
    try std.testing.expectError(
        prove_mod.ProvingError.MissingPreprocessedTree,
        proveEx(
            CpuBackend,
            Hasher,
            MerkleChannel,
            alloc,
            &.{},
            &components_channel,
            components_scheme,
            false,
        ),
    );

    var sampled_scheme = try Scheme.init(alloc, pcs_core.PcsConfig.default());
    _ = try sampled_scheme.twiddle_source.get(alloc, 6);
    var sampled_points = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.alloc([][]CirclePointQM31, 0),
    );
    defer sampled_points.deinitDeep(alloc);
    var sampled_channel = Channel{};
    try std.testing.expectError(
        prove_mod.ProvingError.MissingPreprocessedTree,
        prove_mod.testing.sampledPoints(
            CpuBackend,
            Hasher,
            MerkleChannel,
            alloc,
            &sampled_channel,
            sampled_scheme,
            sampled_points,
        ),
    );
}

test "prover prove: prove_ex components slice verifies with core verifier" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = pcs_prover.CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const VerifierScheme = @import("stwo_core").pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    const MockComponent = struct {
        max_log_degree_bound: u32,
        value: QM31,

        fn asProverComponent(self: *const @This()) component_prover.ComponentProver {
            return .{
                .ctx = self,
                .vtable = &.{
                    .nConstraints = nConstraints,
                    .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                    .traceLogDegreeBounds = traceLogDegreeBounds,
                    .maskPoints = maskPoints,
                    .preprocessedColumnIndices = preprocessedColumnIndices,
                    .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
                    .evaluateConstraintQuotientsOnDomain = evaluateConstraintQuotientsOnDomain,
                },
            };
        }

        fn cast(ctx: *const anyopaque) *const @This() {
            return @ptrCast(@alignCast(ctx));
        }

        fn nConstraints(_: *const anyopaque) usize {
            return 1;
        }

        fn maxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
            return cast(ctx).max_log_degree_bound;
        }

        fn traceLogDegreeBounds(
            _: *const anyopaque,
            allocator: std.mem.Allocator,
        ) !core_air_components.TraceLogDegreeBounds {
            const preprocessed = try allocator.dupe(u32, &[_]u32{3});
            const main = try allocator.dupe(u32, &[_]u32{3});
            return core_air_components.TraceLogDegreeBounds.initOwned(
                try allocator.dupe([]u32, &[_][]u32{ preprocessed, main }),
            );
        }

        fn maskPoints(
            _: *const anyopaque,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            _: u32,
        ) !core_air_components.MaskPoints {
            const preprocessed_col = try allocator.alloc(CirclePointQM31, 1);
            preprocessed_col[0] = point;
            const preprocessed_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{preprocessed_col});

            const main_col = try allocator.alloc(CirclePointQM31, 1);
            main_col[0] = point;
            const main_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{main_col});

            return core_air_components.MaskPoints.initOwned(
                try allocator.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{
                    preprocessed_cols,
                    main_cols,
                }),
            );
        }

        fn preprocessedColumnIndices(_: *const anyopaque, allocator: std.mem.Allocator) ![]usize {
            return allocator.dupe(usize, &[_]usize{0});
        }

        fn evaluateConstraintQuotientsAtPoint(
            ctx: *const anyopaque,
            _: CirclePointQM31,
            _: *const core_air_components.MaskValues,
            evaluation_accumulator: *core_air_accumulation.PointEvaluationAccumulator,
            _: u32,
        ) !void {
            evaluation_accumulator.accumulate(cast(ctx).value);
        }

        fn evaluateConstraintQuotientsOnDomain(
            ctx: *const anyopaque,
            _: *const component_prover.Trace,
            evaluation_accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
        ) !void {
            const self = cast(ctx);
            const domain_size = @as(usize, 1) << @intCast(self.max_log_degree_bound);
            const values = try std.testing.allocator.alloc(QM31, domain_size);
            defer std.testing.allocator.free(values);
            @memset(values, self.value);

            var col = try SecureColumnByCoords.fromSecureSlice(std.testing.allocator, values);
            defer col.deinit(std.testing.allocator);
            try evaluation_accumulator.accumulateColumn(self.max_log_degree_bound, &col);
        }
    };

    const target_composition_eval = QM31.fromU32Unchecked(9, 8, 7, 6);

    var scheme = try Scheme.init(alloc, config);
    var prover_channel = Channel{};

    const preprocessed_col_0 = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
        M31.fromCanonical(1),
    };
    const preprocessed_col_1 = [_]M31{
        M31.fromCanonical(3),
        M31.fromCanonical(3),
        M31.fromCanonical(3),
        M31.fromCanonical(3),
        M31.fromCanonical(3),
        M31.fromCanonical(3),
        M31.fromCanonical(3),
        M31.fromCanonical(3),
    };
    try scheme.commit(
        alloc,
        &[_]pcs_prover.ColumnEvaluation{
            .{ .log_size = 3, .values = preprocessed_col_0[0..] },
            .{ .log_size = 3, .values = preprocessed_col_1[0..] },
        },
        &prover_channel,
    );

    const main_col = [_]M31{
        M31.fromCanonical(2),
        M31.fromCanonical(2),
        M31.fromCanonical(2),
        M31.fromCanonical(2),
        M31.fromCanonical(2),
        M31.fromCanonical(2),
        M31.fromCanonical(2),
        M31.fromCanonical(2),
    };
    try scheme.commit(
        alloc,
        &[_]pcs_prover.ColumnEvaluation{
            .{ .log_size = 3, .values = main_col[0..] },
        },
        &prover_channel,
    );

    const mock_component = MockComponent{
        .max_log_degree_bound = 4,
        .value = target_composition_eval,
    };
    const components_arr = [_]component_prover.ComponentProver{
        mock_component.asProverComponent(),
    };

    var ext_proof = try proveEx(
        CpuBackend,
        Hasher,
        MerkleChannel,
        alloc,
        components_arr[0..],
        &prover_channel,
        scheme,
        false,
    );
    defer ext_proof.aux.deinit(alloc);

    const preprocessed_sampled = ext_proof.proof.commitment_scheme_proof.sampled_values.items[
        PREPROCESSED_TRACE_IDX
    ];
    try std.testing.expectEqual(@as(usize, 2), preprocessed_sampled.len);
    try std.testing.expectEqual(@as(usize, 1), preprocessed_sampled[0].len);
    try std.testing.expectEqual(@as(usize, 0), preprocessed_sampled[1].len);

    var prove_scheme = try Scheme.init(alloc, config);
    var prove_channel = Channel{};
    try prove_scheme.commit(
        alloc,
        &[_]pcs_prover.ColumnEvaluation{
            .{ .log_size = 3, .values = preprocessed_col_0[0..] },
            .{ .log_size = 3, .values = preprocessed_col_1[0..] },
        },
        &prove_channel,
    );
    try prove_scheme.commit(
        alloc,
        &[_]pcs_prover.ColumnEvaluation{
            .{ .log_size = 3, .values = main_col[0..] },
        },
        &prove_channel,
    );

    var proof_from_prove = try prove(
        CpuBackend,
        Hasher,
        MerkleChannel,
        alloc,
        components_arr[0..],
        &prove_channel,
        prove_scheme,
    );
    defer proof_from_prove.deinit(alloc);

    const proof_wire = @import("stwo_proof_wire");
    const prove_ex_bytes = try proof_wire.encodeProofBytes(alloc, ext_proof.proof);
    defer alloc.free(prove_ex_bytes);
    const prove_bytes = try proof_wire.encodeProofBytes(alloc, proof_from_prove);
    defer alloc.free(prove_bytes);
    try std.testing.expectEqualSlices(u8, prove_ex_bytes, prove_bytes);

    var verifier = try VerifierScheme.init(alloc, config);
    defer verifier.deinit(alloc);

    var verifier_channel = Channel{};
    try verifier.commit(
        alloc,
        ext_proof.proof.commitment_scheme_proof.commitments.items[0],
        &[_]u32{ 3, 3 },
        &verifier_channel,
    );
    try verifier.commit(
        alloc,
        ext_proof.proof.commitment_scheme_proof.commitments.items[1],
        &[_]u32{3},
        &verifier_channel,
    );

    const prover_components = component_prover.ComponentProvers{
        .components = components_arr[0..],
        .n_preprocessed_columns = 1,
    };
    var components_view = try prover_components.componentsView(alloc);
    defer components_view.deinit(alloc);

    try core_verifier.verify(
        Hasher,
        MerkleChannel,
        alloc,
        components_view.asCore().components,
        &verifier_channel,
        &verifier,
        ext_proof.proof,
    );
}

test "prover prove: prepared proof verifies with core verifier" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = pcs_prover.CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const Verifier = @import("stwo_core").pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    var scheme = try Scheme.init(alloc, config);
    var prover_channel = Channel{};

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
        &[_]pcs_prover.ColumnEvaluation{
            .{ .log_size = 3, .values = column_values[0..] },
        },
        &prover_channel,
    );

    const sample_point = circle.SECURE_FIELD_CIRCLE_GEN.mul(13);
    const sample_value = QM31.fromBase(M31.fromCanonical(5));

    const sampled_points_col_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree_prover = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col_prover});
    const sampled_points_prover = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_prover}),
    );

    const sampled_values_col = try alloc.dupe(QM31, &[_]QM31{sample_value});
    const sampled_values_tree = try alloc.dupe([]QM31, &[_][]QM31{sampled_values_col});
    const sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{sampled_values_tree}),
    );

    var ext_proof = try prove_mod.testing.prepared(
        CpuBackend,
        Hasher,
        MerkleChannel,
        alloc,
        &prover_channel,
        scheme,
        sampled_points_prover,
        sampled_values,
    );
    defer ext_proof.aux.deinit(alloc);

    const sampled_points_col_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col_verify});
    const sampled_points_verify = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_verify}),
    );

    var verifier = try Verifier.init(alloc, config);
    defer verifier.deinit(alloc);

    var verifier_channel = Channel{};
    try verifier.commit(
        alloc,
        ext_proof.proof.commitment_scheme_proof.commitments.items[0],
        &[_]u32{3},
        &verifier_channel,
    );
    try verifier.verifyValues(
        alloc,
        sampled_points_verify,
        ext_proof.proof.commitment_scheme_proof,
        &verifier_channel,
    );
}

test "prover prove: prove_ex computes sampled values and verifies" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = pcs_prover.CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const Verifier = @import("stwo_core").pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    var scheme = try Scheme.init(alloc, config);
    var prover_channel = Channel{};

    const column_values = [_]M31{
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
        M31.fromCanonical(9),
    };
    try scheme.commit(
        alloc,
        &[_]pcs_prover.ColumnEvaluation{
            .{ .log_size = 3, .values = column_values[0..] },
        },
        &prover_channel,
    );

    const sample_point = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    const sampled_points_col_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
    });
    const sampled_points_tree_prover = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col_prover,
    });
    const sampled_points_prover = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_prover}),
    );

    var ext_proof = try prove_mod.testing.sampledPoints(
        CpuBackend,
        Hasher,
        MerkleChannel,
        alloc,
        &prover_channel,
        scheme,
        sampled_points_prover,
    );
    defer ext_proof.aux.deinit(alloc);

    const sampled_points_col_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col_verify});
    const sampled_points_verify = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_verify}),
    );

    var verifier = try Verifier.init(alloc, config);
    defer verifier.deinit(alloc);

    var verifier_channel = Channel{};
    try verifier.commit(
        alloc,
        ext_proof.proof.commitment_scheme_proof.commitments.items[0],
        &[_]u32{3},
        &verifier_channel,
    );
    try verifier.verifyValues(
        alloc,
        sampled_points_verify,
        ext_proof.proof.commitment_scheme_proof,
        &verifier_channel,
    );
}

test "prover prove: prove_ex supports non-zero blowup" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = pcs_prover.CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel);
    const Verifier = @import("stwo_core").pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 2, 3),
    };

    var scheme = try Scheme.init(alloc, config);
    var prover_channel = Channel{};

    const column_values = [_]M31{
        M31.fromCanonical(12),
        M31.fromCanonical(12),
        M31.fromCanonical(12),
        M31.fromCanonical(12),
        M31.fromCanonical(12),
        M31.fromCanonical(12),
        M31.fromCanonical(12),
        M31.fromCanonical(12),
    };
    try scheme.commit(
        alloc,
        &[_]pcs_prover.ColumnEvaluation{
            .{ .log_size = 3, .values = column_values[0..] },
        },
        &prover_channel,
    );
    try std.testing.expectEqual(@as(u32, 5), scheme.trees.items[0].columns[0].log_size);
    try std.testing.expectEqual(@as(usize, 32), scheme.trees.items[0].columns[0].values.len);

    const sample_point = circle.SECURE_FIELD_CIRCLE_GEN.mul(37);
    const sampled_points_col_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        sample_point,
    });
    const sampled_points_tree_prover = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        sampled_points_col_prover,
    });
    const sampled_points_prover = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_prover}),
    );

    var ext_proof = try prove_mod.testing.sampledPoints(
        CpuBackend,
        Hasher,
        MerkleChannel,
        alloc,
        &prover_channel,
        scheme,
        sampled_points_prover,
    );
    defer ext_proof.aux.deinit(alloc);

    const sampled_points_col_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col_verify});
    const sampled_points_verify = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_verify}),
    );

    var verifier = try Verifier.init(alloc, config);
    defer verifier.deinit(alloc);

    var verifier_channel = Channel{};
    try verifier.commit(
        alloc,
        ext_proof.proof.commitment_scheme_proof.commitments.items[0],
        &[_]u32{3},
        &verifier_channel,
    );
    try verifier.verifyValues(
        alloc,
        sampled_points_verify,
        ext_proof.proof.commitment_scheme_proof,
        &verifier_channel,
    );
}
