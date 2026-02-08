const std = @import("std");
const circle = @import("../core/circle.zig");
const core_verifier = @import("../core/verifier.zig");
const core_air_accumulation = @import("../core/air/accumulation.zig");
const core_air_components = @import("../core/air/components.zig");
const m31 = @import("../core/fields/m31.zig");
const qm31 = @import("../core/fields/qm31.zig");
const pcs_core = @import("../core/pcs/mod.zig");
const proof_mod = @import("../core/proof.zig");
const verifier_types = @import("../core/verifier_types.zig");
const component_prover = @import("air/component_prover.zig");
const prover_air_accumulation = @import("air/accumulation.zig");
const pcs_prover = @import("pcs/mod.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const COMPOSITION_LOG_SPLIT = verifier_types.COMPOSITION_LOG_SPLIT;
const PREPROCESSED_TRACE_IDX = verifier_types.PREPROCESSED_TRACE_IDX;
const TreeVec = pcs_core.TreeVec;

pub const ProvingError = error{
    MissingPreprocessedTree,
    InvalidStructure,
    ConstraintsNotSatisfied,
};

/// Temporary prove entrypoint on top of the sampled-points PCS path.
///
/// This returns only the proof payload (`StarkProof`), dropping auxiliary data.
pub fn prove(
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(H, MC),
    sampled_points: TreeVec([][]CirclePointQM31),
) !proof_mod.StarkProof(H) {
    return (try proveEx(
        H,
        MC,
        allocator,
        channel,
        commitment_scheme,
        sampled_points,
    )).proof;
}

/// Temporary extended prove entrypoint on top of the sampled-points PCS path.
///
/// This is an incremental bridge toward full upstream `prove_ex` parity.
pub fn proveEx(
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(H, MC),
    sampled_points: TreeVec([][]CirclePointQM31),
) !proof_mod.ExtendedStarkProof(H) {
    if (commitment_scheme.trees.items.len == 0) return ProvingError.MissingPreprocessedTree;

    const commitment_proof = try commitment_scheme.proveValues(
        allocator,
        sampled_points,
        channel,
    );

    return .{
        .proof = .{
            .commitment_scheme_proof = commitment_proof.proof,
        },
        .aux = commitment_proof.aux,
    };
}

/// Component-driven proving slice that derives OODS sample points from AIR components.
///
/// Preconditions:
/// - `commitment_scheme` already contains trace trees and composition tree commitment.
/// - the last committed tree corresponds to composition columns.
pub fn proveExComponents(
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    components: []const component_prover.ComponentProver,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(H, MC),
    include_all_preprocessed_columns: bool,
) !proof_mod.ExtendedStarkProof(H) {
    if (commitment_scheme.trees.items.len <= PREPROCESSED_TRACE_IDX) {
        return ProvingError.MissingPreprocessedTree;
    }

    const component_provers = component_prover.ComponentProvers{
        .components = components,
        .n_preprocessed_columns = commitment_scheme.trees.items[PREPROCESSED_TRACE_IDX].columns.len,
    };

    const composition_log_size = component_provers.compositionLogDegreeBound();
    if (composition_log_size <= COMPOSITION_LOG_SPLIT) return ProvingError.InvalidStructure;
    const max_log_degree_bound = composition_log_size - COMPOSITION_LOG_SPLIT;

    const random_coeff = channel.drawSecureFelt();
    const oods_point = circle.randomSecureFieldPoint(channel);

    var components_view = try component_provers.componentsView(allocator);
    defer components_view.deinit(allocator);
    const core_components = components_view.asCore();

    var sample_points = try core_components.maskPoints(
        allocator,
        oods_point,
        max_log_degree_bound,
        include_all_preprocessed_columns,
    );
    try appendCompositionMaskTree(allocator, &sample_points, oods_point);

    var ext_proof = try proveEx(
        H,
        MC,
        allocator,
        channel,
        commitment_scheme,
        sample_points,
    );

    const composition_oods_eval = ext_proof.proof.extractCompositionOodsEval(
        oods_point,
        composition_log_size,
    ) orelse return ProvingError.InvalidStructure;

    const expected = try core_components.evalCompositionPolynomialAtPoint(
        oods_point,
        &ext_proof.proof.commitment_scheme_proof.sampled_values,
        random_coeff,
        max_log_degree_bound,
    );
    if (!composition_oods_eval.eql(expected)) return ProvingError.ConstraintsNotSatisfied;

    return ext_proof;
}

pub fn proveComponents(
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    components: []const component_prover.ComponentProver,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(H, MC),
    include_all_preprocessed_columns: bool,
) !proof_mod.StarkProof(H) {
    return (try proveExComponents(
        H,
        MC,
        allocator,
        components,
        channel,
        commitment_scheme,
        include_all_preprocessed_columns,
    )).proof;
}

/// Proving entrypoint for already-prepared sampled values.
///
/// This is a stepping-stone API until full in-prover sampled-value computation
/// parity is wired through prover/poly modules.
pub fn provePrepared(
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(H, MC),
    sampled_points: TreeVec([][]CirclePointQM31),
    sampled_values: TreeVec([][]QM31),
) !proof_mod.ExtendedStarkProof(H) {
    if (commitment_scheme.trees.items.len == 0) return ProvingError.MissingPreprocessedTree;

    const commitment_proof = try commitment_scheme.proveValuesFromSamples(
        allocator,
        sampled_points,
        sampled_values,
        channel,
    );

    return .{
        .proof = .{
            .commitment_scheme_proof = commitment_proof.proof,
        },
        .aux = commitment_proof.aux,
    };
}

fn appendCompositionMaskTree(
    allocator: std.mem.Allocator,
    sample_points: *core_air_components.MaskPoints,
    oods_point: CirclePointQM31,
) !void {
    const n_composition_cols = 2 * qm31.SECURE_EXTENSION_DEGREE;

    const composition_tree = try allocator.alloc([]CirclePointQM31, n_composition_cols);
    var initialized: usize = 0;
    errdefer {
        for (composition_tree[0..initialized]) |col| allocator.free(col);
        allocator.free(composition_tree);
    }

    for (composition_tree) |*col| {
        col.* = try allocator.alloc(CirclePointQM31, 1);
        col.*[0] = oods_point;
        initialized += 1;
    }

    const old_len = sample_points.items.len;
    const out = try allocator.alloc([][]CirclePointQM31, old_len + 1);
    @memcpy(out[0..old_len], sample_points.items);
    out[old_len] = composition_tree;

    allocator.free(sample_points.items);
    sample_points.items = out;
}

test "prover prove: prepared proof verifies with core verifier" {
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = pcs_prover.CommitmentSchemeProver(Hasher, MerkleChannel);
    const Verifier = @import("../core/pcs/verifier.zig").CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
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

    var ext_proof = try provePrepared(
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
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = pcs_prover.CommitmentSchemeProver(Hasher, MerkleChannel);
    const Verifier = @import("../core/pcs/verifier.zig").CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
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

    var ext_proof = try proveEx(
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

test "prover prove: prove_ex components slice verifies with core verifier" {
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = pcs_prover.CommitmentSchemeProver(Hasher, MerkleChannel);
    const VerifierScheme = @import("../core/pcs/verifier.zig").CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
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
            _: *const anyopaque,
            _: *const component_prover.Trace,
            _: *prover_air_accumulation.DomainEvaluationAccumulator,
        ) !void {}
    };

    const target_composition_eval = QM31.fromU32Unchecked(9, 8, 7, 6);
    const target_coords = target_composition_eval.toM31Array();

    var scheme = try Scheme.init(alloc, config);
    var prover_channel = Channel{};

    const preprocessed_col = [_]M31{
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
        &[_]pcs_prover.ColumnEvaluation{
            .{ .log_size = 3, .values = preprocessed_col[0..] },
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

    var composition_col_values: [2 * qm31.SECURE_EXTENSION_DEGREE][8]M31 = undefined;
    var composition_columns: [2 * qm31.SECURE_EXTENSION_DEGREE]pcs_prover.ColumnEvaluation = undefined;
    for (0..2 * qm31.SECURE_EXTENSION_DEGREE) |i| {
        const fill_value = if (i < qm31.SECURE_EXTENSION_DEGREE) target_coords[i] else M31.zero();
        @memset(composition_col_values[i][0..], fill_value);
        composition_columns[i] = .{
            .log_size = 3,
            .values = composition_col_values[i][0..],
        };
    }
    try scheme.commit(
        alloc,
        composition_columns[0..],
        &prover_channel,
    );

    const mock_component = MockComponent{
        .max_log_degree_bound = 4,
        .value = target_composition_eval,
    };
    const components_arr = [_]component_prover.ComponentProver{
        mock_component.asProverComponent(),
    };

    var ext_proof = try proveExComponents(
        Hasher,
        MerkleChannel,
        alloc,
        components_arr[0..],
        &prover_channel,
        scheme,
        false,
    );
    defer ext_proof.aux.deinit(alloc);

    var verifier = try VerifierScheme.init(alloc, config);
    defer verifier.deinit(alloc);

    var verifier_channel = Channel{};
    try verifier.commit(
        alloc,
        ext_proof.proof.commitment_scheme_proof.commitments.items[0],
        &[_]u32{3},
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
