const std = @import("std");
const air_accumulation = @import("air/accumulation.zig");
const air_components = @import("air/components.zig");
const circle = @import("circle.zig");
const fri = @import("fri.zig");
const m31 = @import("fields/m31.zig");
const line = @import("poly/line.zig");
const qm31 = @import("fields/qm31.zig");
const pcs = @import("pcs/mod.zig");
const pcs_verifier = @import("pcs/verifier.zig");
const proof_mod = @import("proof.zig");
const verifier_types = @import("verifier_types.zig");
const vcs_verifier = @import("vcs_lifted/verifier.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;
const MaskPoints = air_components.MaskPoints;

pub const PREPROCESSED_TRACE_IDX = verifier_types.PREPROCESSED_TRACE_IDX;
pub const COMPOSITION_LOG_SPLIT = verifier_types.COMPOSITION_LOG_SPLIT;
pub const VerificationError = verifier_types.VerificationError;

pub fn verify(
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    component_list: []const air_components.Component,
    channel: anytype,
    commitment_scheme: *pcs_verifier.CommitmentSchemeVerifier(H, MC),
    proof_in: proof_mod.StarkProof(H),
) anyerror!void {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);

    if (commitment_scheme.trees.items.len <= PREPROCESSED_TRACE_IDX) {
        return VerificationError.InvalidPreprocessedTree;
    }

    const n_preprocessed_columns = commitment_scheme
        .trees
        .items[PREPROCESSED_TRACE_IDX]
        .column_log_sizes
        .len;

    const components = air_components.Components{
        .components = component_list,
        .n_preprocessed_columns = n_preprocessed_columns,
    };
    const composition_log_size = components.compositionLogDegreeBound();
    if (composition_log_size <= COMPOSITION_LOG_SPLIT) return VerificationError.InvalidStructure;

    const random_coeff = channel.drawSecureFelt();

    if (proof.commitment_scheme_proof.commitments.items.len == 0) {
        return VerificationError.InvalidStructure;
    }

    const composition_commitment =
        proof.commitment_scheme_proof.commitments.items[
            proof.commitment_scheme_proof.commitments.items.len - 1
        ];

    var composition_commitment_log_sizes: [2 * qm31.SECURE_EXTENSION_DEGREE]u32 = undefined;
    @memset(
        composition_commitment_log_sizes[0..],
        composition_log_size - COMPOSITION_LOG_SPLIT,
    );
    try commitment_scheme.commit(
        allocator,
        composition_commitment,
        composition_commitment_log_sizes[0..],
        channel,
    );

    const oods_point = circle.randomSecureFieldPoint(channel);
    const max_log_degree_bound = composition_log_size - COMPOSITION_LOG_SPLIT;

    var sample_points = try components.maskPoints(
        allocator,
        oods_point,
        max_log_degree_bound,
        false,
    );
    var sample_points_moved = false;
    defer if (!sample_points_moved) sample_points.deinitDeep(allocator);

    try appendCompositionMaskTree(allocator, &sample_points, oods_point);

    const composition_oods_eval = proof.extractCompositionOodsEval(
        oods_point,
        composition_log_size,
    ) orelse return VerificationError.InvalidStructure;

    if (!composition_oods_eval.eql(try components.evalCompositionPolynomialAtPoint(
        oods_point,
        &proof.commitment_scheme_proof.sampled_values,
        random_coeff,
        max_log_degree_bound,
    ))) {
        return VerificationError.OodsNotMatching;
    }

    sample_points_moved = true;
    proof_moved = true;
    const pcs_proof = proof.commitment_scheme_proof;
    try commitment_scheme.verifyValues(allocator, sample_points, pcs_proof, channel);
}

fn appendCompositionMaskTree(
    allocator: std.mem.Allocator,
    sample_points: *MaskPoints,
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

fn buildTestProof(
    comptime H: type,
    allocator: std.mem.Allocator,
    commitments: []const H.Hash,
    composition_value: QM31,
) !proof_mod.StarkProof(H) {
    const composition_tree = try allocator.alloc([]QM31, 2 * qm31.SECURE_EXTENSION_DEGREE);
    var initialized: usize = 0;
    errdefer {
        for (composition_tree[0..initialized]) |col| allocator.free(col);
        allocator.free(composition_tree);
    }
    for (composition_tree) |*col| {
        col.* = try allocator.alloc(QM31, 1);
        col.*[0] = composition_value;
        initialized += 1;
    }

    return .{
        .commitment_scheme_proof = .{
            .config = pcs.PcsConfig.default(),
            .commitments = pcs.TreeVec(H.Hash).initOwned(try allocator.dupe(H.Hash, commitments)),
            .sampled_values = pcs.TreeVec([][]QM31).initOwned(
                try allocator.dupe([][]QM31, &[_][][]QM31{composition_tree}),
            ),
            .decommitments = pcs.TreeVec(vcs_verifier.MerkleDecommitmentLifted(H)).initOwned(
                try allocator.alloc(vcs_verifier.MerkleDecommitmentLifted(H), 0),
            ),
            .queried_values = pcs.TreeVec([][]M31).initOwned(
                try allocator.alloc([][]M31, 0),
            ),
            .proof_of_work = 0,
            .fri_proof = .{
                .first_layer = .{
                    .fri_witness = try allocator.alloc(QM31, 0),
                    .decommitment = .{ .hash_witness = try allocator.alloc(H.Hash, 0) },
                    .commitment = [_]u8{0} ** 32,
                },
                .inner_layers = try allocator.alloc(fri.FriLayerProof(H), 0),
                .last_layer_poly = line.LinePoly.initOwned(
                    try allocator.dupe(QM31, &[_]QM31{QM31.one()}),
                ),
            },
        },
    };
}

test "verifier: invalid proof structure when commitments missing" {
    const alloc = std.testing.allocator;
    const Hasher = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("channel/blake2s.zig").Blake2sChannel;

    const CommitmentSchemeVerifier = pcs_verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);

    const MockComponent = struct {
        max_log_degree_bound: u32,
        evaluation: QM31,

        fn asComponent(self: *const @This()) air_components.Component {
            return .{
                .ctx = self,
                .vtable = &.{
                    .nConstraints = nConstraints,
                    .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                    .traceLogDegreeBounds = traceLogDegreeBounds,
                    .maskPoints = maskPoints,
                    .preprocessedColumnIndices = preprocessedColumnIndices,
                    .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
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

        fn traceLogDegreeBounds(ctx: *const anyopaque, allocator: std.mem.Allocator) !air_components.TraceLogDegreeBounds {
            const self = cast(ctx);
            const preprocessed = try allocator.dupe(u32, &[_]u32{self.max_log_degree_bound});
            const main = try allocator.dupe(u32, &[_]u32{self.max_log_degree_bound});
            return air_components.TraceLogDegreeBounds.initOwned(
                try allocator.dupe([]u32, &[_][]u32{ preprocessed, main }),
            );
        }

        fn maskPoints(
            _: *const anyopaque,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            _: u32,
        ) !air_components.MaskPoints {
            const pp_col = try allocator.alloc(CirclePointQM31, 0);
            const preprocessed_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{pp_col});

            const main_col = try allocator.alloc(CirclePointQM31, 1);
            main_col[0] = point;
            const main_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{main_col});

            return air_components.MaskPoints.initOwned(
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
            _: *const air_components.MaskValues,
            evaluation_accumulator: *air_accumulation.PointEvaluationAccumulator,
            _: u32,
        ) !void {
            evaluation_accumulator.accumulate(cast(ctx).evaluation);
        }
    };

    var commitment_scheme = try CommitmentSchemeVerifier.init(alloc, .{
        .pow_bits = 4,
        .fri_config = try @import("fri.zig").FriConfig.init(0, 1, 1),
    });
    defer commitment_scheme.deinit(alloc);

    var commit_channel = Channel{};
    try commitment_scheme.commit(alloc, [_]u8{1} ** 32, &[_]u32{4}, &commit_channel);

    const mock = MockComponent{
        .max_log_degree_bound = 5,
        .evaluation = QM31.fromBase(M31.fromCanonical(7)),
    };
    const components = [_]air_components.Component{mock.asComponent()};

    const proof = try buildTestProof(Hasher, alloc, &[_]Hasher.Hash{}, QM31.zero());
    var verify_channel = Channel{};

    const trees_before = commitment_scheme.trees.items.len;
    try std.testing.expectError(
        VerificationError.InvalidStructure,
        verify(
            Hasher,
            MerkleChannel,
            alloc,
            components[0..],
            &verify_channel,
            &commitment_scheme,
            proof,
        ),
    );
    try std.testing.expectEqual(trees_before, commitment_scheme.trees.items.len);
}

test "verifier: oods mismatch is rejected" {
    const alloc = std.testing.allocator;
    const Hasher = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("channel/blake2s.zig").Blake2sChannel;
    const CommitmentSchemeVerifier = pcs_verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);

    const Mock = struct {
        max_log_degree_bound: u32,
        evaluation: QM31,

        fn asComponent(self: *const @This()) air_components.Component {
            return .{
                .ctx = self,
                .vtable = &.{
                    .nConstraints = nConstraints,
                    .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                    .traceLogDegreeBounds = traceLogDegreeBounds,
                    .maskPoints = maskPoints,
                    .preprocessedColumnIndices = preprocessedColumnIndices,
                    .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
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

        fn traceLogDegreeBounds(ctx: *const anyopaque, allocator: std.mem.Allocator) !air_components.TraceLogDegreeBounds {
            const self = cast(ctx);
            const preprocessed = try allocator.dupe(u32, &[_]u32{self.max_log_degree_bound});
            const main = try allocator.dupe(u32, &[_]u32{self.max_log_degree_bound});
            return air_components.TraceLogDegreeBounds.initOwned(
                try allocator.dupe([]u32, &[_][]u32{ preprocessed, main }),
            );
        }

        fn maskPoints(
            _: *const anyopaque,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            _: u32,
        ) !air_components.MaskPoints {
            const pp_col = try allocator.alloc(CirclePointQM31, 0);
            const preprocessed_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{pp_col});

            const main_col = try allocator.alloc(CirclePointQM31, 1);
            main_col[0] = point;
            const main_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{main_col});

            return air_components.MaskPoints.initOwned(
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
            _: *const air_components.MaskValues,
            evaluation_accumulator: *air_accumulation.PointEvaluationAccumulator,
            _: u32,
        ) !void {
            evaluation_accumulator.accumulate(cast(ctx).evaluation);
        }
    };

    var commitment_scheme = try CommitmentSchemeVerifier.init(alloc, .{
        .pow_bits = 4,
        .fri_config = try @import("fri.zig").FriConfig.init(0, 1, 1),
    });
    defer commitment_scheme.deinit(alloc);

    var commit_channel = Channel{};
    try commitment_scheme.commit(alloc, [_]u8{2} ** 32, &[_]u32{4}, &commit_channel);

    const mock = Mock{
        .max_log_degree_bound = 5,
        .evaluation = QM31.fromBase(M31.fromCanonical(1)),
    };
    const components = [_]air_components.Component{mock.asComponent()};

    const proof = try buildTestProof(
        Hasher,
        alloc,
        &[_]Hasher.Hash{[_]u8{9} ** 32},
        QM31.zero(),
    );
    var verify_channel = Channel{};

    try std.testing.expectError(
        VerificationError.OodsNotMatching,
        verify(
            Hasher,
            MerkleChannel,
            alloc,
            components[0..],
            &verify_channel,
            &commitment_scheme,
            proof,
        ),
    );
}
