const std = @import("std");
const builtin = @import("builtin");
const circle = @import("stwo_core").circle;
const core_air_components = @import("stwo_core").air.components;
const qm31 = @import("stwo_core").fields.qm31;
const pcs_core = @import("stwo_core").pcs;
const canonic = @import("stwo_core").poly.circle.canonic;
const proof_mod = @import("stwo_core").proof;
const verifier_types = @import("stwo_core").verifier_types;
const component_prover = @import("air/component_prover.zig");
const device_composition = @import("air/device_composition.zig");
const prover_air_accumulation = @import("air/accumulation.zig");
const prover_circle = @import("poly/circle/mod.zig");
const pcs_prover = @import("pcs/mod.zig");
const prover_api = @import("stwo_prover_api");
const stage_profile = prover_api.stage_profile;

const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const PREPROCESSED_TRACE_IDX = verifier_types.PREPROCESSED_TRACE_IDX;
const TreeVec = pcs_core.TreeVec;

pub const ProvingError = error{
    MissingPreprocessedTree,
    InvalidStructure,
    ConstraintsNotSatisfied,
};

/// Proving entrypoint matching upstream component-driven flow.
///
/// Returns only the `StarkProof` payload.
pub fn prove(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    components: []const component_prover.ComponentProver,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(B, H, MC),
) !proof_mod.StarkProof(H) {
    var extended = try proveEx(
        B,
        H,
        MC,
        allocator,
        components,
        channel,
        commitment_scheme,
        false,
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    return proof;
}

/// Extended proving entrypoint matching upstream component-driven `prove_ex`.
pub fn proveEx(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    components: []const component_prover.ComponentProver,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(B, H, MC),
    include_all_preprocessed_columns: bool,
) !proof_mod.ExtendedStarkProof(H) {
    return proveExWithRecorder(
        B,
        H,
        MC,
        allocator,
        components,
        channel,
        commitment_scheme,
        include_all_preprocessed_columns,
        null,
    );
}

pub fn proveExWithRecorder(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    components: []const component_prover.ComponentProver,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(B, H, MC),
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
) !proof_mod.ExtendedStarkProof(H) {
    return proveExWithStage(
        B,
        H,
        MC,
        allocator,
        components,
        channel,
        commitment_scheme,
        include_all_preprocessed_columns,
        recorder,
        null,
    );
}

/// As `proveExWithRecorder`, plus an optional whole-stage device composition
/// evaluator scoped to this one call. See `air/device_composition.zig`.
pub fn proveExWithStage(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    components: []const component_prover.ComponentProver,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(B, H, MC),
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
    composition_stage: ?device_composition.Stage,
) !proof_mod.ExtendedStarkProof(H) {
    return proveExWithExecution(
        B,
        H,
        MC,
        allocator,
        components,
        channel,
        commitment_scheme,
        include_all_preprocessed_columns,
        recorder,
        composition_stage,
        null,
    );
}

/// Adds an explicit per-proof CPU composition request without changing the
/// established device-stage entrypoint.
pub fn proveExWithExecution(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    components: []const component_prover.ComponentProver,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(B, H, MC),
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
    composition_stage: ?device_composition.Stage,
    cpu_composition_execution: ?prover_api.CpuCompositionExecutionRequest,
) !proof_mod.ExtendedStarkProof(H) {
    return proveExComponentsWithRecorder(
        B,
        H,
        MC,
        allocator,
        components,
        channel,
        commitment_scheme,
        include_all_preprocessed_columns,
        recorder,
        composition_stage,
        cpu_composition_execution,
    );
}

/// Sampled-points proving entrypoint.
///
/// This path proves with caller-provided sample points (without AIR component orchestration).
fn proveSampledPoints(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(B, H, MC),
    sampled_points: TreeVec([][]CirclePointQM31),
) !proof_mod.StarkProof(H) {
    var extended = try proveExSampledPoints(
        B,
        H,
        MC,
        allocator,
        channel,
        commitment_scheme,
        sampled_points,
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    return proof;
}

/// Extended sampled-points proving entrypoint.
fn proveExSampledPoints(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(B, H, MC),
    sampled_points: TreeVec([][]CirclePointQM31),
) !proof_mod.ExtendedStarkProof(H) {
    return proveExSampledPointsWithRecorder(
        B,
        H,
        MC,
        allocator,
        channel,
        commitment_scheme,
        sampled_points,
        null,
    );
}

fn proveExSampledPointsWithRecorder(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(B, H, MC),
    sampled_points: TreeVec([][]CirclePointQM31),
    recorder: ?*stage_profile.Recorder,
) !proof_mod.ExtendedStarkProof(H) {
    var scheme = commitment_scheme;
    if (scheme.trees.items.len == 0) {
        scheme.deinit(allocator);
        return ProvingError.MissingPreprocessedTree;
    }

    const commitment_proof = try scheme.proveValuesWithRecorder(
        allocator,
        sampled_points,
        recorder,
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
/// - `commitment_scheme` contains at least preprocessed/main trace trees.
fn proveExComponents(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    components: []const component_prover.ComponentProver,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(B, H, MC),
    include_all_preprocessed_columns: bool,
) !proof_mod.ExtendedStarkProof(H) {
    return proveExComponentsWithRecorder(
        B,
        H,
        MC,
        allocator,
        components,
        channel,
        commitment_scheme,
        include_all_preprocessed_columns,
        null,
        null,
        null,
    );
}

fn proveExComponentsWithRecorder(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    components: []const component_prover.ComponentProver,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(B, H, MC),
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
    composition_stage: ?device_composition.Stage,
    cpu_composition_execution: ?prover_api.CpuCompositionExecutionRequest,
) !proof_mod.ExtendedStarkProof(H) {
    var scheme = commitment_scheme;
    var owns_scheme = true;
    errdefer if (owns_scheme) scheme.deinit(allocator);

    if (scheme.trees.items.len <= PREPROCESSED_TRACE_IDX) {
        return ProvingError.MissingPreprocessedTree;
    }

    const component_provers = component_prover.ComponentProvers{
        .components = components,
        .n_preprocessed_columns = scheme.trees.items[PREPROCESSED_TRACE_IDX].columns.len,
        .composition_stage = composition_stage,
        .cpu_composition_execution = cpu_composition_execution,
        .task_recorder = if (recorder) |active|
            active.taskCaptureRecorder()
        else
            null,
    };

    const composition_log_size = component_provers.compositionLogDegreeBound();
    const composition_log_split = try component_provers.compositionLogSplit();
    if (composition_log_size <= composition_log_split) {
        return ProvingError.InvalidStructure;
    }
    const max_log_degree_bound = composition_log_size - composition_log_split;

    const random_coeff = blk: {
        var draw_random_coeff_stage = try stage_profile.StageScope.begin(
            recorder,
            "draw_random_coeff",
            "Draw random coefficient",
        );
        defer draw_random_coeff_stage.end();
        break :blk channel.drawSecureFelt();
    };

    {
        const residency_handles = try scheme.backendResidencyHandles(allocator);
        defer allocator.free(residency_handles);
        var trace = blk: {
            var composition_trace_stage = try stage_profile.StageScope.begin(
                recorder,
                "composition_trace_extract",
                "Composition trace extract",
            );
            defer composition_trace_stage.end();
            break :blk try scheme.trace(allocator);
        };
        defer trace.polys.deinitDeep(allocator);

        const composition_twiddles = try scheme.twiddle_source.get(
            allocator,
            composition_log_size,
        );

        var composition_eval = blk: {
            var composition_eval_stage = try stage_profile.StageScope.begin(
                recorder,
                "composition_evaluation",
                "Composition evaluation",
            );
            defer composition_eval_stage.end();
            break :blk try component_provers.computeCompositionEvaluationForBackend(
                B,
                allocator,
                random_coeff,
                &trace,
                residency_handles,
                composition_twiddles,
            );
        };
        defer composition_eval.deinit(allocator);

        var composition_split = blk: {
            var composition_interpolate_stage = try stage_profile.StageScope.begin(
                recorder,
                "composition_interpolate_and_split",
                "Composition interpolate and split",
            );
            defer composition_interpolate_stage.end();
            break :blk try prover_circle.secure_poly.interpolateAndSplitFromEvaluationWithTwiddlesForBackend(
                B,
                allocator,
                canonic.CanonicCoset.new(composition_log_size).circleDomain(),
                &composition_eval,
                composition_twiddles,
            );
        };
        defer composition_split.deinit(allocator);
        var composition_chunks = try splitCompositionPair(
            allocator,
            composition_split,
            composition_log_split,
        );
        defer composition_chunks.deinit(allocator);

        {
            var composition_commit_stage = try stage_profile.StageScope.begin(
                recorder,
                "composition_commit",
                "Composition commit",
            );
            defer composition_commit_stage.end();
            try commitCompositionChunks(
                B,
                H,
                MC,
                allocator,
                &scheme,
                composition_chunks.chunks,
                channel,
            );
        }
    }

    var components_view = try component_provers.componentsView(allocator);
    defer components_view.deinit(allocator);
    const core_components = components_view.asCore();

    const OodsSampling = struct {
        point: CirclePointQM31,
        sample_points: core_air_components.MaskPoints,
    };
    const oods_sampling = blk: {
        var oods_stage = try stage_profile.StageScope.begin(
            recorder,
            "oods_point_and_mask_points",
            "OODS point and mask points",
        );
        defer oods_stage.end();
        const oods_point = circle.randomSecureFieldPoint(channel);
        var sample_points = try core_components.maskPoints(
            allocator,
            oods_point,
            max_log_degree_bound,
            include_all_preprocessed_columns,
        );
        errdefer sample_points.deinitDeep(allocator);
        try appendCompositionMaskTree(
            allocator,
            &sample_points,
            oods_point,
            composition_log_split,
        );
        break :blk OodsSampling{
            .point = oods_point,
            .sample_points = sample_points,
        };
    };
    const sample_points = oods_sampling.sample_points;

    // Sampled-points proving consumes the scheme on both success and error.
    owns_scheme = false;
    var ext_proof = try proveExSampledPointsWithRecorder(
        B,
        H,
        MC,
        allocator,
        channel,
        scheme,
        sample_points,
        recorder,
    );
    errdefer ext_proof.deinit(allocator);

    {
        var constraint_stage = try stage_profile.StageScope.begin(
            recorder,
            "constraint_check_and_assembly",
            "Constraint check and assembly",
        );
        defer constraint_stage.end();

        const composition_oods_eval = ext_proof.proof.extractCompositionOodsEvalWithSplit(
            oods_sampling.point,
            composition_log_size,
            composition_log_split,
        ) orelse return ProvingError.InvalidStructure;

        const expected = try core_components.evalCompositionPolynomialAtPoint(
            oods_sampling.point,
            &ext_proof.proof.commitment_scheme_proof.sampled_values,
            random_coeff,
            max_log_degree_bound,
        );
        if (!composition_oods_eval.eql(expected)) return ProvingError.ConstraintsNotSatisfied;
    }

    return ext_proof;
}

fn proveComponents(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    components: []const component_prover.ComponentProver,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(B, H, MC),
    include_all_preprocessed_columns: bool,
) !proof_mod.StarkProof(H) {
    var extended = try proveExComponents(
        B,
        H,
        MC,
        allocator,
        components,
        channel,
        commitment_scheme,
        include_all_preprocessed_columns,
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    return proof;
}

/// Proving entrypoint for already-prepared sampled values.
///
/// This is a stepping-stone API until full in-prover sampled-value computation
/// parity is wired through prover/poly modules.
fn provePrepared(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(B, H, MC),
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

const CompositionChunks = struct {
    chunks: []prover_circle.SecureCirclePoly,
    owns_polynomials: bool,

    fn deinit(self: *CompositionChunks, allocator: std.mem.Allocator) void {
        if (self.owns_polynomials) {
            for (self.chunks) |*chunk| chunk.deinit(allocator);
        }
        allocator.free(self.chunks);
        self.* = undefined;
    }
};

fn splitCompositionPair(
    allocator: std.mem.Allocator,
    pair: prover_circle.SecureCirclePoly.SplitPair,
    split_depth: u32,
) !CompositionChunks {
    if (split_depth == 0) return ProvingError.InvalidStructure;
    if (split_depth == 1) {
        return .{
            .chunks = try allocator.dupe(
                prover_circle.SecureCirclePoly,
                &.{ pair.left, pair.right },
            ),
            .owns_polynomials = false,
        };
    }

    var left = try pair.left.splitIntoChunks(allocator, split_depth - 1);
    var left_moved = false;
    defer if (left_moved)
        allocator.free(left.chunks)
    else
        left.deinit(allocator);
    var right = try pair.right.splitIntoChunks(allocator, split_depth - 1);
    var right_moved = false;
    defer if (right_moved)
        allocator.free(right.chunks)
    else
        right.deinit(allocator);

    const chunks = try allocator.alloc(
        prover_circle.SecureCirclePoly,
        left.chunks.len + right.chunks.len,
    );
    @memcpy(chunks[0..left.chunks.len], left.chunks);
    @memcpy(chunks[left.chunks.len..], right.chunks);
    left_moved = true;
    right_moved = true;
    return .{ .chunks = chunks, .owns_polynomials = true };
}

fn commitCompositionChunks(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    commitment_scheme: *pcs_prover.CommitmentSchemeProver(B, H, MC),
    chunks: []const prover_circle.SecureCirclePoly,
    channel: anytype,
) !void {
    if (chunks.len == 0) return ProvingError.InvalidStructure;
    const split_log_size = chunks[0].logSize();
    for (chunks[1..]) |chunk| {
        if (chunk.logSize() != split_log_size) return ProvingError.InvalidStructure;
    }

    const n_polys = std.math.mul(
        usize,
        chunks.len,
        qm31.SECURE_EXTENSION_DEGREE,
    ) catch return ProvingError.InvalidStructure;
    const polys = try allocator.alloc(prover_circle.CircleCoefficients, n_polys);
    defer allocator.free(polys);

    for (chunks, 0..) |chunk, chunk_index| {
        for (chunk.polys, 0..) |coordinate, coordinate_index| {
            polys[chunk_index * qm31.SECURE_EXTENSION_DEGREE + coordinate_index] =
                coordinate;
        }
    }

    try commitment_scheme.commitPolys(allocator, polys, channel);
}

fn appendCompositionMaskTree(
    allocator: std.mem.Allocator,
    sample_points: *core_air_components.MaskPoints,
    oods_point: CirclePointQM31,
    split_depth: u32,
) !void {
    const n_composition_cols = verifier_types.compositionColumnCount(
        split_depth,
        qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return ProvingError.InvalidStructure;

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

/// Narrow access to private proving paths used by the owned integration tests.
/// The namespace is empty in production builds.
pub const testing = if (builtin.is_test) struct {
    pub const prepared = provePrepared;
    pub const sampledPoints = proveExSampledPoints;
} else struct {};
