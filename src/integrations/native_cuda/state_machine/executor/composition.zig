//! Exact resident two-component LogUp interaction and composition.

const field = @import(
    "../../../../backends/cuda/abi/field.zig",
);
const relation_stage = @import(
    "../../../../backends/cuda/runtime/stages/relation.zig",
);
const stages = @import(
    "../../../../backends/cuda/runtime/stages/mod.zig",
);
const commit_tree = @import("../../common/commit_tree.zig");
const proof_assembly = @import("../../common/proof_assembly.zig");
const transcript = @import("../../common/transcript_executor.zig");
const constraint = @import("../constraint.zig");
const plan_mod = @import("../plan.zig");
const relation_mod = @import("../relation.zig");
const slots = @import("../slots.zig");

const NativeOps = struct {
    const Transcript = stages.transcript.Native;
    const Relation = relation_stage.Native;
    const Power = stages.constraint_power.Native;
    const Constraint = constraint;
    const Split = stages.composition_split.Native;
    const Transform = stages.transform.Native;
    const Commitment = stages.commitment.Native;
};

pub fn run(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: anytype,
) !void {
    return runWith(NativeOps, transaction, prepared, views);
}

pub fn runWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: anytype,
) !void {
    const geometry = prepared.logical.geometry;
    const session = transaction.proofSession();

    try transcript.drawSecure(
        Ops.Transcript,
        session,
        .constraint_evaluation,
        prepared.transcript,
        views.base.transcript,
        4,
        .draw_lookup_elements,
        2,
        64,
        views.relation.buffers.drawn_z_alpha,
    );
    const policy_plan = try relation_mod.Plan.init(
        geometry.statement.log_n_rows,
    );
    const instances = views.relation.bindings();
    const relation_plan = try relation_stage.prepare(
        transaction.allocator,
        .{
            .topology = policy_plan.topology(),
            .buffers = views.relation.buffers,
            .instances = &instances,
        },
    );
    defer relation_stage.deinit(transaction.allocator, relation_plan);
    try Ops.Relation.execute(session, relation_plan);
    try proof_assembly.captureStatement(
        session,
        &views.base,
        try views.relation.claimed_sums.cast(u32),
    );
    try transcript.mixWords(
        Ops.Transcript,
        session,
        .constraint_evaluation,
        prepared.transcript,
        views.base.transcript,
        5,
        .mix_statement,
        try views.relation.claimed_sums.cast(u32),
        false,
    );

    try commitInteraction(
        Ops,
        session,
        prepared,
        views,
    );
    try evaluateAndCommitComposition(
        Ops,
        transaction,
        prepared,
        views,
    );
}

fn commitInteraction(
    comptime Ops: type,
    session: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: anytype,
) !void {
    const geometry = prepared.logical.geometry;
    const interaction = try views.base.trees.require(.interaction);
    try inverseMixed(
        Ops.Transform,
        session,
        .constraint_evaluation,
        interaction.coefficients,
        geometry.statement.log_n_rows,
        4,
        4,
        views.base.twiddles_inverse,
    );
    try Ops.Transform.extend(
        session,
        .constraint_evaluation,
        interaction.coefficients,
        interaction.column_log_sizes,
        interaction.evaluations,
        geometry.commitment_log_rows,
        views.base.twiddles_forward,
        false,
    );
    const root = try commitTree(
        Ops.Commitment,
        session,
        prepared,
        .interaction,
        interaction,
    );
    try proof_assembly.captureTraceRoot(
        session,
        &views.base,
        2,
        root,
    );
    try transcript.mixWords(
        Ops.Transcript,
        session,
        .constraint_evaluation,
        prepared.transcript,
        views.base.transcript,
        6,
        .mix_interaction_root,
        try root.cast(u32),
        false,
    );
}

fn evaluateAndCommitComposition(
    comptime Ops: type,
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: anytype,
) !void {
    const geometry = prepared.logical.geometry;
    const session = transaction.proofSession();
    const composition = try views.base.trees.require(.composition);
    const challenge_words =
        views.base.constraint_buffers.challenge_parameters;
    const challenge = try challenge_words.cast(field.SecureField);

    try transcript.drawSecure(
        Ops.Transcript,
        session,
        .constraint_evaluation,
        prepared.transcript,
        views.base.transcript,
        7,
        .draw_composition_alpha,
        1,
        64,
        challenge,
    );
    try Ops.Power.expand(
        session,
        challenge,
        views.constraint_buffers.random_coefficient_powers,
    );
    try transaction.zeroResidentSlice(
        u32,
        .constraint_evaluation,
        slots.composition_coordinates,
        0,
        views.constraint_buffers.composition_coordinates.storage.len,
    );
    try Ops.Constraint.evaluate(
        session,
        views.constraint_buffers,
        geometry,
    );
    try Ops.Split.interpolateAndSplit(
        session,
        views.constraint_buffers.composition_coordinates,
        composition.coefficients,
        geometry.commitment_log_rows,
        views.base.twiddles_inverse,
    );
    try Ops.Transform.extend(
        session,
        .constraint_evaluation,
        composition.coefficients,
        composition.column_log_sizes,
        composition.evaluations,
        geometry.commitment_log_rows,
        views.base.twiddles_forward,
        false,
    );
    const root = try commitTree(
        Ops.Commitment,
        session,
        prepared,
        .composition,
        composition,
    );
    try proof_assembly.captureTraceRoot(
        session,
        &views.base,
        3,
        root,
    );
    try transcript.mixWords(
        Ops.Transcript,
        session,
        .constraint_evaluation,
        prepared.transcript,
        views.base.transcript,
        8,
        .mix_composition_root,
        try root.cast(u32),
        false,
    );
}

fn inverseMixed(
    comptime Transform: type,
    session: anytype,
    stage: @import(
        "../../../../backends/cuda/runtime/telemetry.zig",
    ).Stage,
    matrix: @import(
        "../../../../backends/cuda/runtime/stages/common.zig",
    ).WordMatrix,
    max_log_rows: u32,
    full_columns: usize,
    half_columns: usize,
    inverse_twiddles: @import(
        "../../../../backends/cuda/runtime/stages/common.zig",
    ).Words,
) !void {
    const full = try matrixColumns(matrix, 0, full_columns);
    const half = try matrixColumns(
        matrix,
        full_columns,
        half_columns,
    );
    try Transform.inverseCompact(
        session,
        stage,
        full,
        full,
        max_log_rows,
        inverse_twiddles,
    );
    try Transform.inverseCompact(
        session,
        stage,
        half,
        half,
        max_log_rows - 1,
        inverse_twiddles,
    );
}

fn matrixColumns(
    matrix: @import(
        "../../../../backends/cuda/runtime/stages/common.zig",
    ).WordMatrix,
    first: usize,
    count: usize,
) !@TypeOf(matrix) {
    return .{
        .storage = try matrix.storage.sub(
            first * matrix.column_stride_words,
            count * matrix.column_stride_words,
        ),
        .column_stride_words = matrix.column_stride_words,
    };
}

fn commitTree(
    comptime Commitment: type,
    session: anytype,
    prepared: *const plan_mod.PreparedPlan,
    role: @import("../../common/uniform_layout.zig").TraceRole,
    tree: @import("../../common/resident_views.zig").TraceTree,
) !@TypeOf(tree.merkle_hashes) {
    const geometry = prepared.logical.geometry;
    const opening = try traceOpening(prepared, role);
    const layers = prepared.decommit.retained_layers[opening.retained_layer_offset..][0..opening.retained_layer_count];
    const Builder = commit_tree.BuilderFor(Commitment);
    return Builder.baseField(
        session,
        .constraint_evaluation,
        @intCast(geometry.commitment_rows),
        tree.evaluations,
        tree.merkle_hashes,
        layers,
    );
}

fn traceOpening(
    prepared: *const plan_mod.PreparedPlan,
    role: @import("../../common/uniform_layout.zig").TraceRole,
) !@TypeOf(prepared.decommit.trace_trees[0]) {
    for (prepared.decommit.trace_trees) |opening| {
        if (opening.role == role) return opening;
    }
    return error.InvalidKernelDescriptor;
}
