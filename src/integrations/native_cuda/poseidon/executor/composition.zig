//! Exact resident Poseidon LogUp interaction and split-depth-two composition.

const field = @import(
    "../../../../backends/cuda/abi/field.zig",
);
const common = @import(
    "../../../../backends/cuda/runtime/stages/common.zig",
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
const geometry_mod = @import("../geometry.zig");
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
        views.transcript,
        3,
        .draw_lookup_elements,
        2,
        64,
        views.relation.buffers.drawn_z_alpha,
    );
    const policy_plan = try relation_mod.Plan.init(
        geometry.log_n_rows,
    );
    const instance = views.relation.instance();
    const relation_plan = try relation_stage.prepare(
        transaction.allocator,
        .{
            .topology = policy_plan.topology(),
            .buffers = views.relation.buffers,
            .instances = &.{instance},
        },
    );
    defer relation_stage.deinit(
        transaction.allocator,
        relation_plan,
    );
    try Ops.Relation.execute(session, relation_plan);
    try proof_assembly.captureStatement(
        session,
        views,
        try views.relation.claimed_sum.cast(u32),
    );

    try commitInteraction(Ops, session, prepared, views);
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
    const interaction = try views.trace.trees.require(.interaction);
    try Ops.Transform.inverseToRetained(
        session,
        .constraint_evaluation,
        interaction.coefficients,
        interaction.coefficients,
        geometry.log_n_rows,
        views.trace.twiddles_inverse,
    );
    try Ops.Transform.extend(
        session,
        .constraint_evaluation,
        interaction.coefficients,
        interaction.column_log_sizes,
        interaction.evaluations,
        geometry.commitment_log_rows,
        views.trace.twiddles_forward,
        false,
    );
    const root = try commitTree(
        Ops.Commitment,
        session,
        prepared,
        .interaction,
        interaction,
    );
    try proof_assembly.captureTraceRoot(session, views, 2, root);
    try transcript.mixWords(
        Ops.Transcript,
        session,
        .constraint_evaluation,
        prepared.transcript,
        views.transcript,
        4,
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
    const composition = try views.trace.trees.require(.composition);

    try transcript.drawSecure(
        Ops.Transcript,
        session,
        .constraint_evaluation,
        prepared.transcript,
        views.transcript,
        5,
        .draw_composition_alpha,
        1,
        64,
        views.constraint.composition_challenge,
    );
    try Ops.Power.expand(
        session,
        views.constraint.composition_challenge,
        views.constraint.random_powers,
    );
    try extendConstraintSources(
        Ops.Transform,
        session,
        geometry,
        views,
    );
    try transaction.zeroResidentSlice(
        u32,
        .constraint_evaluation,
        slots.composition_coordinates,
        0,
        views.constraint.composition_coordinates.storage.len,
    );
    try Ops.Constraint.evaluate(
        session,
        views.constraint.buffers(),
        geometry,
    );

    try Ops.Split.interpolateAndSplit(
        session,
        views.constraint.composition_coordinates,
        views.trace.composition_split_coefficients,
        geometry.composition_log_rows,
        views.trace.twiddles_inverse,
    );
    try orderDepthTwoChunks(transaction, geometry);
    try Ops.Transform.extend(
        session,
        .constraint_evaluation,
        composition.coefficients,
        composition.column_log_sizes,
        composition.evaluations,
        geometry.commitment_log_rows,
        views.trace.twiddles_forward,
        false,
    );
    const root = try commitTree(
        Ops.Commitment,
        session,
        prepared,
        .composition,
        composition,
    );
    try proof_assembly.captureTraceRoot(session, views, 3, root);
    try transcript.mixWords(
        Ops.Transcript,
        session,
        .constraint_evaluation,
        prepared.transcript,
        views.transcript,
        6,
        .mix_composition_root,
        try root.cast(u32),
        false,
    );
}

fn extendConstraintSources(
    comptime Transform: type,
    session: anytype,
    geometry: geometry_mod.Geometry,
    views: anytype,
) !void {
    const main = try views.trace.trees.require(.main);
    const interaction = try views.trace.trees.require(.interaction);
    const main_count: usize = geometry.main_columns;
    const interaction_count: usize =
        geometry_mod.interaction_columns;
    const destination = views.constraint.source_evaluations;
    try Transform.extend(
        session,
        .constraint_evaluation,
        main.coefficients,
        try views.trace.coefficient_log_sizes.sub(0, main_count),
        try matrixColumns(destination, 0, main_count),
        geometry.composition_log_rows,
        views.trace.twiddles_forward,
        false,
    );
    try Transform.extend(
        session,
        .constraint_evaluation,
        interaction.coefficients,
        try views.trace.coefficient_log_sizes.sub(
            main_count,
            interaction_count,
        ),
        try matrixColumns(
            destination,
            main_count,
            interaction_count,
        ),
        geometry.composition_log_rows,
        views.trace.twiddles_forward,
        false,
    );
}

fn orderDepthTwoChunks(
    transaction: anytype,
    geometry: geometry_mod.Geometry,
) !void {
    const rows = try geometry.traceRowCount();
    const split_stride = rows * 2;
    for (0..2) |outer_chunk| {
        for (0..2) |inner_chunk| {
            for (0..4) |coordinate| {
                const source_column = outer_chunk * 4 + coordinate;
                const destination_column =
                    (outer_chunk * 2 + inner_chunk) * 4 +
                    coordinate;
                try transaction.copyResidentSlice(
                    u32,
                    slots.composition_coefficients,
                    destination_column * rows,
                    slots.composition_split_coefficients,
                    source_column * split_stride +
                        inner_chunk * rows,
                    rows,
                );
            }
        }
    }
}

fn matrixColumns(
    matrix: common.WordMatrix,
    first: usize,
    count: usize,
) !common.WordMatrix {
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

comptime {
    if (@sizeOf(field.SecureField) != 4 * @sizeOf(u32))
        @compileError("Poseidon executor assumes four-word QM31");
}
