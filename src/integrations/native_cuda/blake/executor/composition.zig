//! Resident Blake constant-QM31 evaluation and composition commitment.

const commit_tree = @import("../../common/commit_tree.zig");
const constraint = @import("../constraint.zig");
const ingress = @import("ingress.zig");
const plan_mod = @import("../plan.zig");
const proof_assembly = @import("../../common/proof_assembly.zig");
const slots = @import("../slots.zig");
const stages = @import("stwo_cuda_backend").runtime.stages;
const transcript = @import("../../common/transcript_executor.zig");

const NativeOps = struct {
    const Split = stages.composition_split.Native;
    const Transform = stages.transform.Native;
    const Commitment = stages.commitment.Native;
    const Transcript = stages.transcript.Native;
};

pub fn run(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: anytype,
) !void {
    const geometry = prepared.logical.geometry;
    const session = transaction.proofSession();
    const composition = try views.trace.trees.require(.composition);

    try transcript.drawSecure(
        NativeOps.Transcript,
        session,
        .constraint_evaluation,
        prepared.transcript,
        views.transcript,
        4,
        .draw_composition_alpha,
        1,
        64,
        views.constraint.composition_challenge,
    );
    try transaction.zeroResidentSlice(
        u32,
        .constraint_evaluation,
        slots.composition_coordinates,
        0,
        views.constraint.composition_coordinates.storage.len,
    );
    try constraint.evaluate(
        session,
        .{
            .statement_parameters = try ingress.statementSource(views),
            .challenge_parameters = try views.constraint.composition_challenge.cast(u32),
            .composition_coordinates = views.constraint.composition_coordinates,
        },
        geometry,
    );
    try NativeOps.Split.interpolateAndSplit(
        session,
        views.constraint.composition_coordinates,
        composition.coefficients,
        geometry.commitment_log_rows,
        views.trace.twiddles_inverse,
    );
    try NativeOps.Transform.extend(
        session,
        .constraint_evaluation,
        composition.coefficients,
        composition.column_log_sizes,
        composition.evaluations,
        geometry.commitment_log_rows,
        views.trace.twiddles_forward,
        false,
    );

    const opening = try traceOpening(prepared, .composition);
    const Builder = commit_tree.BuilderFor(NativeOps.Commitment);
    const root = try Builder.baseField(
        session,
        .constraint_evaluation,
        @intCast(geometry.commitment_rows),
        composition.evaluations,
        composition.merkle_hashes,
        prepared.decommit.retained_layers[opening.retained_layer_offset..][0..opening.retained_layer_count],
    );
    try proof_assembly.captureTraceRoot(session, views, 2, root);
    try transcript.mixWords(
        NativeOps.Transcript,
        session,
        .constraint_evaluation,
        prepared.transcript,
        views.transcript,
        5,
        .mix_composition_root,
        try root.cast(u32),
        false,
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
