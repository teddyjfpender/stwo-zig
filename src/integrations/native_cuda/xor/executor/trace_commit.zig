//! Resident XOR trace generation, commitment, and transcript prefix.

const commit_tree = @import("../../common/commit_tree.zig");
const device_trace = @import("../device_trace.zig");
const plan_mod = @import("../plan.zig");
const proof_assembly = @import("../../common/proof_assembly.zig");
const stages = @import(
    "../../../../backends/cuda/runtime/stages/mod.zig",
);
const transcript = @import("../../common/transcript_executor.zig");

const NativeOps = struct {
    const Transform = stages.transform.Native;
    const Commitment = stages.commitment.Native;
    const Transcript = stages.transcript.Native;
};

pub fn generate(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: anytype,
) !void {
    const preprocessed = try views.trees.require(.preprocessed);
    const main = try views.trees.require(.main);
    try device_trace.generate(
        transaction.proofSession(),
        .{
            .preprocessed = preprocessed.coefficients,
            .main = main.coefficients,
        },
        prepared.logical.geometry,
    );
}

pub fn commit(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: anytype,
) !void {
    return commitWith(NativeOps, transaction, prepared, views);
}

fn commitWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: anytype,
) !void {
    const session = transaction.proofSession();
    try Ops.Transcript.initialize(
        session,
        .trace_commit,
        views.transcript.state,
        null,
        null,
        prepared.transcript.initialChain(),
    );
    try transcript.mixWords(
        Ops.Transcript,
        session,
        .trace_commit,
        prepared.transcript,
        views.transcript,
        0,
        .mix_pcs_config,
        views.protocol_words,
        true,
    );
    try commitRole(
        Ops,
        session,
        prepared,
        views,
        .preprocessed,
        0,
        1,
        .mix_preprocessed_root,
    );
    try commitRole(
        Ops,
        session,
        prepared,
        views,
        .main,
        1,
        2,
        .mix_main_root,
    );
    try transcript.mixWords(
        Ops.Transcript,
        session,
        .trace_commit,
        prepared.transcript,
        views.transcript,
        3,
        .mix_statement,
        views.statement_words,
        false,
    );
}

fn commitRole(
    comptime Ops: type,
    session: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: anytype,
    role: @import("../../common/uniform_layout.zig").TraceRole,
    commitment_index: usize,
    transcript_step: u32,
    operation: @import(
        "../../common/transcript_schedule.zig",
    ).Operation,
) !void {
    const geometry = prepared.logical.geometry;
    const tree = try views.trees.require(role);
    try Ops.Transform.inverseToRetained(
        session,
        .trace_commit,
        tree.coefficients,
        tree.coefficients,
        geometry.statement.log_size,
        views.twiddles_inverse,
    );
    try Ops.Transform.extend(
        session,
        .trace_commit,
        tree.coefficients,
        tree.column_log_sizes,
        tree.evaluations,
        geometry.commitment_log_rows,
        views.twiddles_forward,
        false,
    );
    const opening = try traceOpening(prepared, role);
    const layers = retainedLayers(
        prepared,
        opening.retained_layer_offset,
        opening.retained_layer_count,
    );
    const Builder = commit_tree.BuilderFor(Ops.Commitment);
    const root = try Builder.baseField(
        session,
        .trace_commit,
        @intCast(geometry.commitment_rows),
        tree.evaluations,
        tree.merkle_hashes,
        layers,
    );
    try proof_assembly.captureTraceRoot(
        session,
        views,
        commitment_index,
        root,
    );
    try transcript.mixWords(
        Ops.Transcript,
        session,
        .trace_commit,
        prepared.transcript,
        views.transcript,
        transcript_step,
        operation,
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

fn retainedLayers(
    prepared: *const plan_mod.PreparedPlan,
    first: usize,
    count: usize,
) []const @import(
    "../../../../backends/cuda/abi/field.zig",
).MerkleLayerDescriptor {
    return prepared.decommit.retained_layers[first..][0..count];
}
