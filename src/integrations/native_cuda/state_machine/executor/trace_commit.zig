//! Exact State v2 trace prefix with an empty preprocessed commitment.

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
    try device_trace.generate(
        transaction.proofSession(),
        .{
            .main = (try views.base.trees.require(.main)).coefficients,
            .relation_sources = views.relation.source_values,
        },
        prepared.logical.geometry,
    );
}

pub fn commit(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: anytype,
) !void {
    try commitWith(NativeOps, transaction, prepared, views);
}

pub fn commitWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: anytype,
) !void {
    const geometry = prepared.logical.geometry;
    const session = transaction.proofSession();
    const main = try views.base.trees.require(.main);

    try Ops.Transcript.initialize(
        session,
        .trace_commit,
        views.base.transcript.state,
        null,
        null,
        prepared.transcript.initialChain(),
    );
    try transcript.mixWords(
        Ops.Transcript,
        session,
        .trace_commit,
        prepared.transcript,
        views.base.transcript,
        0,
        .mix_pcs_config,
        views.base.protocol_words,
        true,
    );
    try transcript.mixWords(
        Ops.Transcript,
        session,
        .trace_commit,
        prepared.transcript,
        views.base.transcript,
        1,
        .mix_preprocessed_root,
        views.empty_preprocessed_root,
        false,
    );
    try proof_assembly.captureStaticTraceRoot(
        session,
        &views.base,
        0,
        views.empty_preprocessed_root,
    );
    try transcript.mixWordsPair(
        Ops.Transcript,
        session,
        .trace_commit,
        prepared.transcript,
        views.base.transcript,
        2,
        .mix_statement,
        try views.transcript_statement_words.sub(0, 2),
        try views.transcript_statement_words.sub(2, 2),
        false,
    );

    try inverseMixed(
        Ops.Transform,
        session,
        main.coefficients,
        geometry.statement.log_n_rows,
        views.base.twiddles_inverse,
    );
    try Ops.Transform.extend(
        session,
        .trace_commit,
        main.coefficients,
        main.column_log_sizes,
        main.evaluations,
        geometry.commitment_log_rows,
        views.base.twiddles_forward,
        false,
    );
    const opening = try traceOpening(prepared, .main);
    const Builder = commit_tree.BuilderFor(Ops.Commitment);
    const root = try Builder.baseField(
        session,
        .trace_commit,
        @intCast(geometry.commitment_rows),
        main.evaluations,
        main.merkle_hashes,
        prepared.decommit.retained_layers[opening.retained_layer_offset..][0..opening.retained_layer_count],
    );
    try proof_assembly.captureTraceRoot(
        session,
        &views.base,
        1,
        root,
    );
    try transcript.mixWords(
        Ops.Transcript,
        session,
        .trace_commit,
        prepared.transcript,
        views.base.transcript,
        3,
        .mix_main_root,
        try root.cast(u32),
        false,
    );
}

fn inverseMixed(
    comptime Transform: type,
    session: anytype,
    matrix: @import(
        "../../../../backends/cuda/runtime/stages/common.zig",
    ).WordMatrix,
    max_log_rows: u32,
    inverse_twiddles: @import(
        "../../../../backends/cuda/runtime/stages/common.zig",
    ).Words,
) !void {
    const full = try matrixColumns(matrix, 0, 2);
    const half = try matrixColumns(matrix, 2, 2);
    try Transform.inverseToRetained(
        session,
        .trace_commit,
        full,
        full,
        max_log_rows,
        inverse_twiddles,
    );
    try Transform.inverseToRetained(
        session,
        .trace_commit,
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

fn traceOpening(
    prepared: *const plan_mod.PreparedPlan,
    role: @import("../../common/uniform_layout.zig").TraceRole,
) !@TypeOf(prepared.decommit.trace_trees[0]) {
    for (prepared.decommit.trace_trees) |opening| {
        if (opening.role == role) return opening;
    }
    return error.InvalidKernelDescriptor;
}
