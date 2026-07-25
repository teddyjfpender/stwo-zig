//! Resident Poseidon trace generation, commitment, and transcript prefix.

const commit_tree = @import("../../common/commit_tree.zig");
const ingress = @import("ingress.zig");
const plan_mod = @import("../plan.zig");
const proof_assembly = @import("../../common/proof_assembly.zig");
const poseidon_input = @import(
    "../../../../examples/poseidon/input.zig",
);
const slots = @import("../slots.zig");
const stages = @import(
    "../../../../backends/cuda/runtime/stages/mod.zig",
);
const trace = @import("../trace.zig");
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
    const main = try views.trace.trees.require(.main);
    try trace.generate(
        transaction.proofSession(),
        main.coefficients,
        prepared.logical.geometry.statement,
    );
    try snapshotRelationSources(
        transaction,
        prepared.logical.geometry,
    );
}

pub fn commit(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: anytype,
) !void {
    const geometry = prepared.logical.geometry;
    const session = transaction.proofSession();
    const main = try views.trace.trees.require(.main);

    try NativeOps.Transcript.initialize(
        session,
        .trace_commit,
        views.transcript.state,
        null,
        null,
        prepared.transcript.initialChain(),
    );
    try transcript.mixWords(
        NativeOps.Transcript,
        session,
        .trace_commit,
        prepared.transcript,
        views.transcript,
        0,
        .mix_pcs_config,
        try ingress.configSource(views),
        true,
    );
    const empty_root = try ingress.emptyRootSource(views);
    try transcript.mixWords(
        NativeOps.Transcript,
        session,
        .trace_commit,
        prepared.transcript,
        views.transcript,
        1,
        .mix_preprocessed_root,
        empty_root,
        false,
    );
    try proof_assembly.captureStaticTraceRoot(
        session,
        views,
        0,
        empty_root,
    );

    try NativeOps.Transform.inverseToRetained(
        session,
        .trace_commit,
        main.coefficients,
        main.coefficients,
        geometry.log_n_rows,
        views.trace.twiddles_inverse,
    );
    try NativeOps.Transform.extend(
        session,
        .trace_commit,
        main.coefficients,
        main.column_log_sizes,
        main.evaluations,
        geometry.commitment_log_rows,
        views.trace.twiddles_forward,
        false,
    );
    const opening = try traceOpening(prepared, .main);
    const Builder = commit_tree.BuilderFor(NativeOps.Commitment);
    const root = try Builder.baseField(
        session,
        .trace_commit,
        @intCast(geometry.commitment_rows),
        main.evaluations,
        main.merkle_hashes,
        retainedLayers(
            prepared,
            opening.retained_layer_offset,
            opening.retained_layer_count,
        ),
    );
    try proof_assembly.captureTraceRoot(session, views, 1, root);
    try transcript.mixWords(
        NativeOps.Transcript,
        session,
        .trace_commit,
        prepared.transcript,
        views.transcript,
        2,
        .mix_main_root,
        try root.cast(u32),
        false,
    );
    try transcript.mixWords(
        NativeOps.Transcript,
        session,
        .trace_commit,
        prepared.transcript,
        views.transcript,
        3,
        .mix_statement,
        try ingress.statementSource(views),
        false,
    );
}

fn snapshotRelationSources(
    transaction: anytype,
    geometry: @import("../geometry.zig").Geometry,
) !void {
    const rows = try geometry.traceRowCount();
    const retained_stride = geometry.commitment_rows;
    for (0..poseidon_input.N_INSTANCES_PER_ROW) |rep| {
        const trace_base = rep * poseidon_input.N_COLUMNS_PER_REP;
        const final_base =
            trace_base + poseidon_input.N_COLUMNS_PER_REP -
            poseidon_input.N_STATE;
        const relation_base = rep * poseidon_input.N_STATE * 2;
        for (0..poseidon_input.N_STATE) |lane| {
            try transaction.copyResidentSlice(
                u32,
                slots.relation_source_values,
                (relation_base + lane) * rows,
                slots.main_coefficients,
                (trace_base + lane) * retained_stride,
                rows,
            );
            try transaction.copyResidentSlice(
                u32,
                slots.relation_source_values,
                (relation_base + poseidon_input.N_STATE + lane) *
                    rows,
                slots.main_coefficients,
                (final_base + lane) * retained_stride,
                rows,
            );
        }
    }
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
