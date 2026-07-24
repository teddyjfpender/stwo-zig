//! Canonical host-to-resident initialization for Native Poseidon.

const field = @import(
    "../../../../backends/cuda/abi/field.zig",
);
const canonical = @import("../canonical_ingress.zig");
const plan_mod = @import("../plan.zig");
const proof_assembly = @import("../../common/proof_assembly.zig");
const slots = @import("../slots.zig");

pub fn run(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    pack: *const canonical.Pack,
    views: anytype,
) !void {
    try proof_assembly.validateLayout(prepared, views);
    try transaction.zeroResidentSlice(
        u32,
        .ingress,
        slots.proof_bundle,
        0,
        views.proof.bundle.len,
    );
    try transaction.uploadResidentSlice(
        u32,
        slots.proof_bundle,
        0,
        prepared.proof.static_header,
    );
    try transaction.upload(
        u32,
        slots.twiddles_forward,
        pack.forwardTwiddleWords(),
    );
    try transaction.upload(
        u32,
        slots.twiddles_inverse,
        pack.inverseTwiddleWords(),
    );
    try transaction.upload(
        u32,
        slots.transcript_static_inputs,
        &pack.transcript_static,
    );
    try transaction.upload(
        u32,
        slots.coefficient_log_sizes,
        pack.coefficient_log_sizes,
    );
    try uploadTraceLayers(transaction, prepared);
    try transaction.upload(
        u32,
        slots.constraint_denominator_inverses,
        &pack.circle.composition_denominator_inverses,
    );
    try transaction.upload(
        field.CirclePointBaseField,
        slots.oods_offset_points,
        pack.oods_offset_points,
    );
    try transaction.upload(
        u32,
        slots.oods_fold_counts,
        pack.oods_fold_counts,
    );
    try transaction.upload(
        u32,
        slots.oods_output_indices,
        pack.oods_output_indices,
    );
    try uploadQuotientTopology(transaction, prepared);
    try uploadFriLayers(transaction, prepared);
    try uploadDecommitTopology(transaction, prepared);
}

pub fn configSource(views: anytype) !@TypeOf(
    views.transcript.static_inputs,
) {
    return views.transcript.static_inputs.sub(
        0,
        canonical.transcript_config_words,
    );
}

pub fn emptyRootSource(views: anytype) !@TypeOf(
    views.transcript.static_inputs,
) {
    return views.transcript.static_inputs.sub(
        canonical.transcript_config_words,
        canonical.transcript_empty_root_words,
    );
}

pub fn statementSource(views: anytype) !@TypeOf(
    views.transcript.static_inputs,
) {
    return views.transcript.static_inputs.sub(
        canonical.transcript_config_words +
            canonical.transcript_empty_root_words,
        canonical.transcript_statement_words,
    );
}

fn uploadTraceLayers(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
) !void {
    const main = prepared.decommit.trace_trees[0];
    const composition = prepared.decommit.trace_trees[1];
    try transaction.upload(
        field.MerkleLayerDescriptor,
        slots.main_merkle_layers,
        retainedLayers(
            prepared,
            main.retained_layer_offset,
            main.retained_layer_count,
        ),
    );
    try transaction.upload(
        field.MerkleLayerDescriptor,
        slots.composition_merkle_layers,
        retainedLayers(
            prepared,
            composition.retained_layer_offset,
            composition.retained_layer_count,
        ),
    );
}

fn uploadQuotientTopology(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
) !void {
    const topology = prepared.quotient;
    try transaction.upload(
        @TypeOf(topology.prepared_terms[0]),
        slots.quotient_prepared_terms,
        topology.prepared_terms,
    );
    try transaction.upload(
        u32,
        slots.quotient_group_offsets,
        topology.group_offsets,
    );
    try transaction.upload(
        u32,
        slots.quotient_group_term_indices,
        topology.group_term_indices,
    );
    try transaction.upload(
        @TypeOf(topology.batch_terms[0]),
        slots.quotient_batch_terms,
        topology.batch_terms,
    );
    try transaction.upload(
        u32,
        slots.quotient_group_log_sizes,
        topology.group_log_sizes,
    );
    try transaction.upload(
        u32,
        slots.quotient_partial_log_sizes,
        topology.partial_log_sizes,
    );
}

fn uploadFriLayers(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
) !void {
    for (prepared.fri.layers, 0..) |layer, index| {
        const begin = layer.retained_layer_offset;
        const end = begin + layer.retained_layer_count;
        try transaction.upload(
            field.MerkleLayerDescriptor,
            slots.friMerkleLayers(index),
            prepared.fri.retained_layers[begin..end],
        );
    }
}

fn uploadDecommitTopology(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
) !void {
    const geometry = prepared.logical.geometry;
    const logs = prepared.decommit.column_log_sizes;
    if (logs.len != geometry.sampled_value_count)
        return error.InvalidKernelDescriptor;
    try transaction.upload(
        u32,
        slots.decommit_sparse_level_offsets,
        &.{0},
    );
    try transaction.upload(
        u32,
        slots.main_column_log_sizes,
        logs[0..geometry.main_columns],
    );
    try transaction.upload(
        u32,
        slots.composition_column_log_sizes,
        logs[geometry.main_columns..],
    );
}

fn retainedLayers(
    prepared: *const plan_mod.PreparedPlan,
    offset: usize,
    count: usize,
) []const field.MerkleLayerDescriptor {
    return prepared.decommit.retained_layers[offset..][0..count];
}
