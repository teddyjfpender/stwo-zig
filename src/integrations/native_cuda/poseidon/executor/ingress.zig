//! Canonical host-to-resident initialization for Native Poseidon.

const std = @import("std");
const field = @import(
    "../../../../backends/cuda/abi/field.zig",
);
const relation_abi = @import(
    "../../../../backends/cuda/abi/stages/relation.zig",
);
const canonical = @import("../canonical_ingress.zig");
const plan_mod = @import("../plan.zig");
const proof_assembly = @import("../../common/proof_assembly.zig");
const relation_mod = @import("../relation.zig");
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
    try uploadRelationGraph(transaction, prepared, views);
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
    const main = try traceOpening(prepared, .main);
    const interaction = try traceOpening(prepared, .interaction);
    const composition = try traceOpening(prepared, .composition);
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
        slots.interaction_merkle_layers,
        retainedLayers(
            prepared,
            interaction.retained_layer_offset,
            interaction.retained_layer_count,
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
    const interaction_first = geometry.main_columns;
    const composition_first =
        interaction_first + @import("../geometry.zig").interaction_columns;
    try transaction.upload(
        u32,
        slots.interaction_column_log_sizes,
        logs[interaction_first..composition_first],
    );
    try transaction.upload(
        u32,
        slots.composition_column_log_sizes,
        logs[composition_first..],
    );
}

fn uploadRelationGraph(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: anytype,
) !void {
    const relation = &views.relation;
    const plan = try relation_mod.Plan.init(
        prepared.logical.geometry.log_n_rows,
    );
    const source_table = try pointerTable(&relation.source_columns);
    const output_table = try pointerTable(
        &relation.output_coordinates,
    );

    try transaction.upload(
        u32,
        slots.relation_source_pointer_table,
        &source_table,
    );
    try transaction.upload(
        relation_abi.ColumnDescriptor,
        slots.relation_descriptors,
        &relation_mod.descriptors,
    );
    try transaction.upload(
        u32,
        slots.relation_output_pointer_table,
        &output_table,
    );
    try transaction.upload(
        relation_abi.Geometry,
        slots.relation_geometry,
        &plan.geometry,
    );
    try uploadSinglePointer(
        transaction,
        slots.relation_source_tables,
        relation.source_pointer_table.address,
    );
    try uploadSinglePointer(
        transaction,
        slots.relation_descriptor_tables,
        relation.descriptor_storage.address,
    );
    try uploadSinglePointer(
        transaction,
        slots.relation_output_tables,
        relation.output_pointer_table.address,
    );
    try uploadSinglePointer(
        transaction,
        slots.relation_denominator_tables,
        relation.denominator_slab.address,
    );
    try uploadSinglePointer(
        transaction,
        slots.relation_claimed_sum_tables,
        relation.claimed_sum.address,
    );
}

fn pointerTable(values: anytype) ![
    values.len * (@sizeOf(usize) / @sizeOf(u32))
]u32 {
    var result: [
        values.len * (@sizeOf(usize) / @sizeOf(u32))
    ]u32 = undefined;
    for (values, 0..) |value, index| {
        const encoded = try pointerWords(value.address);
        const first = index * encoded.len;
        result[first..][0..encoded.len].* = encoded;
    }
    return result;
}

fn uploadSinglePointer(
    transaction: anytype,
    id: slots.SlotId,
    address: usize,
) !void {
    const encoded = try pointerWords(address);
    try transaction.upload(u32, id, &encoded);
}

fn pointerWords(
    address: usize,
) ![@sizeOf(usize) / @sizeOf(u32)]u32 {
    comptime std.debug.assert(@sizeOf(usize) == @sizeOf(u64));
    var bytes: [@sizeOf(u64)]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(address), .little);
    var result: [2]u32 = undefined;
    inline for (0..2) |index| {
        const first = index * @sizeOf(u32);
        result[index] = std.mem.readInt(
            u32,
            bytes[first..][0..@sizeOf(u32)],
            .little,
        );
    }
    return result;
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
    offset: usize,
    count: usize,
) []const field.MerkleLayerDescriptor {
    return prepared.decommit.retained_layers[offset..][0..count];
}
