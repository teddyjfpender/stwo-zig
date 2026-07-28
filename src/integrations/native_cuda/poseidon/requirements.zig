//! Exact word capacities and protocol lifetimes for the prepared proof arena.

const std = @import("std");
const arena = @import("stwo_cuda_backend").runtime.arena;
const oods_stage = @import("stwo_cuda_backend").runtime.stages.oods;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
const canonical_ingress = @import("canonical_ingress.zig");
const proof_bundle = @import("proof_bundle.zig");
const geometry_mod = @import("geometry.zig");
const relation_abi = @import("stwo_cuda_backend").abi.stages.relation;
const relation_mod = @import("relation.zig");
const slots = @import("slots.zig");
const topology = @import("topology.zig");

pub const max_total_words: usize = 6_000_000_000;

pub fn build(
    allocator: std.mem.Allocator,
    geometry: geometry_mod.Geometry,
    quotient: topology.Quotient,
    fri: topology.Fri,
    decommit: topology.Decommit,
    proof: proof_bundle.Bundle,
) ![]arena.Requirement {
    var output: std.ArrayList(arena.Requirement) = .empty;
    errdefer output.deinit(allocator);
    const rows = geometry.trace_rows;
    const commitment_rows = geometry.commitment_rows;
    const source_count = quotient.source_count;
    const sample_count = geometry.sampled_value_count;
    const commitment_log = geometry.queryLogSize();
    const relation_plan = try relation_mod.Plan.init(geometry.log_n_rows);
    const relation_scratch = try usizeCount(
        try relation_plan.topology().scratchWords(),
    );
    const terminal_words = try sum(
        geometry_mod.terminal_statement_words,
        proof.total_words,
    );

    try add(
        &output,
        allocator,
        slots.twiddles_forward,
        commitment_rows,
        .ingress,
        .decommit,
    );
    try add(
        &output,
        allocator,
        slots.twiddles_inverse,
        commitment_rows,
        .ingress,
        .fri_commit,
    );
    try add(&output, allocator, slots.transcript_state, 16, .ingress, .decommit);
    try add(
        &output,
        allocator,
        slots.transcript_input_snapshot,
        @max(try secureWords(sample_count), 16),
        .ingress,
        .pow,
    );
    try add(
        &output,
        allocator,
        slots.transcript_output_snapshot,
        @max(geometry.protocol.fri_config.n_queries, 8),
        .constraint_evaluation,
        .decommit,
    );
    try add(
        &output,
        allocator,
        slots.transcript_boundary_snapshot,
        16,
        .ingress,
        .decommit,
    );
    try add(
        &output,
        allocator,
        slots.transcript_static_inputs,
        canonical_ingress.transcript_static_words,
        .ingress,
        .constraint_evaluation,
    );

    try add(
        &output,
        allocator,
        slots.main_coefficients,
        try mul(geometry.main_columns, rows),
        .trace_generation,
        .oods,
    );
    try add(
        &output,
        allocator,
        slots.interaction_coefficients,
        try mul(geometry_mod.interaction_columns, rows),
        .constraint_evaluation,
        .oods,
    );
    try add(
        &output,
        allocator,
        slots.composition_coefficients,
        try mul(geometry_mod.composition_columns, rows),
        .constraint_evaluation,
        .oods,
    );
    try add(
        &output,
        allocator,
        slots.source_evaluations,
        try mul(geometry_mod.source_columns, commitment_rows),
        .trace_commit,
        .decommit,
    );
    try add(
        &output,
        allocator,
        slots.constraint_source_evaluations,
        try mul(
            geometry.main_columns + geometry_mod.interaction_columns,
            geometry.composition_rows,
        ),
        .trace_commit,
        .constraint_evaluation,
    );
    try add(
        &output,
        allocator,
        slots.coefficient_log_sizes,
        source_count,
        .ingress,
        .constraint_evaluation,
    );
    const trace_hashes = try fullTreeHashes(commitment_rows);
    inline for (.{
        .{ slots.main_merkle_hashes, telemetry.Stage.trace_commit },
        .{
            slots.interaction_merkle_hashes,
            telemetry.Stage.constraint_evaluation,
        },
        .{
            slots.composition_merkle_hashes,
            telemetry.Stage.constraint_evaluation,
        },
    }) |entry| {
        try addAligned(
            &output,
            allocator,
            entry[0],
            try hashWords(trace_hashes),
            8,
            entry[1],
            .decommit,
        );
    }
    const trace_layers = @as(usize, commitment_log) + 1;
    try addAligned(&output, allocator, slots.main_merkle_layers, try descriptorWords(trace_layers), 2, .ingress, .decommit);
    try addAligned(&output, allocator, slots.interaction_merkle_layers, try descriptorWords(trace_layers), 2, .ingress, .decommit);
    try addAligned(&output, allocator, slots.composition_merkle_layers, try descriptorWords(trace_layers), 2, .ingress, .decommit);

    try add(
        &output,
        allocator,
        slots.composition_powers,
        try secureWords(
            @import("stwo_native_examples").backend_support.poseidon.component.N_CONSTRAINTS,
        ),
        .constraint_evaluation,
        .constraint_evaluation,
    );
    try add(&output, allocator, slots.constraint_denominator_inverses, 4, .ingress, .constraint_evaluation);
    try add(
        &output,
        allocator,
        slots.composition_coordinates,
        try mul(
            geometry_mod.composition_coordinates,
            geometry.composition_rows,
        ),
        .constraint_evaluation,
        .constraint_evaluation,
    );
    try add(&output, allocator, slots.composition_challenge, 4, .constraint_evaluation, .constraint_evaluation);
    try add(&output, allocator, slots.lookup_elements, try secureWords(2), .constraint_evaluation, .constraint_evaluation);
    try add(&output, allocator, slots.relation_alpha_powers, try secureWords(relation_mod.max_alpha_powers), .constraint_evaluation, .constraint_evaluation);
    try add(&output, allocator, slots.relation_z, try secureWords(1), .constraint_evaluation, .constraint_evaluation);
    // These values are copied while the witness is still in evaluation form.
    // The main slab is then free to undergo its destructive circle IFFT.
    try add(
        &output,
        allocator,
        slots.relation_source_values,
        try mul(relation_mod.source_pointer_count, rows),
        .trace_generation,
        .constraint_evaluation,
    );
    inline for (.{
        slots.relation_source_tables,
        slots.relation_descriptor_tables,
        slots.relation_output_tables,
        slots.relation_denominator_tables,
        slots.relation_claimed_sum_tables,
    }) |id| {
        try addAligned(
            &output,
            allocator,
            id,
            2,
            2,
            .ingress,
            .constraint_evaluation,
        );
    }
    try addAligned(
        &output,
        allocator,
        slots.relation_geometry,
        @sizeOf(relation_abi.Geometry) / @sizeOf(u32),
        @alignOf(relation_abi.Geometry) / @alignOf(u32),
        .ingress,
        .constraint_evaluation,
    );
    try addAligned(
        &output,
        allocator,
        slots.relation_source_pointer_table,
        try mul(relation_mod.source_pointer_count, 2),
        2,
        .ingress,
        .constraint_evaluation,
    );
    try addAligned(
        &output,
        allocator,
        slots.relation_descriptors,
        try mul(
            relation_mod.interaction_column_count,
            relation_abi.descriptor_words,
        ),
        @alignOf(relation_abi.ColumnDescriptor) / @alignOf(u32),
        .ingress,
        .constraint_evaluation,
    );
    try addAligned(
        &output,
        allocator,
        slots.relation_output_pointer_table,
        try mul(relation_mod.output_coordinate_count, 2),
        2,
        .ingress,
        .constraint_evaluation,
    );
    try add(
        &output,
        allocator,
        slots.relation_denominator_slab,
        try secureWords(try mul(
            relation_mod.interaction_column_count,
            rows,
        )),
        .constraint_evaluation,
        .constraint_evaluation,
    );
    try add(
        &output,
        allocator,
        slots.relation_claimed_sum,
        try secureWords(1),
        .constraint_evaluation,
        .proof_assembly,
    );
    try add(
        &output,
        allocator,
        slots.relation_reduction_partials,
        relation_scratch,
        .constraint_evaluation,
        .constraint_evaluation,
    );
    try add(
        &output,
        allocator,
        slots.relation_scan_block_sums,
        relation_scratch,
        .constraint_evaluation,
        .constraint_evaluation,
    );

    try add(&output, allocator, slots.oods_parameter, 4, .oods, .quotient);
    try add(&output, allocator, slots.oods_offset_points, try mul(sample_count, 2), .ingress, .oods);
    try add(&output, allocator, slots.oods_fold_counts, sample_count, .ingress, .oods);
    try add(&output, allocator, slots.oods_output_indices, sample_count, .ingress, .oods);
    try add(&output, allocator, slots.oods_sample_points, try secureCircleWords(sample_count), .oods, .quotient);
    try add(&output, allocator, slots.oods_evaluation_points, try secureCircleWords(sample_count), .oods, .oods);
    try add(
        &output,
        allocator,
        slots.oods_folding_factors,
        try secureWords(try mul(sample_count, geometry.log_n_rows)),
        .oods,
        .oods,
    );
    const oods_blocks = try ceilDiv(
        rows,
        oods_stage.first_coefficients_per_block,
    );
    const oods_scratch = try secureWords(try mul(sample_count, oods_blocks));
    try add(&output, allocator, slots.oods_reduce_a, oods_scratch, .oods, .oods);
    try add(&output, allocator, slots.oods_reduce_b, oods_scratch, .oods, .oods);
    try add(&output, allocator, slots.sampled_values, try secureWords(sample_count), .oods, .proof_assembly);

    try add(&output, allocator, slots.quotient_challenge, 4, .oods, .quotient);
    try add(&output, allocator, slots.quotient_prepared_terms, try mul(quotient.prepared_terms.len, 5), .ingress, .quotient);
    try add(&output, allocator, slots.quotient_group_offsets, quotient.group_offsets.len, .ingress, .quotient);
    try add(&output, allocator, slots.quotient_group_term_indices, quotient.group_term_indices.len, .ingress, .quotient);
    try add(&output, allocator, slots.quotient_batch_terms, try mul(quotient.batch_terms.len, 3), .ingress, .quotient);
    try add(&output, allocator, slots.quotient_group_log_sizes, quotient.group_log_sizes.len, .ingress, .quotient);
    try add(&output, allocator, slots.quotient_partial_log_sizes, quotient.partial_log_sizes.len, .ingress, .quotient);
    try add(&output, allocator, slots.quotient_term_points, try secureCircleWords(sample_count), .quotient, .quotient);
    try add(&output, allocator, slots.quotient_line_coefficients, try secureWords(try mul(sample_count, 3)), .quotient, .quotient);
    try add(&output, allocator, slots.quotient_group_points, 8, .quotient, .quotient);
    try add(&output, allocator, slots.quotient_first_linear_terms, 4, .quotient, .quotient);
    try add(&output, allocator, slots.quotient_partial_coordinates, try mul(commitment_rows, 4), .quotient, .quotient);

    try add(&output, allocator, slots.fri_alpha, 4, .fri_commit, .fri_commit);
    try add(&output, allocator, slots.fri_last_evaluation, try secureWords(geometry.last_layer_domain_rows), .fri_commit, .fri_commit);
    try add(&output, allocator, slots.fri_last_coefficients, try secureWords(geometry.last_layer_domain_rows), .fri_commit, .proof_assembly);
    try add(&output, allocator, slots.fri_last_degree_error, 1, .fri_commit, .proof_assembly);
    try add(&output, allocator, slots.fri_last_transcript, try secureWords(1), .fri_commit, .proof_assembly);
    for (fri.layers, 0..) |layer, index| {
        try add(
            &output,
            allocator,
            slots.friCoordinates(index),
            layer.coordinate_words,
            if (index == 0) .quotient else .fri_commit,
            .decommit,
        );
        try addAligned(
            &output,
            allocator,
            slots.friMerkleHashes(index),
            try hashWords(layer.merkle_hashes),
            8,
            .fri_commit,
            .decommit,
        );
        try addAligned(
            &output,
            allocator,
            slots.friMerkleLayers(index),
            try descriptorWords(layer.retained_layer_count),
            2,
            .ingress,
            .decommit,
        );
    }

    try add(&output, allocator, slots.pow_prefix_digest, 8, .pow, .pow);
    try addAligned(&output, allocator, slots.pow_best_nonce, 2, 2, .pow, .pow);
    try add(&output, allocator, slots.pow_completed_blocks, 1, .pow, .pow);
    try add(&output, allocator, slots.pow_transcript_nonce, 2, .pow, .proof_assembly);

    try add(
        &output,
        allocator,
        slots.raw_queries,
        geometry.protocol.fri_config.n_queries,
        .decommit,
        .decommit,
    );
    try add(&output, allocator, slots.unique_queries, decommit.unique_query_words, .decommit, .decommit);
    try add(&output, allocator, slots.decommit_mapped_queries, decommit.mapped_query_words, .decommit, .decommit);
    try add(&output, allocator, slots.decommit_walk_queries, decommit.walk_query_words, .decommit, .decommit);
    try add(&output, allocator, slots.decommit_walk_scratch, decommit.walk_query_words, .decommit, .decommit);
    try add(&output, allocator, slots.decommit_leaf_indices, decommit.leaf_index_words, .decommit, .decommit);
    try add(&output, allocator, slots.decommit_expanded_positions, decommit.expanded_position_words, .decommit, .decommit);
    try add(&output, allocator, slots.decommit_sparse_indices, decommit.sparse_index_words, .decommit, .decommit);
    try addAligned(&output, allocator, slots.decommit_sparse_hashes, decommit.sparse_hash_words, 8, .decommit, .decommit);
    try add(&output, allocator, slots.decommit_counts, decommit.count_words, .decommit, .decommit);
    try add(&output, allocator, slots.decommit_sparse_level_offsets, 1, .ingress, .decommit);
    try add(&output, allocator, slots.decommit_sparse_level_counts, 1, .decommit, .decommit);
    try add(&output, allocator, slots.main_column_log_sizes, geometry.main_columns, .ingress, .decommit);
    try add(&output, allocator, slots.interaction_column_log_sizes, geometry_mod.interaction_columns, .ingress, .decommit);
    try add(&output, allocator, slots.composition_column_log_sizes, geometry_mod.composition_columns, .ingress, .decommit);
    // The header is uploaded at ingress. Every dynamic section is then filled
    // in-place, and the transaction reads this exact whole-proof extent once.
    try add(
        &output,
        allocator,
        slots.proof_bundle,
        terminal_words,
        .ingress,
        .proof_assembly,
    );

    return output.toOwnedSlice(allocator);
}

fn add(
    output: *std.ArrayList(arena.Requirement),
    allocator: std.mem.Allocator,
    id: arena.SlotId,
    words: usize,
    live_from: telemetry.Stage,
    live_through: telemetry.Stage,
) std.mem.Allocator.Error!void {
    try addAligned(output, allocator, id, words, 1, live_from, live_through);
}

fn addAligned(
    output: *std.ArrayList(arena.Requirement),
    allocator: std.mem.Allocator,
    id: arena.SlotId,
    words: usize,
    alignment_words: usize,
    live_from: telemetry.Stage,
    live_through: telemetry.Stage,
) std.mem.Allocator.Error!void {
    try output.append(allocator, .{
        .id = id,
        .words = words,
        .alignment_words = alignment_words,
        .live_from = live_from,
        .live_through = live_through,
    });
}

fn secureWords(count: usize) geometry_mod.Error!usize {
    return mul(count, 4);
}

fn secureCircleWords(count: usize) geometry_mod.Error!usize {
    return mul(count, 8);
}

fn hashWords(count: usize) geometry_mod.Error!usize {
    return mul(count, 8);
}

fn descriptorWords(count: usize) geometry_mod.Error!usize {
    return mul(count, 4);
}

fn usizeCount(value: anytype) geometry_mod.Error!usize {
    return std.math.cast(usize, value) orelse error.GeometryOverflow;
}

fn fullTreeHashes(leaves: usize) geometry_mod.Error!usize {
    return std.math.sub(usize, try mul(leaves, 2), 1) catch
        return error.GeometryOverflow;
}

fn ceilDiv(value: usize, divisor: usize) geometry_mod.Error!usize {
    return std.math.divCeil(usize, value, divisor) catch error.GeometryOverflow;
}

fn mul(left: anytype, right: anytype) geometry_mod.Error!usize {
    const lhs = std.math.cast(usize, left) orelse return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.GeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.GeometryOverflow;
}

fn sum(left: usize, right: usize) geometry_mod.Error!usize {
    return std.math.add(usize, left, right) catch error.GeometryOverflow;
}
