//! Exact word capacities and protocol lifetimes for the prepared proof arena.

const std = @import("std");
const arena = @import("../../../backends/cuda/runtime/arena.zig");
const telemetry = @import("../../../backends/cuda/runtime/telemetry.zig");
const proof_bundle = @import("proof_bundle.zig");
const request = @import("request.zig");
const slots = @import("slots.zig");
const topology = @import("topology.zig");

pub const max_total_words: usize = 6_000_000_000;

pub fn build(
    allocator: std.mem.Allocator,
    geometry: request.Geometry,
    quotient: topology.Quotient,
    fri: topology.Fri,
    decommit: topology.Decommit,
    proof: proof_bundle.Bundle,
) (std.mem.Allocator.Error || request.Error)![]arena.Requirement {
    var output: std.ArrayList(arena.Requirement) = .empty;
    errdefer output.deinit(allocator);
    const rows = geometry.trace_rows;
    const commitment_rows = geometry.commitment_rows;
    const source_count = quotient.source_count;
    const sample_count = geometry.sampled_value_count;
    const commitment_log = geometry.queryLogSize();

    try add(&output, allocator, slots.twiddles_forward, rows, .ingress, .decommit);
    try add(&output, allocator, slots.twiddles_inverse, rows, .ingress, .fri_commit);
    try add(
        &output,
        allocator,
        slots.circle_domain,
        commitment_rows,
        .ingress,
        .fri_commit,
    );
    try add(&output, allocator, slots.transcript_state, 16, .ingress, .decommit);
    try add(&output, allocator, slots.transcript_seed_snapshot, 9, .ingress, .trace_commit);
    try add(
        &output,
        allocator,
        slots.transcript_input_snapshot,
        @max(try secureWords(sample_count), 16),
        .trace_commit,
        .pow,
    );
    try add(
        &output,
        allocator,
        slots.transcript_output_snapshot,
        @max(geometry.protocol.n_queries, 8),
        .constraint_evaluation,
        .decommit,
    );
    try add(
        &output,
        allocator,
        slots.transcript_boundary_snapshot,
        16,
        .trace_commit,
        .decommit,
    );

    const main_retained_words = try mul(
        geometry.main_columns,
        try mul(rows, 2),
    );
    const composition_coefficient_words = try mul(
        request.composition_column_count,
        rows,
    );
    try add(
        &output,
        allocator,
        slots.coefficient_slab,
        try sum(main_retained_words, composition_coefficient_words),
        .trace_generation,
        .oods,
    );
    try add(
        &output,
        allocator,
        slots.committed_evaluation_slab,
        try mul(source_count, commitment_rows),
        .trace_commit,
        .decommit,
    );
    try add(
        &output,
        allocator,
        slots.coefficient_log_sizes,
        source_count,
        .ingress,
        .trace_commit,
    );
    try add(
        &output,
        allocator,
        slots.main_commit_states,
        try progressiveWords(commitment_rows),
        .trace_commit,
        .trace_commit,
    );
    try add(
        &output,
        allocator,
        slots.composition_commit_states,
        try progressiveWords(commitment_rows),
        .constraint_evaluation,
        .constraint_evaluation,
    );
    const trace_hashes = try fullTreeHashes(commitment_rows);
    try addAligned(
        &output,
        allocator,
        slots.main_merkle_hashes,
        try hashWords(trace_hashes),
        8,
        .trace_commit,
        .decommit,
    );
    try addAligned(
        &output,
        allocator,
        slots.composition_merkle_hashes,
        try hashWords(trace_hashes),
        8,
        .constraint_evaluation,
        .decommit,
    );
    const trace_layers = @as(usize, commitment_log) + 1;
    try addAligned(&output, allocator, slots.main_merkle_layers, try descriptorWords(trace_layers), 2, .ingress, .decommit);
    try addAligned(&output, allocator, slots.composition_merkle_layers, try descriptorWords(trace_layers), 2, .ingress, .decommit);

    try add(
        &output,
        allocator,
        slots.constraint_random_powers,
        try secureWords(geometry.main_columns - 2),
        .constraint_evaluation,
        .constraint_evaluation,
    );
    try add(&output, allocator, slots.constraint_denominator_inverses, 2, .ingress, .constraint_evaluation);
    try add(
        &output,
        allocator,
        slots.composition_coordinates,
        try mul(request.composition_coordinate_count, commitment_rows),
        .constraint_evaluation,
        .constraint_evaluation,
    );
    try add(&output, allocator, slots.composition_challenge, 4, .constraint_evaluation, .constraint_evaluation);

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
        try secureWords(try mul(sample_count, geometry.statement.log_n_rows)),
        .oods,
        .oods,
    );
    const oods_blocks = try ceilDiv(rows, 512);
    const oods_scratch = try secureWords(try mul(sample_count, oods_blocks));
    try add(&output, allocator, slots.oods_reduce_a, oods_scratch, .oods, .oods);
    try add(&output, allocator, slots.oods_reduce_b, oods_scratch, .oods, .oods);
    try add(&output, allocator, slots.sampled_values, try secureWords(sample_count), .oods, .proof_assembly);

    try add(&output, allocator, slots.quotient_challenge, 4, .quotient, .quotient);
    try add(&output, allocator, slots.quotient_prepared_terms, try mul(quotient.prepared_terms.len, 5), .ingress, .quotient);
    try add(&output, allocator, slots.quotient_group_offsets, quotient.group_offsets.len, .ingress, .quotient);
    try add(&output, allocator, slots.quotient_group_term_indices, quotient.group_term_indices.len, .ingress, .quotient);
    try add(&output, allocator, slots.quotient_batch_offsets, quotient.batch_offsets.len, .ingress, .quotient);
    try add(&output, allocator, slots.quotient_batch_terms, try mul(quotient.batch_terms.len, 3), .ingress, .quotient);
    try add(&output, allocator, slots.quotient_group_log_sizes, quotient.group_log_sizes.len, .ingress, .quotient);
    try add(&output, allocator, slots.quotient_partial_log_sizes, quotient.partial_log_sizes.len, .ingress, .quotient);
    try add(&output, allocator, slots.quotient_term_points, try secureCircleWords(sample_count), .quotient, .quotient);
    try add(&output, allocator, slots.quotient_line_coefficients, try secureWords(try mul(sample_count, 3)), .quotient, .quotient);
    try add(&output, allocator, slots.quotient_group_points, 8, .quotient, .quotient);
    try add(&output, allocator, slots.quotient_first_linear_terms, 4, .quotient, .quotient);
    try add(&output, allocator, slots.quotient_partial_coordinates, try mul(commitment_rows, 4), .quotient, .quotient);

    try add(&output, allocator, slots.fri_alpha, 4, .fri_commit, .fri_commit);
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

    try add(&output, allocator, slots.raw_queries, geometry.protocol.n_queries, .decommit, .decommit);
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
    try add(&output, allocator, slots.composition_column_log_sizes, request.composition_column_count, .ingress, .decommit);
    // The header is uploaded at ingress. Every dynamic section is then filled
    // in-place, and the transaction reads this exact whole-proof extent once.
    try add(
        &output,
        allocator,
        slots.proof_bundle,
        proof.total_words,
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

fn secureWords(count: usize) request.Error!usize {
    return mul(count, 4);
}

fn secureCircleWords(count: usize) request.Error!usize {
    return mul(count, 8);
}

fn progressiveWords(count: usize) request.Error!usize {
    return mul(count, 24);
}

fn hashWords(count: usize) request.Error!usize {
    return mul(count, 8);
}

fn descriptorWords(count: usize) request.Error!usize {
    return mul(count, 4);
}

fn fullTreeHashes(leaves: usize) request.Error!usize {
    return std.math.sub(usize, try mul(leaves, 2), 1) catch
        return error.GeometryOverflow;
}

fn ceilDiv(value: usize, divisor: usize) request.Error!usize {
    return std.math.divCeil(usize, value, divisor) catch error.GeometryOverflow;
}

fn mul(left: anytype, right: anytype) request.Error!usize {
    const lhs = std.math.cast(usize, left) orelse return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.GeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.GeometryOverflow;
}

fn sum(left: usize, right: usize) request.Error!usize {
    return std.math.add(usize, left, right) catch error.GeometryOverflow;
}
