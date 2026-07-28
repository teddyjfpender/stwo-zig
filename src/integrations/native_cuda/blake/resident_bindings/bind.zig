//! Geometry-checked conversion from arena slots to stage-native descriptors.

const std = @import("std");
const field = @import("stwo_cuda_backend").abi.field;
const quotient_abi = @import("stwo_cuda_backend").abi.stages.quotient;
const column = @import("stwo_cuda_backend").runtime.column;
const runtime_error = @import("stwo_cuda_backend").runtime.runtime_error;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const oods_stage = @import("stwo_cuda_backend").runtime.stages.oods;
const quotient_stage = @import("stwo_cuda_backend").runtime.stages.quotient;
const canonical_ingress = @import("../canonical_ingress.zig");
const proof_binding = @import("../../common/resident_proof_binding.zig");
const plan_mod = @import("../plan.zig");
const proof_bundle = @import("../proof_bundle.zig");
const geometry_mod = @import("../geometry.zig");
const slots = @import("../slots.zig");
const types = @import("types.zig");

const Words = column.DeviceSlice(u32);

/// Binds every sealed slot without allocating, uploading, dispatching, or
/// synchronizing. `provider` only needs an exact `slot(SlotId)` method.
pub fn bind(
    provider: anytype,
    prepared: *const plan_mod.PreparedPlan,
) runtime_error.Error!types.Views {
    try validatePrepared(prepared);
    const geometry = prepared.logical.geometry;
    var trace = try bindTrace(provider, geometry);
    const transcript = try bindTranscript(provider, geometry);
    const constraint = try bindConstraint(provider, geometry);
    const oods = try bindOods(provider, geometry);
    const fri = try bindFri(provider, prepared);
    const quotient = try bindQuotient(
        provider,
        prepared,
        trace.all_evaluations,
        fri.layers[0].coordinates,
    );
    const pow = try bindPow(provider);
    const decommit = try bindDecommit(provider, prepared);
    trace.trees = try bindTraceTrees(trace, decommit);
    const proof = try bindProof(provider, prepared);
    try requireDisjoint(
        fri.last_evaluation,
        fri.last_coefficients,
    );
    return .{
        .trace = trace,
        .transcript = transcript,
        .constraint = constraint,
        .oods = oods,
        .quotient = quotient,
        .fri = fri,
        .pow = pow,
        .decommit = decommit,
        .proof = proof,
    };
}

fn bindTrace(provider: anytype, geometry: geometry_mod.Geometry) !types.Trace {
    const rows = geometry.trace_rows;
    const committed_rows = geometry.commitment_rows;
    const main_coefficient_words = try mul(geometry.main_columns, rows);
    const main_evaluation_words = try mul(
        geometry.main_columns,
        committed_rows,
    );
    const composition_coefficient_words = try mul(
        geometry_mod.composition_columns,
        rows,
    );
    const coefficient_slab = try exactWords(
        provider,
        slots.coefficient_slab,
        try add(main_coefficient_words, composition_coefficient_words),
    );
    const main_coefficients = common.WordMatrix{
        .storage = try coefficient_slab.sub(0, main_coefficient_words),
        .column_stride_words = rows,
    };
    const composition_coefficients = common.WordMatrix{
        .storage = try coefficient_slab.sub(
            main_coefficient_words,
            composition_coefficient_words,
        ),
        .column_stride_words = rows,
    };

    const source_count = try add(
        geometry.main_columns,
        geometry_mod.composition_columns,
    );
    const evaluation_words = try mul(source_count, committed_rows);
    const committed_evaluation_slab = try exactWords(
        provider,
        slots.committed_evaluation_slab,
        evaluation_words,
    );
    const main_evaluations = common.WordMatrix{
        .storage = try committed_evaluation_slab.sub(
            0,
            main_evaluation_words,
        ),
        .column_stride_words = committed_rows,
    };
    const composition_evaluations = common.WordMatrix{
        .storage = try committed_evaluation_slab.sub(
            main_evaluation_words,
            try mul(geometry_mod.composition_columns, committed_rows),
        ),
        .column_stride_words = committed_rows,
    };
    const hash_count = try sub(try mul(committed_rows, 2), 1);
    const layer_count = @as(usize, geometry.queryLogSize()) + 1;
    return .{
        .trees = .{
            .storage = undefined,
            .len = 0,
        },
        .twiddles_forward = try exactWords(
            provider,
            slots.twiddles_forward,
            rows,
        ),
        .twiddles_inverse = try exactWords(
            provider,
            slots.twiddles_inverse,
            rows,
        ),
        .coefficient_slab = coefficient_slab,
        .main_coefficients = main_coefficients,
        .composition_coefficients = composition_coefficients,
        .committed_evaluation_slab = committed_evaluation_slab,
        .main_evaluations = main_evaluations,
        .composition_evaluations = composition_evaluations,
        .all_evaluations = .{
            .storage = committed_evaluation_slab,
            .column_stride_words = committed_rows,
        },
        .coefficient_log_sizes = try exactWords(
            provider,
            slots.coefficient_log_sizes,
            source_count,
        ),
        .main_merkle_hashes = try exactAs(
            provider,
            field.Blake2sHash,
            slots.main_merkle_hashes,
            hash_count,
        ),
        .composition_merkle_hashes = try exactAs(
            provider,
            field.Blake2sHash,
            slots.composition_merkle_hashes,
            hash_count,
        ),
        .main_merkle_layers = try exactAs(
            provider,
            field.MerkleLayerDescriptor,
            slots.main_merkle_layers,
            layer_count,
        ),
        .composition_merkle_layers = try exactAs(
            provider,
            field.MerkleLayerDescriptor,
            slots.composition_merkle_layers,
            layer_count,
        ),
    };
}

fn bindTraceTrees(
    trace: types.Trace,
    decommit: types.Decommit,
) !types.TraceTrees {
    return types.TraceTrees.init(&.{
        .{
            .role = .main,
            .coefficients = trace.main_coefficients,
            .evaluations = trace.main_evaluations,
            .column_log_sizes = decommit.main_column_log_sizes,
            .merkle_hashes = trace.main_merkle_hashes,
            .merkle_layers = trace.main_merkle_layers,
        },
        .{
            .role = .composition,
            .coefficients = trace.composition_coefficients,
            .evaluations = trace.composition_evaluations,
            .column_log_sizes = decommit.composition_column_log_sizes,
            .merkle_hashes = trace.composition_merkle_hashes,
            .merkle_layers = trace.composition_merkle_layers,
        },
    });
}

fn bindTranscript(
    provider: anytype,
    geometry: geometry_mod.Geometry,
) !types.Transcript {
    return .{
        .state = try exactWords(provider, slots.transcript_state, 16),
        .input_snapshot = try exactWords(
            provider,
            slots.transcript_input_snapshot,
            @max(try mul(geometry.sampled_value_count, 4), 16),
        ),
        .output_snapshot = try exactWords(
            provider,
            slots.transcript_output_snapshot,
            @max(geometry.protocol.fri_config.n_queries, 8),
        ),
        .boundary_snapshot = try exactWords(
            provider,
            slots.transcript_boundary_snapshot,
            16,
        ),
        .static_inputs = try exactWords(
            provider,
            slots.transcript_static_inputs,
            canonical_ingress.transcript_static_words,
        ),
    };
}

fn bindConstraint(
    provider: anytype,
    geometry: geometry_mod.Geometry,
) !types.Constraint {
    return .{
        .random_powers = try exactAs(
            provider,
            field.SecureField,
            slots.constraint_random_powers,
            1,
        ),
        .denominator_inverses = try exactWords(
            provider,
            slots.constraint_denominator_inverses,
            2,
        ),
        .composition_coordinates = try matrix(
            provider,
            slots.composition_coordinates,
            geometry_mod.composition_coordinates,
            geometry.commitment_rows,
        ),
        .composition_challenge = try exactAs(
            provider,
            field.SecureField,
            slots.composition_challenge,
            1,
        ),
    };
}

fn bindOods(provider: anytype, geometry: geometry_mod.Geometry) !types.Oods {
    const samples = geometry.sampled_value_count;
    const scratch_per_sample = try ceilDiv(
        geometry.trace_rows,
        oods_stage.first_coefficients_per_block,
    );
    const scratch_count = try mul(samples, scratch_per_sample);
    return .{
        .parameter = try exactAs(
            provider,
            field.SecureField,
            slots.oods_parameter,
            1,
        ),
        .offset_points = try exactAs(
            provider,
            field.CirclePointBaseField,
            slots.oods_offset_points,
            samples,
        ),
        .fold_counts = try exactWords(
            provider,
            slots.oods_fold_counts,
            samples,
        ),
        .output_indices = try exactWords(
            provider,
            slots.oods_output_indices,
            samples,
        ),
        .sample_points = try exactAs(
            provider,
            field.SecureCirclePoint,
            slots.oods_sample_points,
            samples,
        ),
        .evaluation_points = try exactAs(
            provider,
            field.SecureCirclePoint,
            slots.oods_evaluation_points,
            samples,
        ),
        .folding_factors = try exactAs(
            provider,
            field.SecureField,
            slots.oods_folding_factors,
            try mul(samples, geometry.statement.log_n_rows),
        ),
        .reduce_a = try exactAs(
            provider,
            field.SecureField,
            slots.oods_reduce_a,
            scratch_count,
        ),
        .reduce_b = try exactAs(
            provider,
            field.SecureField,
            slots.oods_reduce_b,
            scratch_count,
        ),
        .sampled_values = try exactAs(
            provider,
            field.SecureField,
            slots.sampled_values,
            samples,
        ),
    };
}

fn bindQuotient(
    provider: anytype,
    prepared: *const plan_mod.PreparedPlan,
    source_evaluations: common.WordMatrix,
    result_matrix: common.WordMatrix,
) !types.Quotient {
    const topology = prepared.quotient;
    const term_count = topology.prepared_terms.len;
    const group_count = topology.group_log_sizes.len;
    const rows = topology.output_rows;
    const prepared_terms = try exactAs(
        provider,
        quotient_abi.PreparedTermDescriptor,
        slots.quotient_prepared_terms,
        term_count,
    );
    const group_offsets = try exactWords(
        provider,
        slots.quotient_group_offsets,
        topology.group_offsets.len,
    );
    const group_term_indices = try exactWords(
        provider,
        slots.quotient_group_term_indices,
        topology.group_term_indices.len,
    );
    const batch_terms = try exactAs(
        provider,
        quotient_abi.BatchTermDescriptor,
        slots.quotient_batch_terms,
        topology.batch_terms.len,
    );
    const group_log_sizes = try exactWords(
        provider,
        slots.quotient_group_log_sizes,
        group_count,
    );
    const partial_log_sizes = try exactWords(
        provider,
        slots.quotient_partial_log_sizes,
        topology.partial_log_sizes.len,
    );
    const partial_storage = try exactWords(
        provider,
        slots.quotient_partial_coordinates,
        try mul(4, rows),
    );
    const partials = quotient_stage.CoordinateSlabs{
        .c0 = try subMatrix(partial_storage, 0, rows),
        .c1 = try subMatrix(partial_storage, rows, rows),
        .c2 = try subMatrix(partial_storage, try mul(2, rows), rows),
        .c3 = try subMatrix(partial_storage, try mul(3, rows), rows),
    };
    if (result_matrix.storage.len != try mul(4, rows) or
        result_matrix.column_stride_words != rows)
    {
        return error.InvalidKernelDescriptor;
    }
    const result = quotient_stage.CoordinateColumns{
        .c0 = try result_matrix.storage.sub(0, rows),
        .c1 = try result_matrix.storage.sub(rows, rows),
        .c2 = try result_matrix.storage.sub(try mul(2, rows), rows),
        .c3 = try result_matrix.storage.sub(try mul(3, rows), rows),
    };
    return .{
        .challenge = try exactAs(
            provider,
            field.SecureField,
            slots.quotient_challenge,
            1,
        ),
        .prepared_terms = prepared_terms,
        .group_offsets = group_offsets,
        .group_term_indices = group_term_indices,
        .batch_terms = batch_terms,
        .group_log_sizes = group_log_sizes,
        .partial_log_sizes = partial_log_sizes,
        .term_points = try exactAs(
            provider,
            field.SecureCirclePoint,
            slots.quotient_term_points,
            term_count,
        ),
        .line_coefficients = try exactAs(
            provider,
            field.SecureField,
            slots.quotient_line_coefficients,
            try mul(term_count, 3),
        ),
        .group_points = try exactAs(
            provider,
            field.SecureCirclePoint,
            slots.quotient_group_points,
            group_count,
        ),
        .first_linear_terms = try exactAs(
            provider,
            field.SecureField,
            slots.quotient_first_linear_terms,
            group_count,
        ),
        .partial_coordinates = partials,
        .result_coordinates = result,
        .source_evaluations = source_evaluations,
        .prepared_groups = .{
            .descriptors = prepared_terms,
            .sample_count = topology.source_count,
            .offsets = group_offsets,
            .term_indices = group_term_indices,
            .group_count = try count(group_count),
        },
        .numerator_topology = .{
            .offsets = group_offsets,
            .terms = batch_terms,
            .group_log_sizes = group_log_sizes,
            .group_count = try count(group_count),
            .max_output_size = try count(rows),
            .source_count = topology.source_count,
            .source_stride_words = topology.source_stride_words,
            .line_term_count = try count(term_count),
        },
        .combine_topology = .{
            .partial_log_sizes = partial_log_sizes,
            .sample_count = try count(topology.partial_log_sizes.len),
            .domain_log_size = prepared.logical.geometry.queryLogSize(),
            .partial_stride_words = rows,
        },
    };
}

fn bindFri(
    provider: anytype,
    prepared: *const plan_mod.PreparedPlan,
) !types.Fri {
    var layers: [types.max_fri_layers]types.FriLayer = undefined;
    for (prepared.fri.layers, 0..) |layer, index| {
        layers[index] = .{
            .coordinates = try matrix(
                provider,
                slots.friCoordinates(index),
                4,
                layer.coordinate_stride_words,
            ),
            .merkle_hashes = try exactAs(
                provider,
                field.Blake2sHash,
                slots.friMerkleHashes(index),
                layer.merkle_hashes,
            ),
            .merkle_layers = try exactAs(
                provider,
                field.MerkleLayerDescriptor,
                slots.friMerkleLayers(index),
                layer.retained_layer_count,
            ),
        };
        if (layers[index].coordinates.storage.len != layer.coordinate_words)
            return error.InvalidKernelDescriptor;
    }
    const last_rows = prepared.logical.geometry.last_layer_domain_rows;
    return .{
        .alpha = try exactAs(
            provider,
            field.SecureField,
            slots.fri_alpha,
            1,
        ),
        .layers = layers,
        .layer_count = prepared.fri.layers.len,
        .last_evaluation = try exactAs(
            provider,
            field.SecureField,
            slots.fri_last_evaluation,
            last_rows,
        ),
        .last_coefficients = try exactAs(
            provider,
            field.SecureField,
            slots.fri_last_coefficients,
            last_rows,
        ),
        .last_degree_error = try exactWords(
            provider,
            slots.fri_last_degree_error,
            1,
        ),
        .last_transcript = try exactAs(
            provider,
            field.SecureField,
            slots.fri_last_transcript,
            1,
        ),
    };
}

fn bindPow(provider: anytype) !types.Pow {
    return .{
        .prefix_digest = try exactWords(provider, slots.pow_prefix_digest, 8),
        .best_nonce = try exactAs(provider, u64, slots.pow_best_nonce, 1),
        .completed_blocks = try exactWords(
            provider,
            slots.pow_completed_blocks,
            1,
        ),
        .transcript_nonce = try exactWords(
            provider,
            slots.pow_transcript_nonce,
            2,
        ),
    };
}

fn bindDecommit(
    provider: anytype,
    prepared: *const plan_mod.PreparedPlan,
) !types.Decommit {
    const topology = prepared.decommit;
    const counts = try exactWords(
        provider,
        slots.decommit_counts,
        topology.count_words,
    );
    if (counts.len != 5) return error.InvalidKernelDescriptor;
    const main_column_log_sizes = try exactWords(
        provider,
        slots.main_column_log_sizes,
        prepared.logical.geometry.main_columns,
    );
    return .{
        .raw_queries = try exactWords(
            provider,
            slots.raw_queries,
            topology.query_count,
        ),
        .unique_queries = try exactWords(
            provider,
            slots.unique_queries,
            topology.unique_query_words,
        ),
        .mapped_queries = try exactWords(
            provider,
            slots.decommit_mapped_queries,
            topology.mapped_query_words,
        ),
        .walk_queries = try exactWords(
            provider,
            slots.decommit_walk_queries,
            topology.walk_query_words,
        ),
        .walk_scratch = try exactWords(
            provider,
            slots.decommit_walk_scratch,
            topology.walk_query_words,
        ),
        .leaf_indices = try exactWords(
            provider,
            slots.decommit_leaf_indices,
            topology.leaf_index_words,
        ),
        .expanded_positions = try exactWords(
            provider,
            slots.decommit_expanded_positions,
            topology.expanded_position_words,
        ),
        .sparse_indices = try exactWords(
            provider,
            slots.decommit_sparse_indices,
            topology.sparse_index_words,
        ),
        .sparse_hashes = try exactAs(
            provider,
            field.Blake2sHash,
            slots.decommit_sparse_hashes,
            topology.sparse_hash_words / 8,
        ),
        .counts = .{
            .unique = try counts.sub(0, 1),
            .mapped_or_tree = try counts.sub(1, 1),
            .walk = try counts.sub(2, 1),
            .expanded = try counts.sub(3, 1),
            .leaf_or_sparse = try counts.sub(4, 1),
        },
        .sparse_level_offsets = try exactWords(
            provider,
            slots.decommit_sparse_level_offsets,
            1,
        ),
        .sparse_level_counts = try exactWords(
            provider,
            slots.decommit_sparse_level_counts,
            1,
        ),
        .preprocessed_column_log_sizes = try main_column_log_sizes.sub(0, 0),
        .main_column_log_sizes = main_column_log_sizes,
        .interaction_column_log_sizes = try main_column_log_sizes.sub(0, 0),
        .composition_column_log_sizes = try exactWords(
            provider,
            slots.composition_column_log_sizes,
            geometry_mod.composition_columns,
        ),
    };
}

fn bindProof(
    provider: anytype,
    prepared: *const plan_mod.PreparedPlan,
) !types.Proof {
    return proof_binding.bind(
        geometry_mod,
        proof_bundle,
        slots,
        provider,
        prepared,
    );
}

fn validatePrepared(prepared: *const plan_mod.PreparedPlan) !void {
    const geometry = prepared.logical.geometry;
    const source_count = try add(
        geometry.main_columns,
        geometry_mod.composition_columns,
    );
    const trace_layer_count = @as(usize, geometry.queryLogSize()) + 1;
    const groups = prepared.quotient.group_log_sizes.len;
    if (prepared.fri.layers.len == 0 or
        prepared.fri.layers.len > types.max_fri_layers or
        prepared.fri.layers.len != geometry.fri_tree_count or
        prepared.decommit.fri_trees.len != geometry.fri_tree_count or
        prepared.decommit.query_count !=
            geometry.protocol.fri_config.n_queries or
        prepared.decommit.count_words != 5 or
        prepared.decommit.column_log_sizes.len != source_count or
        prepared.decommit.trace_trees[0].column_count !=
            geometry.main_columns or
        prepared.decommit.trace_trees[1].column_count !=
            geometry_mod.composition_columns or
        prepared.decommit.trace_trees[0].retained_layer_offset != 0 or
        prepared.decommit.trace_trees[0].retained_layer_count !=
            trace_layer_count or
        prepared.decommit.trace_trees[1].retained_layer_offset !=
            trace_layer_count or
        prepared.decommit.trace_trees[1].retained_layer_count !=
            trace_layer_count or
        prepared.quotient.source_count != source_count or
        prepared.quotient.source_stride_words != geometry.commitment_rows or
        prepared.quotient.output_rows != geometry.commitment_rows or
        prepared.quotient.prepared_terms.len !=
            geometry.sampled_value_count or
        prepared.quotient.batch_terms.len != geometry.sampled_value_count or
        groups == 0 or
        prepared.quotient.group_offsets.len != groups + 1 or
        prepared.quotient.group_term_indices.len !=
            prepared.quotient.prepared_terms.len or
        prepared.quotient.partial_log_sizes.len != groups)
    {
        return error.InvalidKernelDescriptor;
    }
    var retained_count = trace_layer_count * 2;
    for (prepared.fri.layers, 0..) |layer, index| {
        const opening = prepared.decommit.fri_trees[index];
        if (@as(usize, layer.tree_index) !=
            geometry.decommitted_trace_tree_count + index or
            layer.coordinate_stride_words != layer.evaluation_rows or
            layer.coordinate_words != try mul(4, layer.evaluation_rows) or
            layer.retained_layer_count !=
                @as(usize, layer.evaluation_log_size) + 1 or
            opening.tree_index != layer.tree_index or
            opening.evaluation_log_size != layer.evaluation_log_size or
            opening.cumulative_fold != layer.cumulative_fold or
            opening.fold_step != layer.fold_step or
            opening.log_rows_per_leaf != layer.log_rows_per_leaf or
            opening.retained_layer_offset !=
                retained_count or
            opening.retained_layer_count != layer.retained_layer_count or
            opening.max_expanded_positions !=
                try mul(
                    geometry.protocol.fri_config.n_queries,
                    try pow2(layer.fold_step),
                ))
        {
            return error.InvalidKernelDescriptor;
        }
        retained_count = try add(retained_count, layer.retained_layer_count);
    }
    if (prepared.decommit.retained_layers.len != retained_count or
        prepared.fri.retained_layers.len != retained_count -
            trace_layer_count * 2 or
        prepared.proof.section(.decommitment).words !=
            prepared.decommit.assembly_words)
    {
        return error.InvalidKernelDescriptor;
    }
}

fn exactWords(provider: anytype, id: anytype, expected: usize) !Words {
    const value = try provider.slot(id);
    if (value.len != expected) return error.InvalidKernelDescriptor;
    return value;
}

fn exactAs(
    provider: anytype,
    comptime F: type,
    id: anytype,
    expected: usize,
) !column.DeviceSlice(F) {
    const words_per_element = @sizeOf(F) / @sizeOf(u32);
    const words = try exactWords(provider, id, try mul(expected, words_per_element));
    const value = try words.cast(F);
    if (value.len != expected) return error.InvalidKernelDescriptor;
    return value;
}

fn matrix(
    provider: anytype,
    id: anytype,
    columns: usize,
    stride: usize,
) !common.WordMatrix {
    return .{
        .storage = try exactWords(provider, id, try mul(columns, stride)),
        .column_stride_words = stride,
    };
}

fn subMatrix(storage: Words, first: usize, stride: usize) !common.WordMatrix {
    return .{
        .storage = try storage.sub(first, stride),
        .column_stride_words = stride,
    };
}

fn requireDisjoint(first: anytype, second: anytype) !void {
    const first_bytes = try mul(first.len, @sizeOf(field.SecureField));
    const second_bytes = try mul(second.len, @sizeOf(field.SecureField));
    const first_end = try add(first.address, first_bytes);
    const second_end = try add(second.address, second_bytes);
    if (first.address < second_end and second.address < first_end)
        return error.OverlappingDeviceRange;
}

fn count(value: usize) !u32 {
    return std.math.cast(u32, value) orelse error.SizeOverflow;
}

fn ceilDiv(value: usize, divisor: usize) !usize {
    return std.math.divCeil(usize, value, divisor) catch error.SizeOverflow;
}

fn pow2(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.SizeOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

fn add(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.add(usize, lhs, rhs) catch error.SizeOverflow;
}

fn sub(left: usize, right: usize) !usize {
    return std.math.sub(usize, left, right) catch error.SizeOverflow;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.SizeOverflow;
}
