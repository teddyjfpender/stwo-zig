//! Geometry-checked views over one prepared resident Native CUDA proof arena.
const std = @import("std");
const field = @import("../../../backends/cuda/abi/field.zig");
const quotient_abi = @import(
    "../../../backends/cuda/abi/stages/quotient.zig",
);
const column = @import("../../../backends/cuda/runtime/column.zig");
const common = @import("../../../backends/cuda/runtime/stages/common.zig");
const oods_stage = @import("../../../backends/cuda/runtime/stages/oods.zig");
const quotient_stage = @import(
    "../../../backends/cuda/runtime/stages/quotient.zig",
);
const constraint = @import(
    "../../../backends/cuda/runtime/constraints/constant_qm31.zig",
);
const tree_binding = @import("resident_tree_binding.zig");
const proof_binding = @import("resident_proof_binding.zig");
const views = @import("resident_views.zig");

const Words = column.DeviceSlice(u32);

pub const Bound = struct {
    trees: views.TraceTrees,
    trace: Trace,
    twiddles_forward: common.Words,
    twiddles_inverse: common.Words,
    protocol_words: common.Words,
    statement_words: common.Words,
    transcript: Transcript,
    constraint_buffers: constraint.Buffers,
    source_evaluations: common.WordMatrix,
    oods: views.Oods,
    quotient: views.Quotient,
    fri: views.Fri,
    pow: views.Pow,
    decommit: views.Decommit,
    proof: views.Proof,
};

pub const Trace = struct {
    trees: views.TraceTrees,
    twiddles_forward: common.Words,
    twiddles_inverse: common.Words,
    source_evaluations: common.WordMatrix,
};

pub const Transcript = struct {
    state: common.Words,
    input_snapshot: common.Words,
    output_snapshot: common.Words,
    boundary_snapshot: common.Words,
    protocol_words: common.Words,
    statement_words: common.Words,
};

pub fn BindingFor(
    comptime geometry_mod: type,
    comptime plan_mod: type,
    comptime slots: type,
    comptime proof_bundle: type,
) type {
    return struct {
        pub fn bind(
            provider: anytype,
            prepared: *const plan_mod.PreparedPlan,
        ) !Bound {
            const geometry = prepared.logical.geometry;
            const rows = try geometry.traceRowCount();
            const committed_rows = geometry.commitment_rows;
            // Coefficients own normalized N-word images. Commitment-domain
            // evaluations remain separate 2N-word LDE columns.
            const hash_count = try sub(try mul(committed_rows, 2), 1);
            const layer_count = @as(usize, geometry.commitment_log_rows) + 1;
            const resident_column_count = if (@hasDecl(
                geometry_mod,
                "resident_evaluation_columns",
            ))
                geometry_mod.resident_evaluation_columns
            else
                geometry_mod.sampled_mask_points;
            const sampled_source_offset = if (@hasDecl(
                geometry_mod,
                "sampled_source_column_offset",
            ))
                geometry_mod.sampled_source_column_offset
            else
                0;
            const sampled_source_count = if (@hasDecl(
                geometry_mod,
                "sampled_source_column_count",
            ))
                geometry_mod.sampled_source_column_count
            else
                geometry_mod.sampled_mask_points;
            const source_words = try exactWords(
                provider,
                slots.source_evaluations,
                try mul(resident_column_count, committed_rows),
            );
            const preprocessed_evaluations = common.WordMatrix{
                .storage = try source_words.sub(
                    0,
                    try mul(geometry_mod.preprocessed_columns, committed_rows),
                ),
                .column_stride_words = committed_rows,
            };
            const main_offset = try mul(
                geometry_mod.preprocessed_columns,
                committed_rows,
            );
            const main_evaluations = common.WordMatrix{
                .storage = try source_words.sub(
                    main_offset,
                    try mul(geometry_mod.main_columns, committed_rows),
                ),
                .column_stride_words = committed_rows,
            };
            const after_main = try add(
                main_offset,
                try mul(geometry_mod.main_columns, committed_rows),
            );
            const has_interaction = @hasDecl(
                geometry_mod,
                "interaction_columns",
            ) and geometry_mod.interaction_columns > 0;
            const interaction_coefficient_stride =
                if (@hasDecl(
                    geometry_mod,
                    "interactionCoefficientStride",
                ))
                    geometry_mod.interactionCoefficientStride(geometry)
                else
                    rows;
            const interaction_offset = after_main;
            const composition_offset = if (has_interaction)
                try add(
                    interaction_offset,
                    try mul(
                        geometry_mod.interaction_columns,
                        committed_rows,
                    ),
                )
            else
                after_main;
            const composition_evaluations = common.WordMatrix{
                .storage = try source_words.sub(
                    composition_offset,
                    try mul(geometry_mod.composition_columns, committed_rows),
                ),
                .column_stride_words = committed_rows,
            };
            const has_preprocessed =
                geometry_mod.preprocessed_columns > 0;
            const preprocessed = if (has_preprocessed)
                try tree_binding.bind(
                    provider,
                    .preprocessed,
                    slots.preprocessed_coefficients,
                    preprocessed_evaluations,
                    slots.preprocessed_log_sizes,
                    slots.preprocessed_merkle_hashes,
                    slots.preprocessed_merkle_layers,
                    geometry_mod.preprocessed_columns,
                    rows,
                    hash_count,
                    layer_count,
                )
            else
                undefined;
            const main = try tree_binding.bind(
                provider,
                .main,
                slots.main_coefficients,
                main_evaluations,
                slots.main_log_sizes,
                slots.main_merkle_hashes,
                slots.main_merkle_layers,
                geometry_mod.main_columns,
                rows,
                hash_count,
                layer_count,
            );
            const interaction = if (has_interaction)
                try tree_binding.bind(
                    provider,
                    .interaction,
                    slots.interaction_coefficients,
                    .{
                        .storage = try source_words.sub(
                            interaction_offset,
                            try mul(
                                geometry_mod.interaction_columns,
                                committed_rows,
                            ),
                        ),
                        .column_stride_words = committed_rows,
                    },
                    slots.interaction_log_sizes,
                    slots.interaction_merkle_hashes,
                    slots.interaction_merkle_layers,
                    geometry_mod.interaction_columns,
                    interaction_coefficient_stride,
                    hash_count,
                    layer_count,
                )
            else
                undefined;
            const composition = try tree_binding.bind(
                provider,
                .composition,
                slots.composition_coefficients,
                composition_evaluations,
                slots.composition_log_sizes,
                slots.composition_merkle_hashes,
                slots.composition_merkle_layers,
                geometry_mod.composition_columns,
                rows,
                hash_count,
                layer_count,
            );
            const statement_words = try exactWords(
                provider,
                slots.statement_words,
                geometry_mod.statement_word_count,
            );
            const challenge_words = try exactWords(
                provider,
                slots.composition_challenge,
                4,
            );
            const protocol_words = try exactWords(
                provider,
                slots.protocol_words,
                4,
            );
            const transcript = Transcript{
                .state = try exactWords(provider, slots.transcript_state, 16),
                .input_snapshot = try exactWords(
                    provider,
                    slots.transcript_input_snapshot,
                    @max(try mul(geometry_mod.sampled_mask_points, 4), 16),
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
                .protocol_words = protocol_words,
                .statement_words = statement_words,
            };
            const trees = if (has_preprocessed and has_interaction)
                try views.TraceTrees.init(&.{
                    preprocessed,
                    main,
                    interaction,
                    composition,
                })
            else if (has_preprocessed)
                try views.TraceTrees.init(&.{
                    preprocessed,
                    main,
                    composition,
                })
            else if (has_interaction)
                try views.TraceTrees.init(&.{
                    main,
                    interaction,
                    composition,
                })
            else
                try views.TraceTrees.init(&.{
                    main,
                    composition,
                });
            const fri = try bindFri(provider, prepared);
            const source_evaluations = common.WordMatrix{
                .storage = try source_words.sub(
                    try mul(sampled_source_offset, committed_rows),
                    try mul(
                        sampled_source_count,
                        committed_rows,
                    ),
                ),
                .column_stride_words = committed_rows,
            };
            const twiddles_forward = try exactWords(
                provider,
                slots.twiddles_forward,
                rows,
            );
            const twiddles_inverse = try exactWords(
                provider,
                slots.twiddles_inverse,
                rows,
            );
            return .{
                .trees = trees,
                .trace = .{
                    .trees = trees,
                    .twiddles_forward = twiddles_forward,
                    .twiddles_inverse = twiddles_inverse,
                    .source_evaluations = source_evaluations,
                },
                .twiddles_forward = twiddles_forward,
                .twiddles_inverse = twiddles_inverse,
                .protocol_words = protocol_words,
                .statement_words = statement_words,
                .transcript = transcript,
                .source_evaluations = source_evaluations,
                .constraint_buffers = .{
                    .statement_parameters = statement_words,
                    .challenge_parameters = challenge_words,
                    .composition_coordinates = .{
                        .storage = try exactWords(
                            provider,
                            slots.composition_coordinates,
                            try mul(4, committed_rows),
                        ),
                        .column_stride_words = committed_rows,
                    },
                },
                .oods = try bindOods(provider, geometry),
                .quotient = try bindQuotient(
                    provider,
                    prepared,
                    source_evaluations,
                    fri.layers[0].coordinates,
                ),
                .fri = fri,
                .pow = try bindPow(provider),
                .decommit = try bindDecommit(provider, prepared),
                .proof = try proof_binding.bind(
                    geometry_mod,
                    proof_bundle,
                    slots,
                    provider,
                    prepared,
                ),
            };
        }

        fn bindOods(
            provider: anytype,
            geometry: geometry_mod.Geometry,
        ) !views.Oods {
            const samples: usize = geometry_mod.sampled_mask_points;
            const factor_count = if (@hasDecl(
                geometry_mod,
                "oodsFactorCount",
            ))
                try geometry_mod.oodsFactorCount(geometry)
            else
                try mul(samples, geometry.traceLogSize());
            const scratch_count = if (@hasDecl(
                geometry_mod,
                "oodsScratchCount",
            ))
                try geometry_mod.oodsScratchCount(geometry)
            else
                try mul(
                    samples,
                    try ceilDiv(
                        try geometry.traceRowCount(),
                        oods_stage.first_coefficients_per_block,
                    ),
                );
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
                    factor_count,
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
        ) !views.Quotient {
            const topology = prepared.quotient;
            const term_count = topology.prepared_terms.len;
            const group_count = topology.group_log_sizes.len;
            const rows: usize = topology.output_rows;
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
                    .sample_count = @intCast(term_count),
                    .offsets = group_offsets,
                    .term_indices = group_term_indices,
                    .group_count = @intCast(group_count),
                },
                .numerator_topology = .{
                    .offsets = group_offsets,
                    .terms = batch_terms,
                    .group_log_sizes = group_log_sizes,
                    .group_count = @intCast(group_count),
                    .max_output_size = @intCast(rows),
                    .source_count = topology.source_count,
                    .source_stride_words = topology.source_stride_words,
                    .line_term_count = @intCast(term_count),
                },
                .combine_topology = .{
                    .partial_log_sizes = partial_log_sizes,
                    .sample_count = @intCast(topology.partial_log_sizes.len),
                    .domain_log_size = prepared.logical.geometry.queryLogSize(),
                    .partial_stride_words = rows,
                },
            };
        }

        fn bindFri(
            provider: anytype,
            prepared: *const plan_mod.PreparedPlan,
        ) !views.Fri {
            var layers: [views.max_fri_layers]views.FriLayer = undefined;
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
                if (layers[index].coordinates.storage.len !=
                    layer.coordinate_words)
                {
                    return error.InvalidKernelDescriptor;
                }
            }
            const last_rows =
                prepared.logical.geometry.last_layer_domain_rows;
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

        fn bindPow(provider: anytype) !views.Pow {
            return .{
                .prefix_digest = try exactWords(
                    provider,
                    slots.pow_prefix_digest,
                    8,
                ),
                .best_nonce = try exactAs(
                    provider,
                    u64,
                    slots.pow_best_nonce,
                    1,
                ),
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
        ) !views.Decommit {
            const topology = prepared.decommit;
            const counts = try exactWords(
                provider,
                slots.decommit_counts,
                topology.count_words,
            );
            if (counts.len != 5) return error.InvalidKernelDescriptor;
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
                .preprocessed_column_log_sizes = if (geometry_mod.preprocessed_columns > 0)
                    try exactWords(
                        provider,
                        slots.decommit_preprocessed_log_sizes,
                        geometry_mod.preprocessed_columns,
                    )
                else
                    .{
                        .address = 0,
                        .len = 0,
                        .owner = 0,
                        .generation = 0,
                    },
                .main_column_log_sizes = try exactWords(
                    provider,
                    slots.decommit_main_log_sizes,
                    geometry_mod.main_columns,
                ),
                .interaction_column_log_sizes = if (@hasDecl(
                    geometry_mod,
                    "interaction_columns",
                ) and geometry_mod.interaction_columns > 0)
                    try exactWords(
                        provider,
                        slots.decommit_interaction_log_sizes,
                        geometry_mod.interaction_columns,
                    )
                else
                    .{
                        .address = 0,
                        .len = 0,
                        .owner = 0,
                        .generation = 0,
                    },
                .composition_column_log_sizes = try exactWords(
                    provider,
                    slots.decommit_composition_log_sizes,
                    geometry_mod.composition_columns,
                ),
            };
        }

        fn exactWords(
            provider: anytype,
            id: slots.SlotId,
            expected: usize,
        ) !Words {
            const value = try provider.slot(id);
            if (value.len != expected) return error.InvalidKernelDescriptor;
            return value;
        }

        fn exactAs(
            provider: anytype,
            comptime F: type,
            id: slots.SlotId,
            expected: usize,
        ) !column.DeviceSlice(F) {
            const words_per_element = @sizeOf(F) / @sizeOf(u32);
            const words = try exactWords(
                provider,
                id,
                try mul(expected, words_per_element),
            );
            const result = try words.cast(F);
            if (result.len != expected) return error.InvalidKernelDescriptor;
            return result;
        }

        fn matrix(
            provider: anytype,
            id: slots.SlotId,
            columns: usize,
            stride: usize,
        ) !common.WordMatrix {
            return .{
                .storage = try exactWords(
                    provider,
                    id,
                    try mul(columns, stride),
                ),
                .column_stride_words = stride,
            };
        }

        fn subMatrix(
            storage: Words,
            first: usize,
            stride: usize,
        ) !common.WordMatrix {
            return .{
                .storage = try storage.sub(first, stride),
                .column_stride_words = stride,
            };
        }

        fn ceilDiv(value: usize, divisor: usize) !usize {
            return std.math.divCeil(usize, value, divisor) catch
                error.SizeOverflow;
        }

        fn sub(left: usize, right: usize) !usize {
            return std.math.sub(usize, left, right) catch error.SizeOverflow;
        }

        fn add(left: usize, right: usize) !usize {
            return std.math.add(usize, left, right) catch error.SizeOverflow;
        }

        fn mul(left: anytype, right: anytype) !usize {
            const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
            const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
            return std.math.mul(usize, lhs, rhs) catch error.SizeOverflow;
        }
    };
}
