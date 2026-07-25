//! Public value types for the Cairo CUDA resident-memory contract.

const proof_ir = @import("stwo_backend_contracts").proof_program;
const arena = @import("../../../backends/cuda/runtime/arena.zig");
const telemetry = @import("../../../backends/cuda/runtime/telemetry.zig");

pub const word_bytes: u64 = @sizeOf(u32);

pub const SlotKind = enum(u8) {
    adapted_input,
    statement_bootstrap,
    writer_inputs,
    writer_pointer_tables,
    writer_descriptors,
    writer_lookup_inputs,
    writer_scratch,
    fixed_writer_tables,
    memory_writer_tables,
    relation_top_level_tables,
    relation_source_pointer_tables,
    relation_descriptors,
    relation_geometry,
    relation_challenges,
    relation_z,
    relation_alpha_powers,
    relation_denominators,
    relation_claimed_sums,
    relation_output_graph,
    relation_reduction_scratch,
    relation_scan_scratch,
    eval_arguments,
    eval_trace_offsets,
    eval_interaction_offsets,
    eval_lde_descriptors,
    eval_lde_tile,
    eval_base_parameters,
    eval_extended_parameter_descriptors,
    eval_extended_parameters,
    eval_composition_offsets,
    trace_coefficients,
    constraint_composition_accumulator,
    constraint_composition_output,
    trace_evaluations,
    trace_column_logs,
    trace_column_offsets,
    trace_merkle_hashes,
    trace_merkle_layers,
    trace_progressive_states,
    trace_root,
    twiddles_forward,
    twiddles_inverse,
    transcript,
    interaction_claims,
    composition_alpha,
    constraint_random_powers,
    constraint_denominators,
    oods_parameter,
    oods_offset_points,
    oods_fold_counts,
    oods_output_indices,
    oods_sample_points,
    oods_evaluation_points,
    oods_folding_factors,
    oods_reduce_a,
    oods_reduce_b,
    oods_sampled_values,
    quotient_challenge,
    quotient_prepared_terms,
    quotient_group_offsets,
    quotient_group_term_indices,
    quotient_batch_terms,
    quotient_source_descriptors,
    quotient_group_logs,
    quotient_partial_logs,
    quotient_partial_offsets,
    quotient_term_points,
    quotient_line_coefficients,
    quotient_group_points,
    quotient_first_linear_terms,
    quotient_partial_coordinates,
    quotient_result_coordinates,
    fri_alpha,
    fri_coordinates,
    fri_merkle_hashes,
    fri_merkle_layers,
    fri_last_evaluation,
    fri_last_coefficients,
    fri_last_degree_error,
    fri_last_transcript,
    pow_prefix,
    pow_best_nonce,
    pow_completed_blocks,
    pow_transcript_nonce,
    decommit_raw_queries,
    decommit_unique_queries,
    decommit_mapped_queries,
    decommit_walk_queries,
    decommit_walk_scratch,
    decommit_leaf_indices,
    decommit_expanded_positions,
    decommit_sparse_indices,
    decommit_sparse_hashes,
    decommit_counts,
    decommit_level_offsets,
    decommit_level_counts,
    decommit_column_logs,
    decommit_assembly,
    terminal_bundle,
};

pub const Slot = struct {
    id: arena.SlotId,
    kind: SlotKind,
    ordinal: u32,
    words: usize,
    alignment_words: usize,
    live_from: telemetry.Stage,
    live_through: telemetry.Stage,
    storage: proof_ir.StorageClass,
    immutable: bool,
    identity: proof_ir.Digest,
};

pub const Summary = struct {
    slot_count: usize,
    logical_words: u64,
    request_logical_words: u64,
    persistent_words: u64,
    request_arena_words: u64,
    peak_live_words: u64,
    allocated_resident_words: u64,
    coefficient_cells: u64,
    evaluation_cells: u64,
    terminal_words: u64,
    decommit_assembly_words: u64,
    decommit_terminal_shortfall_words: u64,

    pub fn allocatedResidentBytes(self: Summary) u64 {
        return self.allocated_resident_words * word_bytes;
    }

    pub fn logicalBytes(self: Summary) u64 {
        return self.logical_words * word_bytes;
    }

    pub fn fitsBytes(self: Summary, capacity_bytes: u64) bool {
        return self.allocatedResidentBytes() <= capacity_bytes;
    }
};

pub const QuotientGeometry = struct {
    term_count: usize,
    group_count: usize,
    source_count: usize,
    partial_word_count: usize,
    maximum_partial_rows: u32,
    identity: proof_ir.Digest,
};

pub const Error = error{
    GeometryOverflow,
    InvalidComposition,
    InvalidIngressGeometry,
    InvalidProgram,
    UnsupportedGeometry,
};
