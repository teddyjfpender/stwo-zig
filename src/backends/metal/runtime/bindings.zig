//! Objective-C/Metal entry points consumed by the Zig runtime stages.

const std = @import("std");
const runtime = @import("../runtime.zig");

const ArenaCopyRange = runtime.ArenaCopyRange;
const PipelineCacheStats = runtime.PipelineCacheStats;
const ArchiveStoreStatsV1 = runtime.ArchiveStoreStatsV1;
const CommandEpochStats = runtime.CommandEpochStats;
const PreparedStateRange = runtime.PreparedStateRange;
const WitnessLayout = runtime.WitnessLayout;
const BasePolynomialDispatch = runtime.BasePolynomialDispatch;
const BasePolynomialOutput = runtime.BasePolynomialOutput;
const LookupPolynomialDispatch = runtime.LookupPolynomialDispatch;

pub const QuotientWorkReceipt = extern struct {
    schema_version: u32,
    path: u32,
    reserved0: u32,
    reserved1: u32,
    row_count: u64,
    batch_count: u64,
    view_count: u64,
    grouped_partial_count: u64,
    numerator_additions: u64,
    numerator_multiplications: u64,
    domain_circle_additions: u64,
    batch_inverse_calls: u64,
};

comptime {
    std.debug.assert(@sizeOf(QuotientWorkReceipt) == 80);
    std.debug.assert(@offsetOf(QuotientWorkReceipt, "row_count") == 16);
}

pub extern fn stwo_zig_metal_runtime_destroy(runtime: ?*anyopaque) void;
pub extern fn stwo_zig_metal_runtime_identity(
    runtime: *anyopaque,
    output: ?[*]u8,
    output_len: usize,
) usize;
pub extern fn stwo_zig_metal_blake2s_pow_search(
    runtime: *anyopaque,
    prefix_words: *const [8]u32,
    round_zero_columns: *const [16]u32,
    pow_bits: u32,
    nonce: *u64,
    gpu_milliseconds: *f64,
    dispatch_count: *u32,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_pipeline_cache_stats(
    runtime: *anyopaque,
    stats: *PipelineCacheStats,
) bool;
pub extern fn stwo_zig_metal_archive_store_stats_v1(
    runtime: *anyopaque,
    stats: *ArchiveStoreStatsV1,
    stats_size: usize,
) bool;
pub extern fn stwo_zig_metal_max_buffer_length(runtime: *anyopaque) u64;
pub extern fn stwo_zig_metal_recommended_max_working_set_size(runtime: *anyopaque) u64;
pub extern fn stwo_zig_metal_buffer_create(
    runtime: *anyopaque,
    byte_length: usize,
    contents: **anyopaque,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_commit_arena_alias(
    runtime: *anyopaque,
    contents: *anyopaque,
    byte_length: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_resident_merkle_tree_from_completed_arena(
    runtime: *anyopaque,
    epoch: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_quadratic_recurrence_trace(
    runtime: *anyopaque,
    columns: [*]const [*]u32,
    column_count: u32,
    row_count: u32,
    log_n_rows: u32,
    recipe: *const [7]u32,
    gpu_milliseconds: *f64,
    copyback_count: *u32,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_clear_arena_ranges(
    runtime: *anyopaque,
    arena: *anyopaque,
    ranges: [*]const [2]u32,
    range_count: u32,
    max_length: u32,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_arena_copy_prepare(
    runtime: *anyopaque,
    ranges: [*]const ArenaCopyRange,
    range_count: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_arena_copy_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_prepared_state_transfer(
    runtime: *anyopaque,
    arena: *anyopaque,
    snapshot: *anyopaque,
    ranges: [*]const PreparedStateRange,
    range_count: u32,
    capture: bool,
    clear_arena: bool,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_witness_feed_prepare(
    runtime: *anyopaque,
    descriptors: [*]const u32,
    descriptor_count: u32,
    luts: [*]const u32,
    lut_words: usize,
    destination_offsets: [*]const u32,
    destination_count: usize,
    source_offsets: [*]const u32,
    source_count: usize,
    clear_ranges: [*]const [2]u32,
    clear_range_count: u32,
    clear_max_length: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_witness_feed_batch_prepare(
    runtime: *anyopaque,
    plans: [*]const *anyopaque,
    column_lengths: [*]const u32,
    plan_count: u32,
    clear_ranges: [*]const [2]u32,
    clear_range_count: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_witness_feed_batch_counts_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    batch: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_witness_feed_batch_clear_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    batch: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_witness_feed_batch_index_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    batch: *anyopaque,
    index: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_circle_lde_prepare(
    runtime: *anyopaque,
    source_offsets: [*]const u64,
    destination_offsets: [*]const u64,
    column_count: u32,
    base_log_size: u32,
    extended_log_size: u32,
    twiddle_offset_words: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_circle_lde_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_circle_ifft_prepare(
    runtime: *anyopaque,
    source_offsets: [*]const u64,
    destination_offsets: [*]const u64,
    column_count: u32,
    log_size: u32,
    twiddle_offset_words: u32,
    scale_factor: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_circle_ifft_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_fixed_table_prepare(
    runtime: *anyopaque,
    descriptors: [*]const u32,
    descriptor_words: u32,
    source_offsets: [*]const u32,
    source_count: u32,
    multiplicity_offsets: [*]const u32,
    multiplicity_count: u32,
    destination_offset: u32,
    row_count: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_fixed_table_batch_prepare(
    runtime: *anyopaque,
    plans: [*]const *anyopaque,
    plan_count: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_fixed_table_batch_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    batch: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_merkle_parent_chain_prepare(
    runtime: *anyopaque,
    child_offsets: [*]const u32,
    destination_offsets: [*]const u32,
    parent_counts: [*]const u32,
    level_count: u32,
    node_seed: *const [8]u32,
    prefix_bytes: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_merkle_leaf_prepare(
    runtime: *anyopaque,
    column_offsets: [*]const u32,
    column_log_sizes: [*]const u32,
    column_count: u32,
    lifting_log_size: u32,
    destination_offset: u32,
    leaf_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_merkle_leaf_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_resident_merkle_prepare(
    runtime: *anyopaque,
    column_offsets: [*]const u32,
    column_log_sizes: [*]const u32,
    column_count: u32,
    lifting_log_size: u32,
    layer_offsets: [*]const u32,
    layer_count: u32,
    leaf_seed: *const [8]u32,
    node_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_resident_merkle_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_merkle_parent_chain_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_ec_op_prepare(
    runtime: *anyopaque,
    execution_offsets: *const [37]u32,
    trace_offsets: *const [273]u32,
    partial_offsets: *const [127]u32,
    multiplicity_offsets: *const [4]u32,
    lookup_offset: u32,
    segment_offset: u32,
    scratch_offset: u32,
    row_count: u32,
    write_base: bool,
    write_lookup: bool,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_ec_op_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_compact_prepare(
    runtime: *anyopaque,
    source_offsets: [*]const u32,
    source_count: u32,
    descriptors: [*]const u32,
    descriptor_words: u32,
    output_offsets: [*]const u32,
    output_count: u32,
    params: *const [21]u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_compact_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_eval_prepare(
    runtime: *anyopaque,
    source: [*]const u8,
    source_len: usize,
    name: [*]const u8,
    name_len: usize,
    arguments: *const [14]u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_eval_library_load(
    runtime: *anyopaque,
    path: [*]const u8,
    path_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_eval_library_compile(
    runtime: *anyopaque,
    source: [*]const u8,
    source_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_witness_prepare_library(
    runtime: *anyopaque,
    library: *anyopaque,
    name: [*]const u8,
    name_len: usize,
    arguments: *const WitnessLayout,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_witness_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_eval_prepare_library(
    runtime: *anyopaque,
    library: *anyopaque,
    name: [*]const u8,
    name_len: usize,
    arguments: *const [14]u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_base_polynomial_prepare_aot(
    runtime: *anyopaque,
    name: [*]const u8,
    name_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_base_polynomial_prepare_library(
    runtime: *anyopaque,
    library: *anyopaque,
    name: [*]const u8,
    name_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_base_polynomial_batch(
    runtime: *anyopaque,
    trees: [*]const ?*anyopaque,
    tree_count: u32,
    main_columns: [*]const [*]const u32,
    total_main_columns: u32,
    dispatches: [*]const BasePolynomialDispatch,
    dispatch_count: u32,
    power_words: [*]const u32,
    total_power_words: u32,
    outputs: [*]const BasePolynomialOutput,
    output_count: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_lookup_polynomial_prepare_aot(
    runtime: *anyopaque,
    name: [*]const u8,
    name_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_lookup_polynomial_prepare_library(
    runtime: *anyopaque,
    library: *anyopaque,
    name: [*]const u8,
    name_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_lookup_polynomial_batch(
    runtime: *anyopaque,
    trees: [*]const ?*anyopaque,
    tree_count: u32,
    main_columns: [*]const [*]const u32,
    total_main_columns: u32,
    interaction_columns: [*]const [*]const u32,
    total_interaction_columns: u32,
    dispatches: [*]const LookupPolynomialDispatch,
    dispatch_count: u32,
    power_words: [*]const u32,
    total_power_words: u32,
    parameter_words: [*]const u32,
    total_parameter_words: u32,
    outputs: [*]const BasePolynomialOutput,
    output_count: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_eval_batch_prepare(
    plans: [*]const *anyopaque,
    plan_count: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_eval_batch_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    batch: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_eval_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_composition_finalize_prepare(
    runtime: *anyopaque,
    accumulator_offsets: [*]const u32,
    accumulator_logs: [*]const u32,
    accumulator_count: u32,
    inverse_twiddle_offset_words: u32,
    output_offsets: *const [8]u32,
    scale_factor: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_composition_lde_prepare(
    runtime: *anyopaque,
    source_offsets: [*]const u64,
    source_logs: [*]const u32,
    destination_offsets: [*]const u32,
    column_count: u32,
    extended_log: u32,
    twiddle_offset_words: u32,
    use_radix4: bool,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_composition_lde_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_composition_inputs_prepare(
    runtime: *anyopaque,
    descriptors: ?[*]const u32,
    descriptor_count: u32,
    random_offset: u32,
    powers_offset: u32,
    power_count: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_composition_front_prepare(
    inputs: *anyopaque,
    lde_plans: [*]const *anyopaque,
    eval_batches: [*]const *anyopaque,
    component_count: u32,
    accumulator_offset: u32,
    accumulator_words: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_composition_front_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_composition_finalize_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_composition_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    front: *anyopaque,
    finalize: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_relation_prepare(
    runtime: *anyopaque,
    geometry: [*]const u32,
    instance_count: u32,
    source_offsets: [*]const u32,
    source_count: u32,
    descriptors: [*]const u32,
    descriptor_words: u32,
    output_offsets: [*]const u32,
    output_count: u32,
    total_blocks: u32,
    alpha_offset_words: u32,
    z_offset_words: u32,
    scratch_offset_words: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_relation_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_witness_feed_counts_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    column_length: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
const opening_bindings = @import("opening_bindings.zig");

pub const stwo_zig_metal_fri_fold_circle = opening_bindings.stwo_zig_metal_fri_fold_circle;
pub const stwo_zig_metal_fri_fold_line = opening_bindings.stwo_zig_metal_fri_fold_line;
pub const stwo_zig_metal_fri_fold_line_and_commit = opening_bindings.stwo_zig_metal_fri_fold_line_and_commit;
pub const stwo_zig_metal_fri_line_cascade = opening_bindings.stwo_zig_metal_fri_line_cascade;
pub const stwo_zig_metal_fri_fold_prepare = opening_bindings.stwo_zig_metal_fri_fold_prepare;
pub const stwo_zig_metal_fri_fold_prepared = opening_bindings.stwo_zig_metal_fri_fold_prepared;
pub const stwo_zig_metal_quotient_combine_prepare = opening_bindings.stwo_zig_metal_quotient_combine_prepare;
pub const stwo_zig_metal_quotient_combine_prepared = opening_bindings.stwo_zig_metal_quotient_combine_prepared;
pub const stwo_zig_metal_quotient_coefficients_resident = opening_bindings.stwo_zig_metal_quotient_coefficients_resident;
pub const stwo_zig_metal_fri_round_prepare = opening_bindings.stwo_zig_metal_fri_round_prepare;
pub const stwo_zig_metal_fri_round_prepared = opening_bindings.stwo_zig_metal_fri_round_prepared;
pub const stwo_zig_metal_fri_tree_prepare = opening_bindings.stwo_zig_metal_fri_tree_prepare;
pub const stwo_zig_metal_fri_tree_prepared = opening_bindings.stwo_zig_metal_fri_tree_prepared;
pub const stwo_zig_metal_fri_final_prepare = opening_bindings.stwo_zig_metal_fri_final_prepare;
pub const stwo_zig_metal_fri_final_prepared = opening_bindings.stwo_zig_metal_fri_final_prepared;
pub const stwo_zig_metal_transcript_init = opening_bindings.stwo_zig_metal_transcript_init;
pub const stwo_zig_metal_transcript_mix = opening_bindings.stwo_zig_metal_transcript_mix;
pub const stwo_zig_metal_transcript_draw_secure = opening_bindings.stwo_zig_metal_transcript_draw_secure;
pub const stwo_zig_metal_transcript_draw_queries = opening_bindings.stwo_zig_metal_transcript_draw_queries;
pub const stwo_zig_metal_decommit_normalize_queries = opening_bindings.stwo_zig_metal_decommit_normalize_queries;
pub const stwo_zig_metal_decommit_prepare_fri_queries = opening_bindings.stwo_zig_metal_decommit_prepare_fri_queries;
pub const stwo_zig_metal_decommit_prepare_trace_queries = opening_bindings.stwo_zig_metal_decommit_prepare_trace_queries;
pub const stwo_zig_metal_decommit_gather_trace_values = opening_bindings.stwo_zig_metal_decommit_gather_trace_values;
pub const stwo_zig_metal_decommit_gather_fri_values = opening_bindings.stwo_zig_metal_decommit_gather_fri_values;
pub const stwo_zig_metal_decommit_assemble_fri = opening_bindings.stwo_zig_metal_decommit_assemble_fri;
pub const stwo_zig_metal_decommit_fri_round = opening_bindings.stwo_zig_metal_decommit_fri_round;
pub const stwo_zig_metal_decommit_sparse_parent = opening_bindings.stwo_zig_metal_decommit_sparse_parent;
pub const stwo_zig_metal_decommit_sparse_leaves = opening_bindings.stwo_zig_metal_decommit_sparse_leaves;
pub const stwo_zig_metal_decommit_sparse_leaf_group = opening_bindings.stwo_zig_metal_decommit_sparse_leaf_group;
pub const stwo_zig_metal_decommit_trace_group = opening_bindings.stwo_zig_metal_decommit_trace_group;
pub const stwo_zig_metal_decommit_assemble_trace = opening_bindings.stwo_zig_metal_decommit_assemble_trace;
const resident_data_bindings = @import("resident_data.zig");

pub const stwo_zig_metal_witness_input_gather = resident_data_bindings.stwo_zig_metal_witness_input_gather;
pub const stwo_zig_metal_execution_table_split = resident_data_bindings.stwo_zig_metal_execution_table_split;
pub const stwo_zig_metal_memory_address_base_trace = resident_data_bindings.stwo_zig_metal_memory_address_base_trace;
pub const stwo_zig_metal_memory_value_base_trace = resident_data_bindings.stwo_zig_metal_memory_value_base_trace;
pub const stwo_zig_metal_memory_rc99_count = resident_data_bindings.stwo_zig_metal_memory_rc99_count;
pub const stwo_zig_metal_public_memory_seed = resident_data_bindings.stwo_zig_metal_public_memory_seed;
pub const stwo_zig_metal_leaf_absorb = resident_data_bindings.stwo_zig_metal_leaf_absorb;
pub const stwo_zig_metal_leaf_absorb_compact = resident_data_bindings.stwo_zig_metal_leaf_absorb_compact;
pub const stwo_zig_metal_parent_seeded = resident_data_bindings.stwo_zig_metal_parent_seeded;
pub const stwo_zig_metal_parent_plain = resident_data_bindings.stwo_zig_metal_parent_plain;
pub const stwo_zig_metal_qm31_to_coordinates = resident_data_bindings.stwo_zig_metal_qm31_to_coordinates;
pub const stwo_zig_metal_felt252_oracle = resident_data_bindings.stwo_zig_metal_felt252_oracle;
pub const stwo_zig_metal_merkle_commit = resident_data_bindings.stwo_zig_metal_merkle_commit;
pub extern fn stwo_zig_metal_compute_quotients(
    runtime: *anyopaque,
    flat_views: [*]const u32,
    flat_views_len: usize,
    raw_columns: [*]const [*]const u32,
    raw_column_lengths: [*]const usize,
    raw_column_count: u32,
    resident_trees: [*]const *anyopaque,
    resident_tree_count: u32,
    views: *const anyopaque,
    view_count: u32,
    raw_views: bool,
    sample_components: [*]const u32,
    linear_terms: [*]const u32,
    batch_count: u32,
    cache_domain: bool,
    domain_log_size: u32,
    domain_initial_index: u32,
    domain_step_size: u32,
    domain_x: ?[*]const u32,
    domain_y: ?[*]const u32,
    row_count: u32,
    output: [*]u32,
    resident_output: ?*anyopaque,
    leaf_seed: ?*const [8]u32,
    node_seed: ?*const [8]u32,
    domain_prefix_bytes: u32,
    fri_line_output: ?*anyopaque,
    fri_coordinates: ?[*]const *anyopaque,
    fri_final_destination: ?*anyopaque,
    fri_layer_count: u32,
    fri_domain_initial_index: u32,
    fri_domain_step_size: u32,
    fri_channel_state: ?*[10]u32,
    fri_trees: ?[*]?*anyopaque,
    fri_inverse_generation_mask: ?*u32,
    fri_stats: ?*CommandEpochStats,
    quotient_work_receipt: ?*QuotientWorkReceipt,
    tree: *?*anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_eval_polynomials(
    runtime: *anyopaque,
    coefficients: [*]const [*]const u32,
    coefficient_lengths: [*]const usize,
    coefficient_column_count: u32,
    coefficient_count: usize,
    factors: [*]const u32,
    factor_word_count: usize,
    basis_tasks: *const anyopaque,
    basis_task_count: u32,
    basis_count: u32,
    tasks: *const anyopaque,
    task_columns: [*]const u32,
    task_count: u32,
    output_count: u32,
    output: [*]u32,
    basis_threadgroup_width: *u32,
    evaluation_threadgroup_width: *u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_circle_transform(
    runtime: *anyopaque,
    columns: [*]const [*]u32,
    column_count: u32,
    log_size: u32,
    twiddles: [*]const u32,
    inverse: bool,
    scale_factor: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_circle_lde(
    runtime: *anyopaque,
    source_columns: [*]const [*]const u32,
    base_columns: [*]const [*]u32,
    transform_words: [*]u32,
    transform_word_count: usize,
    extended_start: u32,
    extended_stride: u32,
    column_count: u32,
    base_log_size: u32,
    extended_log_size: u32,
    inverse_twiddles: [*]const u32,
    forward_twiddles: [*]const u32,
    scale_factor: u32,
    /// Out: which source binding the commit actually took, as
    /// `telemetry.CommitSourceBinding`. Reported from the branch itself so the
    /// no-copy alias can be attributed rather than assumed.
    source_binding: *u32,
    /// Out: actual interpolation normalization batches completed by this
    /// dispatch. Written only after successful command completion.
    normalization_batch_count: *u32,
    /// Out: logical forward FFT layers elided by the executed fused branch.
    forward_skipped_layers: *u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_circle_lde_merkle_commit(
    runtime: *anyopaque,
    source_columns: [*]const [*]const u32,
    base_columns: [*]const [*]u32,
    transform_words: [*]u32,
    transform_word_count: usize,
    extended_start: u32,
    extended_stride: u32,
    column_count: u32,
    base_log_size: u32,
    extended_log_size: u32,
    inverse_twiddles: [*]const u32,
    forward_twiddles: [*]const u32,
    scale_factor: u32,
    coefficients_ready: u32,
    trace_recipe: ?*const [7]u32,
    leaf_seed: *const [8]u32,
    node_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    /// Out: actual interpolation normalization batches completed by this
    /// transaction. Coefficient-form input reports zero.
    normalization_batch_count: *u32,
    /// Out: logical forward FFT layers elided by the executed fused branch.
    forward_skipped_layers: *u32,
    /// Out: internal parent compressions encoded and completed by the device.
    merkle_compressions: *u64,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_recurrence_composition(
    runtime: *anyopaque,
    resident_tree: ?*anyopaque,
    trace_first: [*]const u32,
    row_count: u32,
    column_count: u32,
    column_stride: u32,
    power_words: [*]const u32,
    power_word_count: u32,
    denominator_inverses: *const [2]u32,
    output_words: [*]u32,
    output_word_count: usize,
    inverse_twiddles: [*]const u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
