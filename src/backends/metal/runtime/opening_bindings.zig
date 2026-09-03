//! Objective-C ABI declarations for FRI folding, transcripts, and proof openings.

const std = @import("std");
const abi = @import("abi.zig");
const command_epoch = @import("../command_epoch.zig");

const CommandEpochStats = command_epoch.Stats;
const DecommitFriRoundParams = abi.DecommitFriRoundParams;
const DecommitTraceGroupParams = abi.DecommitTraceGroupParams;
const QuotientCoefficientTask = abi.QuotientCoefficientTask;
const QuotientCoefficientTerm = abi.QuotientCoefficientTerm;

pub extern fn stwo_zig_metal_fri_fold_circle(
    runtime: *anyopaque,
    source: [*]const u32,
    source_count: u32,
    inverse_y: ?[*]const u32,
    domain_initial_index: u32,
    domain_step_size: u32,
    alpha: *const [4]u32,
    destination: [*]u32,
    inverse_generated: ?*bool,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_fri_fold_line(
    runtime: *anyopaque,
    source: [*]const u32,
    source_count: u32,
    inverse_x: [*]const u32,
    alpha: *const [4]u32,
    destination: [*]u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_fri_fold_line_and_commit(
    runtime: *anyopaque,
    source: *anyopaque,
    source_count: u32,
    inverse_x: [*]const u32,
    inverse_x_count: u32,
    alphas: [*]const u32,
    fold_count: u32,
    destination: *anyopaque,
    coordinates: *anyopaque,
    leaf_seed: *const [8]u32,
    node_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    hash_family: u32,
    stats: *CommandEpochStats,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_fri_line_cascade(
    runtime: *anyopaque,
    source: *anyopaque,
    source_count: u32,
    circle_source: ?*anyopaque,
    circle_alpha: ?*const [4]u32,
    prior_channel_buffer: ?*anyopaque,
    prior_state_word_offset: u32,
    prior_alpha_word_offset: u32,
    inverse_x: ?[*]const u32,
    inverse_x_count: u32,
    domain_initial_index: u32,
    domain_step_size: u32,
    coordinates: [*]const *anyopaque,
    final_destination: *anyopaque,
    layer_count: u32,
    leaf_seed: *const [8]u32,
    node_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    channel_state: *[10]u32,
    trees: [*]?*anyopaque,
    inverse_generation_mask: ?*u32,
    stats: *CommandEpochStats,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_fri_fold_prepare(
    runtime: *anyopaque,
    source_offset_words: u32,
    inverse_offset_words: u32,
    alpha_offset_words: u32,
    destination_offset_words: u32,
    source_count: u32,
    circle: bool,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_fri_fold_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_quotient_combine_prepare(
    runtime: *anyopaque,
    partial_offsets: [*]const u32,
    partial_logs: [*]const u32,
    sample_count: u32,
    sample_offset: u32,
    linear_offset: u32,
    scratch_offset: u32,
    output_offset: u32,
    row_count: u32,
    log_size: u32,
    initial_index: u32,
    step_size: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_quotient_combine_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_quotient_coefficients_resident(
    runtime: *anyopaque,
    arena: *anyopaque,
    terms: [*]const QuotientCoefficientTerm,
    term_count: u32,
    tasks: [*]const QuotientCoefficientTask,
    task_count: u32,
    row_starts: [*]const u32,
    total_rows: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_fri_round_prepare(
    runtime: *anyopaque,
    twiddle_base: u32,
    twiddle_words: u32,
    input_base: u32,
    input_stride: u32,
    alpha_base: u32,
    output_base: u32,
    output_stride: u32,
    n: u32,
    fold_count: u32,
    first_circle: bool,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_fri_round_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_fri_tree_prepare(
    runtime: *anyopaque,
    evaluation_base: u32,
    coordinate_stride: u32,
    evaluation_size: u32,
    log_rows_per_leaf: u32,
    layer_offsets: [*]const u32,
    layer_count: u32,
    leaf_seed: *const [8]u32,
    node_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_fri_tree_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_fri_final_prepare(
    runtime: *anyopaque,
    evaluation_base: u32,
    coordinate_stride: u32,
    inverse_x: u32,
    coefficient_base: u32,
    degree_error: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_fri_final_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_transcript_init(
    runtime: *anyopaque,
    arena: *anyopaque,
    state_base: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_transcript_mix(
    runtime: *anyopaque,
    arena: *anyopaque,
    state_base: u32,
    source_base: u32,
    source_words: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_transcript_draw_secure(
    runtime: *anyopaque,
    arena: *anyopaque,
    state_base: u32,
    destination_base: u32,
    felt_count: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_transcript_draw_queries(
    runtime: *anyopaque,
    arena: *anyopaque,
    state_base: u32,
    destination_base: u32,
    log_domain_size: u32,
    query_count: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_decommit_normalize_queries(
    runtime: *anyopaque,
    arena: *anyopaque,
    raw_base: u64,
    raw_count: u32,
    log_domain_size: u32,
    unique_base: u64,
    unique_count_base: u64,
    tree_count: u32,
    assembly_base: u64,
    assembly_capacity: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_decommit_prepare_fri_queries(
    runtime: *anyopaque,
    arena: *anyopaque,
    unique_base: u64,
    unique_count_base: u64,
    max_queries: u32,
    cumulative_fold: u32,
    fold_step: u32,
    packed_log: u32,
    tree_queries_base: u64,
    tree_count_base: u64,
    expanded_base: u64,
    expanded_count_base: u64,
    walk_base: u64,
    walk_count_base: u64,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_decommit_prepare_trace_queries(
    runtime: *anyopaque,
    arena: *anyopaque,
    unique_base: u64,
    unique_count_base: u64,
    max_queries: u32,
    source_log: u32,
    tree_log: u32,
    leaf_log: u32,
    unretained: u32,
    mapped_base: u64,
    mapped_count_base: u64,
    walk_base: u64,
    walk_count_base: u64,
    leaves_base: u64,
    leaf_count_base: u64,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_decommit_gather_trace_values(
    runtime: *anyopaque,
    arena: *anyopaque,
    column_offsets_base: u64,
    column_logs_base: u64,
    column_count: u32,
    lifting_log: u32,
    queries_base: u64,
    query_count_base: u64,
    max_queries: u32,
    first_column: u32,
    stride: u32,
    output_base: u64,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_decommit_gather_fri_values(
    runtime: *anyopaque,
    arena: *anyopaque,
    coordinate_bases: u64,
    positions_base: u64,
    count_base: u64,
    max_positions: u32,
    values_base: u64,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_decommit_assemble_fri(
    runtime: *anyopaque,
    arena: *anyopaque,
    tree_index: u32,
    leaf_log: u32,
    tree_queries: u64,
    tree_count_at: u64,
    expanded: u64,
    expanded_count_at: u64,
    values: u64,
    walk: u64,
    scratch: u64,
    walk_count_at: u64,
    retained_offsets: u64,
    assembly: u64,
    capacity: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_decommit_fri_round(
    runtime: *anyopaque,
    arena: *anyopaque,
    params: *const DecommitFriRoundParams,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_decommit_sparse_parent(
    runtime: *anyopaque,
    arena: *anyopaque,
    child_indices: u64,
    child_hashes: u64,
    child_count_at: u64,
    max_child_count: u32,
    parent_indices: u64,
    parent_hashes: u64,
    parent_count_at: u64,
    node_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_decommit_sparse_leaves(
    runtime: *anyopaque,
    arena: *anyopaque,
    column_offsets: u64,
    column_logs: u64,
    column_count: u32,
    lifting_log: u32,
    leaf_indices: u64,
    leaf_count_at: u64,
    max_leaf_count: u32,
    output_hashes: u64,
    leaf_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_decommit_sparse_leaf_group(
    runtime: *anyopaque,
    arena: *anyopaque,
    column_offsets: u64,
    column_logs: u64,
    column_count: u32,
    first_column: u32,
    total_columns: u32,
    lifting_log: u32,
    leaf_indices: u64,
    leaf_count_at: u64,
    max_leaf_count: u32,
    output_hashes: u64,
    leaf_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_decommit_trace_group(
    runtime: *anyopaque,
    arena: *anyopaque,
    params: *const DecommitTraceGroupParams,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_decommit_assemble_trace(
    runtime: *anyopaque,
    arena: *anyopaque,
    tree_index: u32,
    role: u32,
    leaf_log: u32,
    first_retained_log: u32,
    column_count: u32,
    mapped: u64,
    mapped_count_at: u64,
    max_queries: u32,
    walk: u64,
    scratch: u64,
    walk_count_at: u64,
    values: u64,
    retained_offsets: u64,
    sparse_indices: u64,
    sparse_hashes: u64,
    sparse_offsets: u64,
    sparse_counts: u64,
    sparse_level_count: u32,
    assembly: u64,
    capacity: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;

test "opening bindings retain canonical shared ABI parameter types" {
    const fold_commit = @typeInfo(@TypeOf(stwo_zig_metal_fri_fold_line_and_commit)).@"fn";
    try std.testing.expectEqual(@as(usize, 15), fold_commit.params.len);
    try std.testing.expect(fold_commit.params[12].type.? == *CommandEpochStats);
    try std.testing.expect(fold_commit.return_type.? == ?*anyopaque);

    const cascade = @typeInfo(@TypeOf(stwo_zig_metal_fri_line_cascade)).@"fn";
    try std.testing.expectEqual(@as(usize, 19), cascade.params.len);
    try std.testing.expect(cascade.params[16].type.? == *CommandEpochStats);
    try std.testing.expect(cascade.return_type.? == bool);

    const quotient = @typeInfo(@TypeOf(stwo_zig_metal_quotient_coefficients_resident)).@"fn";
    try std.testing.expect(quotient.params[2].type.? == [*]const QuotientCoefficientTerm);
    try std.testing.expect(quotient.params[4].type.? == [*]const QuotientCoefficientTask);

    const fri_round = @typeInfo(@TypeOf(stwo_zig_metal_decommit_fri_round)).@"fn";
    try std.testing.expect(fri_round.params[2].type.? == *const DecommitFriRoundParams);
    const trace_group = @typeInfo(@TypeOf(stwo_zig_metal_decommit_trace_group)).@"fn";
    try std.testing.expect(trace_group.params[2].type.? == *const DecommitTraceGroupParams);
}
