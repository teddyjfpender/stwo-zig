//! Resident trace and FRI opening assembly entry points.

const field = @import("../field.zig");

pub extern "c" fn stwo_decommit_normalize_queries_on(
    raw_queries: [*]const u32,
    raw_query_count: u32,
    query_log_size: u32,
    tree_count: u32,
    unique_queries: [*]u32,
    unique_count: [*]u32,
    assembly: [*]u32,
    assembly_capacity_words: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_decommit_prepare_trace_queries_on(
    unique_queries: [*]const u32,
    unique_count: [*]const u32,
    max_queries: u32,
    source_log_size: u32,
    tree_log_size: u32,
    leaf_log_size: u32,
    unretained_bottom_layers: u32,
    mapped_queries: [*]u32,
    mapped_count: [*]u32,
    walk_queries: [*]u32,
    walk_count: [*]u32,
    leaf_indices: [*]u32,
    leaf_count: [*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_decommit_pack_trace_group_on(
    tree_index: u32,
    total_column_count: u32,
    first_column: u32,
    group_column_count: u32,
    columns: *const [*]const u32,
    column_log_sizes: [*]const u32,
    lifting_log_size: u32,
    mapped_queries: [*]const u32,
    mapped_count: [*]const u32,
    max_queries: u32,
    assembly: [*]u32,
    assembly_capacity_words: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_decommit_sparse_parent_on(
    child_indices: [*]const u32,
    child_hashes: [*]const field.Blake2sHash,
    child_count: [*]const u32,
    max_child_count: u32,
    parent_indices: [*]u32,
    parent_hashes: [*]field.Blake2sHash,
    parent_count: [*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_decommit_assemble_trace_on(
    tree_index: u32,
    tree_role: u32,
    leaf_log_size: u32,
    first_retained_log_size: u32,
    column_count: u32,
    mapped_count: [*]const u32,
    max_queries: u32,
    walk_queries: [*]u32,
    walk_scratch: [*]u32,
    walk_count: [*]const u32,
    retained_layers_by_log: *const [*]const field.Blake2sHash,
    sparse_indices: [*]const u32,
    sparse_hashes: [*]const field.Blake2sHash,
    sparse_level_offsets: [*]const u32,
    sparse_level_counts: [*]const u32,
    sparse_level_count: u32,
    assembly: [*]u32,
    assembly_capacity_words: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_decommit_prepare_fri_queries_on(
    unique_queries: [*]const u32,
    unique_count: [*]const u32,
    max_queries: u32,
    cumulative_fold: u32,
    fold_step: u32,
    log_rows_per_leaf: u32,
    tree_queries: [*]u32,
    tree_query_count: [*]u32,
    expanded_positions: [*]u32,
    expanded_count: [*]u32,
    walk_queries: [*]u32,
    walk_count: [*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_decommit_assemble_fri_on(
    tree_index: u32,
    leaf_log_size: u32,
    tree_queries: [*]const u32,
    tree_query_count: [*]const u32,
    expanded_positions: [*]const u32,
    expanded_count: [*]const u32,
    coordinate_columns: *const [*]const u32,
    walk_queries: [*]u32,
    walk_scratch: [*]u32,
    walk_count: [*]const u32,
    retained_layers_by_log: *const [*]const field.Blake2sHash,
    assembly: [*]u32,
    assembly_capacity_words: u32,
    stream: *anyopaque,
) c_int;
