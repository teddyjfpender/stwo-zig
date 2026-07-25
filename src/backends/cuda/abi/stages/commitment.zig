//! Allocation-free Blake2s commitment entry points.

const field = @import("../field.zig");

pub extern "c" fn stwo_blake2s_contiguous_leaf_on(
    size: u32,
    columns: [*]const u32,
    column_stride_words: usize,
    column_capacity_words: usize,
    result: [*]field.Blake2sHash,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_contiguous_tail_on(
    previous_layer: [*]const field.Blake2sHash,
    previous_size: u32,
    output_levels: [*]field.Blake2sHash,
    output_capacity: usize,
    level_count: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_progressive_init_on(
    size: u32,
    states: [*]field.ProgressiveBlake2sState,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_progressive_absorb_on(
    size: u32,
    absorbed_columns_before: u32,
    columns: [*]const u32,
    column_stride_words: usize,
    column_capacity_words: usize,
    states: [*]field.ProgressiveBlake2sState,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_progressive_absorb_lifted_on(
    size: u32,
    source_size: u32,
    absorbed_columns_before: u32,
    columns: [*]const u32,
    column_stride_words: usize,
    column_capacity_words: usize,
    states: [*]field.ProgressiveBlake2sState,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_progressive_finalize_on(
    size: u32,
    absorbed_columns: u32,
    states: [*]const field.ProgressiveBlake2sState,
    result: [*]field.Blake2sHash,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_layer_on(
    previous_layer: [*]const field.Blake2sHash,
    output_size: u32,
    result: [*]field.Blake2sHash,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_interior4_on(
    previous_layer: [*]const field.Blake2sHash,
    output_size: u32,
    result: [*]field.Blake2sHash,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_fri_leaf_on(
    evaluation_size: u32,
    coordinate_columns: [*]const u32,
    coordinate_stride_words: usize,
    coordinate_capacity_words: usize,
    log_rows_per_leaf: u32,
    result: [*]field.Blake2sHash,
    stream: *anyopaque,
) c_int;
