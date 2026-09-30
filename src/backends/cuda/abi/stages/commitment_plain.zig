//! Canonical plain BLAKE2s commitment ABI used by pinned Stwo-Cairo.

const field = @import("../field.zig");
pub const MixedSegment = @import("commitment.zig").MixedSegment;
pub const max_mixed_segments = @import("commitment.zig").max_mixed_segments;

pub extern "c" fn stwo_blake2s_mixed_leaf_plain_on(
    size: u32,
    count: u32,
    segments: [*]const MixedSegment,
    result: [*]field.Blake2sHash,
    stream: *anyopaque,
) c_int;
pub const stwo_blake2s_mixed_leaf_on = stwo_blake2s_mixed_leaf_plain_on;
pub extern "c" fn stwo_blake2s_mixed_seeded_plain_on(
    size: u32,
    count: u32,
    segments: [*]const MixedSegment,
    absorbed_before: u32,
    seed_size: u32,
    seed: ?[*]const field.ProgressiveBlake2sState,
    prefix: ?[*]field.ProgressiveBlake2sState,
    result: ?[*]field.Blake2sHash,
    stream: *anyopaque,
) c_int;
pub const stwo_blake2s_mixed_seeded_on = stwo_blake2s_mixed_seeded_plain_on;

pub extern "c" fn stwo_blake2s_contiguous_leaf_plain_on(
    size: u32,
    columns: [*]const u32,
    column_stride_words: usize,
    column_capacity_words: usize,
    result: [*]field.Blake2sHash,
    stream: *anyopaque,
) c_int;

pub const stwo_blake2s_contiguous_leaf_on = stwo_blake2s_contiguous_leaf_plain_on;

pub extern "c" fn stwo_blake2s_contiguous_tail_plain_on(
    previous_layer: [*]const field.Blake2sHash,
    previous_size: u32,
    output_levels: [*]field.Blake2sHash,
    output_capacity: usize,
    level_count: u32,
    stream: *anyopaque,
) c_int;

pub const stwo_blake2s_contiguous_tail_on = stwo_blake2s_contiguous_tail_plain_on;

pub extern "c" fn stwo_blake2s_fri_leaf_plain_on(
    evaluation_size: u32,
    coordinate_columns: [*]const u32,
    coordinate_stride_words: usize,
    coordinate_capacity_words: usize,
    log_rows_per_leaf: u32,
    result: [*]field.Blake2sHash,
    stream: *anyopaque,
) c_int;

pub const stwo_blake2s_fri_leaf_on = stwo_blake2s_fri_leaf_plain_on;

pub extern "c" fn stwo_blake2s_interior4_plain_on(
    previous_layer: [*]const field.Blake2sHash,
    output_size: u32,
    result: [*]field.Blake2sHash,
    stream: *anyopaque,
) c_int;

pub const stwo_blake2s_interior4_on = stwo_blake2s_interior4_plain_on;

pub extern "c" fn stwo_blake2s_layer_plain_on(
    previous_layer: [*]const field.Blake2sHash,
    output_size: u32,
    result: [*]field.Blake2sHash,
    stream: *anyopaque,
) c_int;

pub const stwo_blake2s_layer_on = stwo_blake2s_layer_plain_on;

pub extern "c" fn stwo_blake2s_progressive_absorb_lifted_plain_on(
    size: u32,
    source_size: u32,
    absorbed_columns_before: u32,
    columns: [*]const u32,
    column_stride_words: usize,
    column_capacity_words: usize,
    states: [*]field.ProgressiveBlake2sState,
    stream: *anyopaque,
) c_int;

pub const stwo_blake2s_progressive_absorb_lifted_on = stwo_blake2s_progressive_absorb_lifted_plain_on;

pub extern "c" fn stwo_blake2s_progressive_absorb_plain_on(
    size: u32,
    absorbed_columns_before: u32,
    columns: [*]const u32,
    column_stride_words: usize,
    column_capacity_words: usize,
    states: [*]field.ProgressiveBlake2sState,
    stream: *anyopaque,
) c_int;

pub const stwo_blake2s_progressive_absorb_on = stwo_blake2s_progressive_absorb_plain_on;

pub extern "c" fn stwo_blake2s_progressive_finalize_plain_on(
    size: u32,
    absorbed_columns: u32,
    states: [*]const field.ProgressiveBlake2sState,
    result: [*]field.Blake2sHash,
    stream: *anyopaque,
) c_int;

pub const stwo_blake2s_progressive_finalize_on = stwo_blake2s_progressive_finalize_plain_on;

pub extern "c" fn stwo_blake2s_progressive_init_plain_on(
    size: u32,
    states: [*]field.ProgressiveBlake2sState,
    stream: *anyopaque,
) c_int;

pub const stwo_blake2s_progressive_init_on = stwo_blake2s_progressive_init_plain_on;
