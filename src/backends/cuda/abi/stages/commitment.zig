//! Allocation-free Blake2s commitment entry points.

const field = @import("../field.zig");

pub extern "c" fn stwo_blake2s_progressive_init_on(
    size: u32,
    states: [*]field.ProgressiveBlake2sState,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_progressive_absorb_on(
    size: u32,
    number_of_columns: u32,
    absorbed_columns_before: u32,
    columns: *const [*]u32,
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
    coordinate_columns: *const [*]u32,
    log_rows_per_leaf: u32,
    result: [*]field.Blake2sHash,
    stream: *anyopaque,
) c_int;
