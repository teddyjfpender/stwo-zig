//! Allocation-free out-of-domain sampling entry points.

const field = @import("../field.zig");

pub extern "c" fn stwo_oods_derive_points_on(
    oods_parameter: *const field.SecureField,
    offset_points: [*]const field.CirclePointBaseField,
    fold_counts: [*]const u32,
    output_indices: [*]const u32,
    sample_count: u32,
    coefficient_log_size: u32,
    sample_points: [*]u32,
    evaluation_points: [*]u32,
    folding_factors: [*]field.SecureField,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_oods_eval_first_on(
    coefficients: *const [*]const u32,
    coefficient_size: u32,
    sample_count: u32,
    folding_factors: [*]const field.SecureField,
    scratch: [*]field.SecureField,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_oods_eval_reduce_on(
    input: [*]const field.SecureField,
    input_size: u32,
    input_stride: u32,
    factor_index: u32,
    coefficient_log_size: u32,
    sample_count: u32,
    folding_factors: [*]const field.SecureField,
    output: [*]field.SecureField,
    output_stride: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_oods_store_results_on(
    reduced: [*]const field.SecureField,
    reduced_stride: u32,
    output_indices: [*]const u32,
    sample_count: u32,
    sampled_values: [*]field.SecureField,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_oods_barycentric_weights_on(
    half_coset_initial_index: u32,
    half_coset_step_size: u32,
    size: u32,
    log_size: u32,
    evaluation_point: [*]const u32,
    si0: field.SecureField,
    vanishing_rotation: field.CirclePointBaseField,
    numerator_inverses: [*]field.SecureField,
    weights: [*]field.SecureField,
    scales: [*]field.SecureField,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_oods_barycentric_eval_many_on(
    columns: *const [*]const u32,
    column_count: u32,
    weights: [*]const field.SecureField,
    size: u32,
    partial_sums: [*]field.SecureField,
    reduction_blocks: u32,
    output_indices: [*]const u32,
    sampled_values: [*]field.SecureField,
    stream: *anyopaque,
) c_int;
