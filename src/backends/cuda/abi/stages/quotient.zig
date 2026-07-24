//! Resident quotient-numerator and quotient-combination entry points.

const field = @import("../field.zig");

pub extern "c" fn stwo_prepare_quotient_numerator_terms_on(
    term_descriptors: [*]const u32,
    term_count: u32,
    sample_points: [*]const u32,
    sample_values: [*]const field.SecureField,
    random_coefficient: *const field.SecureField,
    term_points: [*]u32,
    line_coefficients: [*]field.SecureField,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_finalize_quotient_numerator_groups_on(
    group_offsets: [*]const u32,
    group_term_indices: [*]const u32,
    group_count: u32,
    term_points: [*]const u32,
    line_coefficients: [*]field.SecureField,
    sample_points: [*]u32,
    first_linear_terms: [*]field.SecureField,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_zero_quotient_numerator_outputs_on(
    group_log_sizes: [*]const u32,
    group_count: u32,
    max_output_size: u32,
    outputs_0: *const [*]u32,
    outputs_1: *const [*]u32,
    outputs_2: *const [*]u32,
    outputs_3: *const [*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_accumulate_quotient_numerator_single_write_on(
    group_offsets: [*]const u32,
    term_descriptors: [*]const u32,
    group_count: u32,
    max_output_size: u32,
    source_evaluations: *const [*]const u32,
    line_coefficients: [*]const field.SecureField,
    group_log_sizes: [*]const u32,
    outputs_0: *const [*]u32,
    outputs_1: *const [*]u32,
    outputs_2: *const [*]u32,
    outputs_3: *const [*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_combine_quotients_from_numerators_on(
    half_coset_initial_index: u32,
    half_coset_step_size: u32,
    domain_size: u32,
    domain_log_size: u32,
    sample_points: [*]const u32,
    sample_size: u32,
    first_linear_term_accumulators: [*]const field.SecureField,
    partial_numerator_log_sizes: [*]const u32,
    partial_numerators_0: *const [*]const u32,
    partial_numerators_1: *const [*]const u32,
    partial_numerators_2: *const [*]const u32,
    partial_numerators_3: *const [*]const u32,
    result_column_0: [*]u32,
    result_column_1: [*]u32,
    result_column_2: [*]u32,
    result_column_3: [*]u32,
    stream: *anyopaque,
) c_int;
