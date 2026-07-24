//! Allocation-free circle transform entry points on an explicit proof stream.

pub extern "c" fn stwo_ntt_b2n_columns_to_retained_on(
    inputs: [*]const u32,
    input_column_stride_words: usize,
    retained_outputs: [*]u32,
    output_column_stride_words: usize,
    log_n: u32,
    num_poly: u32,
    twiddles: [*]const u32,
    twiddle_words: u32,
    evaluation_domain_size: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_ntt_n2b_columns_on(
    device_values: [*]u32,
    column_stride_words: usize,
    log_n: u32,
    num_poly: u32,
    twiddles: [*]const u32,
    twiddle_words: u32,
    evaluation_domain_size: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_lde_n2b_columns_on(
    coefficient_values: [*]const u32,
    coefficient_column_stride_words: usize,
    coefficient_log_sizes: [*]const u32,
    device_values: [*]u32,
    evaluation_column_stride_words: usize,
    log_n: u32,
    num_poly: u32,
    twiddles: [*]const u32,
    twiddle_words: u32,
    evaluation_domain_size: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_lde_n2b_columns_before_circle_on(
    coefficient_values: [*]const u32,
    coefficient_column_stride_words: usize,
    coefficient_log_sizes: [*]const u32,
    device_values: [*]u32,
    evaluation_column_stride_words: usize,
    log_n: u32,
    num_poly: u32,
    twiddles: [*]const u32,
    twiddle_words: u32,
    evaluation_domain_size: u32,
    stream: *anyopaque,
) c_int;
