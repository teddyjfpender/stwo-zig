//! Resident FRI folding, terminal interpolation, and PoW entry points.

const field = @import("../field.zig");

pub extern "c" fn stwo_fold_circle_into_line_on(
    domain: [*]const u32,
    domain_words: usize,
    twiddle_offset: u32,
    size: u32,
    evaluation_values: [*]const u32,
    evaluation_words: usize,
    evaluation_stride: u32,
    alpha: *const field.SecureField,
    alpha_squarings: u32,
    folded_values: [*]u32,
    folded_words: usize,
    folded_stride: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_fold_line_on(
    domain: [*]const u32,
    domain_words: usize,
    twiddle_offset: u32,
    size: u32,
    evaluation_values: [*]const u32,
    evaluation_words: usize,
    evaluation_stride: u32,
    alpha: *const field.SecureField,
    alpha_squarings: u32,
    folded_values: [*]u32,
    folded_words: usize,
    folded_stride: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_fri_fold_fused3_on(
    domain: [*]const u32,
    domain_words: usize,
    twiddle_offset_0: u32,
    twiddle_offset_1: u32,
    twiddle_offset_2: u32,
    size: u32,
    first_fold_is_circle: u32,
    evaluation_values: [*]const u32,
    evaluation_words: usize,
    evaluation_stride: u32,
    alpha: *const field.SecureField,
    folded_values: [*]u32,
    folded_words: usize,
    folded_stride: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_fri_last_layer_on(
    evaluation: [*]const u32,
    evaluation_words: usize,
    evaluation_stride: u32,
    log_size: u32,
    inverse_twiddles: [*]const u32,
    inverse_twiddle_words: u32,
    log_degree_bound: u32,
    coefficients: [*]u32,
    coefficient_words: usize,
    degree_error: [*]u32,
    degree_error_words: usize,
    transcript_coefficients: [*]u32,
    transcript_words: usize,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_pow_persistent_on(
    transcript_state: [*]const u32,
    pow_bits: u32,
    search_end: u64,
    prefix_digest: [*]u32,
    best_nonce: *u64,
    completed_blocks: [*]u32,
    transcript_nonce: [*]u32,
    stream: *anyopaque,
) c_int;
