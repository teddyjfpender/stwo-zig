//! Allocation-free secure-composition split on an explicit proof stream.

pub extern "c" fn stwo_ntt_b2n_composition_split_compact_on(
    coordinate_values: [*]u32,
    coordinate_capacity_words: usize,
    coordinate_stride_words: usize,
    coefficients: [*]u32,
    coefficient_capacity_words: usize,
    coefficient_stride_words: usize,
    log_n: u32,
    inverse_twiddles: [*]const u32,
    inverse_twiddle_words: u32,
    evaluation_domain_size: u32,
    stream: *anyopaque,
) c_int;
