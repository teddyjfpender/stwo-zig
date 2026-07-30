//! Allocation-free Native trace construction on the proof-owned stream.

pub extern "c" fn stwo_native_wide_fibonacci_trace_on(
    trace: [*]u32,
    column_stride_words: usize,
    trace_capacity_words: usize,
    row_count: u32,
    log_n_rows: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_native_xor_trace_on(
    preprocessed: [*]u32,
    preprocessed_stride_words: usize,
    preprocessed_capacity_words: usize,
    main_trace: [*]u32,
    main_stride_words: usize,
    main_capacity_words: usize,
    row_count: u32,
    log_n_rows: u32,
    log_step: u32,
    offset: u64,
    stream: *anyopaque,
) c_int;
