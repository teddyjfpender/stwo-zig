//! Allocation-free Native trace construction on the proof-owned stream.

pub extern "c" fn stwo_native_wide_fibonacci_trace_on(
    trace: [*]u32,
    trace_words: usize,
    row_count: u32,
    sequence_len: u32,
    log_n_rows: u32,
    stream: *anyopaque,
) c_int;
