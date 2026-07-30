//! Exact explicit-stream ABI for Cairo's native EC-op witness graph.

pub extern "c" fn ec_op_builtin_witness_on(
    execution_tables: [*]const [*]const u32,
    n_addresses: u32,
    n_big: u32,
    n_small: u32,
    segment_start_source: [*]const u32,
    row_count: u32,
    trace_columns_host: [*]const [*]u32,
    lookup_words: [*]u32,
    partial_input_columns_host: [*]const [*]u32,
    partial_row_count: u32,
    address_counts: [*]u32,
    address_count_words: u32,
    big_counts: [*]u32,
    big_count_words: u32,
    small_counts: [*]u32,
    small_count_words: u32,
    range_check_8_counts: [*]u32,
    range_check_8_count_words: u32,
    stream: *anyopaque,
) c_int;
