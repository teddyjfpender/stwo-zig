//! Allocation-free Cairo fixed-table and memory base-trace construction.

pub extern "c" fn stwo_fixed_table_materialize_on(
    source_columns: ?[*]const u64,
    multiplicity_columns: [*]const u64,
    trace_multiplicity_columns: [*]const u32,
    trace_outputs: [*]const u64,
    trace_output_count: u32,
    lookup_descriptors: [*]const u32,
    lookup_outputs: [*]const u64,
    lookup_output_count: u32,
    row_count: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_cairo_memory_split_big_on(
    values: ?[*]const u32,
    value_count: u32,
    row_count: u32,
    outputs_host: [*]const [*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_cairo_memory_split_small_on(
    values: ?[*]const u32,
    value_count: u32,
    row_count: u32,
    outputs_host: [*]const [*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_cairo_memory_address_base_on(
    address_ids: [*]const u32,
    address_id_words: u32,
    multiplicities: [*]const u32,
    multiplicity_words: u32,
    row_count: u32,
    outputs_host: [*]const [*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_cairo_memory_value_base_on(
    sources_host: [*]const [*]const u32,
    limb_count: u32,
    source_words: u32,
    multiplicities: [*]const u32,
    multiplicity_words: u32,
    row_count: u32,
    outputs_host: [*]const [*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_cairo_memory_range_check_9_9_on(
    limbs_host: [*]const [*]const u32,
    pair_count: u32,
    row_count: u32,
    input_to_row: [*]const u32,
    table_rows: u32,
    counts: [*]u32,
    count_words: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_witness_feed_counts_on(
    sub_words: [*]const u32,
    column_length: u32,
    descriptors: [*]const u32,
    descriptor_count: u32,
    luts: [*]const u64,
    destinations: [*]const u64,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_witness_feed_clear_on(
    destinations: [*]const u64,
    lengths: [*]const u32,
    destination_count: u32,
    maximum_words: u32,
    stream: *anyopaque,
) c_int;
