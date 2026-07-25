//! Allocation-free Cairo witness construction on the proof-owned stream.

pub extern "c" fn stwo_witness_casm_input_scatter_on(
    rows: [*]const u32,
    real_rows: u32,
    consumer_rows: u32,
    pc: [*]u32,
    ap: [*]u32,
    fp: [*]u32,
    enabler: [*]u32,
    iota: ?[*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_witness_input_seed_contiguous_on(
    scalars: [*]const u32,
    scalar_count: u32,
    real_rows: u32,
    consumer_rows: u32,
    outputs: [*]u32,
    output_stride_words: usize,
    output_capacity_words: usize,
    include_enabler: u32,
    include_iota: u32,
    stream: *anyopaque,
) c_int;
