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
