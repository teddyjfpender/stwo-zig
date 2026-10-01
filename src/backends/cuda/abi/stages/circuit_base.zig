//! Resident circuit gate base trace and table multiplicities.
pub extern "c" fn stwo_circuit_base_witness_on(
    component: u32,
    values: [*]const u32,
    value_count: u32,
    row_count: u32,
    first_permutation_row: u32,
    pp_host: [*]const [*]const u32,
    pp_count: u32,
    out_host: [*]const [*]u32,
    out_count: u32,
    counts_host: [*]const [*]u32,
    count_count: u32,
    error_flag: [*]u32,
    stream: *anyopaque,
) c_int;
