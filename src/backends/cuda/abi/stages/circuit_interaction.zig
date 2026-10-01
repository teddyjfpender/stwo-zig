//! Paired circuit LogUp fractions before shared CUDA relation completion.
const field = @import("../field.zig");

pub extern "c" fn stwo_circuit_interaction_fractions_on(
    component: u32,
    rows: u32,
    pp_host: [*]const [*]const u32,
    pp_count: u32,
    base_host: [*]const [*]const u32,
    base_count: u32,
    out_host: [*]const [*]u32,
    out_count: u32,
    powers: [*]const field.SecureField,
    power_count: u32,
    z: [*]const field.SecureField,
    denominators: [*]field.SecureField,
    denominator_count: u32,
    error_flag: [*]u32,
    stream: *anyopaque,
) c_int;
