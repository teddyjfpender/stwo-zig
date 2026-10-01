const field = @import("../field.zig");

pub extern "c" fn stwo_circuit_lookup_sum_on(
    claimed_sums: [*]const field.SecureField,
    output_values: ?[*]const field.SecureField,
    output_count: u32,
    alpha_powers: [*]const field.SecureField,
    power_count: u32,
    z: [*]const field.SecureField,
    error_flag: [*]u32,
    stream: *anyopaque,
) c_int;
