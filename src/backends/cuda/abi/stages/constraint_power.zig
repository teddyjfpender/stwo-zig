//! Allocation-free challenge-power expansion for Native constraints.

const field = @import("../field.zig");

pub extern "c" fn stwo_constraint_expand_powers_on(
    alpha: *const field.SecureField,
    output: [*]field.SecureField,
    output_capacity: usize,
    count: u32,
    stream: *anyopaque,
) c_int;
