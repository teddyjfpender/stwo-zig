//! Allocation-free heterogeneous composition lift on one proof stream.

pub extern "c" fn stwo_composition_lift_accumulate_on(
    previous_coordinates: [*]const u32,
    previous_log_size: u32,
    current_coordinates: [*]u32,
    current_log_size: u32,
    stream: *anyopaque,
) c_int;
