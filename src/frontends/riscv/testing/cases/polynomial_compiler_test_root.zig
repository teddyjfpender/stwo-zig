//! Shared direct polynomial compiler and production materialization consumers.
test {
    _ = @import("stwo_riscv_air_lang");
    _ = @import("air/lang/tests/materialization_direct_program_test.zig");
    _ = @import("air/lang/tests/materialization_fixed_direct_test.zig");
    _ = @import("air/lang/tests/materialization_fixed_cost_test.zig");
    _ = @import("stwo_riscv_memory");
}
