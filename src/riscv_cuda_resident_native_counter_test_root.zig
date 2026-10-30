test {
    _ = @import("integrations/riscv_cuda/resident_native_projection_counter_test_v1.zig");
}
comptime {
    _ = @import("integrations/riscv_cuda/resident_native_projection_counter_oracle_v1.zig");
}
