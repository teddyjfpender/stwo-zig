test {
    _ = @import("rv64/immutable_setup.zig");
    _ = @import("rv64/resident_router.zig");
    _ = @import("stwo_riscv_cpu_integration").rv64_gkr_cpu_worker.DeviceGlobal;
    _ = @import("stwo_riscv_cpu_integration").rv64_memory_input;
}
