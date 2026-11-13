//! Concrete Ethereum producer binding; all shared proof records stay native-owned.
pub const Coordinator = @import("stwo_riscv_cpu_integration").rv64_gkr_coordinator.ForEarlySources(
    @import("early_cpu0.zig").Owner,
    @import("early_segments.zig").Owner,
);
