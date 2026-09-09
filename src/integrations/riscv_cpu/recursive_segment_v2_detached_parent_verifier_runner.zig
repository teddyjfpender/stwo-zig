//! Standalone verifier; protocol implementation is owned by the integration.
pub fn main() !void {
    return @import("stwo_riscv_cpu_integration").recursive_segment_v2_detached_parent_command.main();
}
