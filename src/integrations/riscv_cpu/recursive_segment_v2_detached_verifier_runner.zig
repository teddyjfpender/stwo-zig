//! Standalone consumer: fixed-key pin, expected public wire, claims and proof.
pub fn main() !void {
    return @import("stwo_riscv_cpu_integration").recursive_segment_v2_detached_command.main();
}
