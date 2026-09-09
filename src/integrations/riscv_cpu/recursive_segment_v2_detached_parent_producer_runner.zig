//! Maintained CLI, with all implementation owned by the integration module.
pub fn main() !void {
    return @import("stwo_riscv_cpu_integration").recursive_segment_v2_detached_parent_producer.main();
}
