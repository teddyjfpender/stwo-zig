//! Canonical CPU entry for the shared detached parent producer.
pub fn main() !void {
    return @import("stwo_riscv_detached_parent_producer").main();
}
