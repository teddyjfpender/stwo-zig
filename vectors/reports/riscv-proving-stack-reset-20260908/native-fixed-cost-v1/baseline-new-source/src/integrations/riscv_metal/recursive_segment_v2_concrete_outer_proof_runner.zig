//! Metal dependency boundary for the shared small recursive proof runner.
const shared = @import("stwo_riscv_cpu_small_recursion_runner");

pub fn main() !void {
    try shared.runWithMetal(@import("stwo_metal_backend"));
}
