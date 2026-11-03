//! Independent receiver entry: the native authority loader with no GPU factory.
//! No CUDA module is imported or initialized by this executable.
pub fn main() !void {
    return @import("stwo_riscv_cpu_integration").rv64_ethereum_gkr_main.mainWithRecursion();
}
