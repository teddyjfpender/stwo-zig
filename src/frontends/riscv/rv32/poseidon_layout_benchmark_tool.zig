//! Package-root executable boundary for the isolated H-010 benchmark.

pub fn main() void {
    @import("stwo_riscv_memory").typed_poseidon_layout_benchmark_command.main();
}
