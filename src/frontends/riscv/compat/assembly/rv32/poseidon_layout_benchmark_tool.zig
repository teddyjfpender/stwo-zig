//! Package-root executable boundary for the isolated H-010 benchmark.

pub fn main() void {
    @import("stwo_riscv_memory").testing.proposals.poseidon_layout_benchmark_command.main();
}
