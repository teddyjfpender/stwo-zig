//! Consumer-owned laws selected for the stwo_riscv_cpu_integration boundary.
const provider = @import("stwo_prover_api");
const laws = @import("waist_consumer_laws");
const consumer = @import("stwo_riscv_cpu_integration");
comptime {
    provider.assertProverEngine(consumer.CpuProverEngine);
}

test "cdc: stwo_riscv_cpu_integration request ownership and invalid input laws" {
    try laws.column(provider);
    try laws.diagnostic(provider);
    try laws.logicalWork(provider);
}
