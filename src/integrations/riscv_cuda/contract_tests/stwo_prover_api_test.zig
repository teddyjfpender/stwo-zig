//! Consumer-owned laws selected for the stwo_riscv_cuda_integration boundary.
const provider = @import("stwo_prover_api");
const laws = @import("waist_consumer_laws");

test "cdc: stwo_riscv_cuda_integration request ownership and invalid input laws" {
    try laws.column(provider);
    try laws.diagnostic(provider);
    try laws.logicalWork(provider);
}
