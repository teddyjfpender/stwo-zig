//! Consumer-owned laws selected for the stwo_riscv_rv32 boundary.
const provider = @import("stwo_prover_api");
const laws = @import("waist_consumer_laws");

test "cdc: stwo_riscv_rv32 request ownership and invalid input laws" {
    try laws.stageOwnership(provider);
    try laws.column(provider);
}
