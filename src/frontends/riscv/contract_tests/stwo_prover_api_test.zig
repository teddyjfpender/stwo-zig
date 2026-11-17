//! Consumer-owned laws selected for the stwo_riscv_frontend boundary.
const provider = @import("stwo_prover_api");
const laws = @import("waist_consumer_laws");

test "cdc: stwo_riscv_frontend request ownership and invalid input laws" {
    try laws.stageOwnership(provider);
}
