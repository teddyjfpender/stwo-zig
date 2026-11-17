//! Consumer-owned laws selected for the stwo_riscv_memory boundary.
const provider = @import("stwo_prover_api");
const laws = @import("waist_consumer_laws");

test "cdc: stwo_riscv_memory request ownership and invalid input laws" {
    try laws.logicalWork(provider);
}
