//! Consumer-owned laws selected for the stwo_riscv_recursion boundary.
const provider = @import("stwo_prover_api");
const laws = @import("waist_consumer_laws");

test "cdc: stwo_riscv_recursion request ownership and invalid input laws" {
    try laws.diagnostic(provider);
    try laws.column(provider);
}
