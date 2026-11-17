//! Consumer-owned laws selected for the stwo_ethereum_statement boundary.
const provider = @import("stwo_prover_api");
const laws = @import("waist_consumer_laws");

test "cdc: stwo_ethereum_statement request ownership and invalid input laws" {
    try laws.column(provider);
    try laws.diagnostic(provider);
    try laws.logicalWork(provider);
}
