//! Consumer-owned laws selected for the stwo_circuit_metal_integration boundary.
const provider = @import("stwo_prover_api");
const laws = @import("waist_consumer_laws");
const consumer = @import("stwo_circuit_metal_integration");
comptime {
    provider.assertProverEngine(consumer.Internal.Engine);
    provider.assertProverEngine(consumer.Root.Engine);
}

test "cdc: stwo_circuit_metal_integration request ownership and invalid input laws" {
    try laws.column(provider);
    try laws.diagnostic(provider);
    try laws.logicalWork(provider);
}
