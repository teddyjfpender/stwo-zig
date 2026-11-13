//! Consumer-owned laws selected for the stwo_metal_backend boundary.
const provider = @import("stwo_prover_api");
const laws = @import("waist_consumer_laws");
const consumer = @import("stwo_metal_backend");
comptime {
    provider.assertProverEngine(consumer.MetalProverEngine);
    provider.assertProverEngine(consumer.PlainMetalProverEngine);
}

test "cdc: stwo_metal_backend request ownership and invalid input laws" {
    try laws.column(provider);
    try laws.diagnostic(provider);
    try laws.logicalWork(provider);
}
