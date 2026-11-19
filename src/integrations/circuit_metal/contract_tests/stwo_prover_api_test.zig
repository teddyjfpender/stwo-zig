//! Consumer-owned laws selected for the stwo_circuit_metal_integration boundary.
const provider = @import("stwo_prover_api");
const laws = @import("waist_consumer_laws");
const consumer = @import("stwo_circuit_metal_integration");
test "cdc: stwo_circuit_metal_integration request ownership and invalid input laws" {
    // Resolving the native engine signatures requires the linked Metal runtime.
    if (comptime @import("builtin").os.tag == .macos) {
        comptime provider.assertProverEngine(consumer.Internal.Engine);
        comptime provider.assertProverEngine(consumer.Root.Engine);
    }
    try laws.column(provider);
    try laws.diagnostic(provider);
    try laws.logicalWork(provider);
}
