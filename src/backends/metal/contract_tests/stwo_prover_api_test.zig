//! Consumer-owned laws selected for the stwo_metal_backend boundary.
const provider = @import("stwo_prover_api");
const laws = @import("waist_consumer_laws");
const consumer = @import("stwo_metal_backend");
test "cdc: stwo_metal_backend request ownership and invalid input laws" {
    // Resolving the native engine signatures requires the linked Metal runtime.
    if (comptime @import("builtin").os.tag == .macos) {
        comptime provider.assertProverEngine(consumer.MetalProverEngine);
        comptime provider.assertProverEngine(consumer.PlainMetalProverEngine);
    }
    try laws.column(provider);
    try laws.diagnostic(provider);
    try laws.logicalWork(provider);
}
