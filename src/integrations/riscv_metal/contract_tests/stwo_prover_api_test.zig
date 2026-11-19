//! Consumer-owned laws selected for the stwo_riscv_metal_integration boundary.
const provider = @import("stwo_prover_api");
const laws = @import("waist_consumer_laws");
const consumer = @import("stwo_riscv_metal_integration");
test "cdc: stwo_riscv_metal_integration request ownership and invalid input laws" {
    // Resolving the native engine signature requires the linked Metal runtime.
    if (comptime @import("builtin").os.tag == .macos) comptime provider.assertProverEngine(consumer.MetalProverEngine);
    try laws.column(provider);
    try laws.diagnostic(provider);
    try laws.logicalWork(provider);
}
