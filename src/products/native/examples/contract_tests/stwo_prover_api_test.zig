//! Consumer-owned laws selected for the stwo_native_examples boundary.
const provider = @import("stwo_prover_api");
const laws = @import("waist_consumer_laws");
const consumer = @import("stwo_native_examples");
comptime {
    provider.assertProverEngine(consumer.xor.CpuProverEngine);
    provider.assertProverEngine(consumer.plonk.CpuProverEngine);
    provider.assertProverEngine(consumer.poseidon.CpuProverEngine);
}

test "cdc: stwo_native_examples request ownership and invalid input laws" {
    try laws.column(provider);
    try laws.diagnostic(provider);
    try laws.logicalWork(provider);
}
