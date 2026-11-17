//! Consumer-owned laws selected for the stwo_metal_backend boundary.
const provider = @import("stwo_backend_contracts");
const laws = @import("waist_consumer_laws");
const core = @import("stwo_core");
const consumer = @import("stwo_metal_backend");
comptime {
    provider.assertBackend(consumer.MetalCommitBackend);
}

test "cdc: stwo_metal_backend line geometry rejects invalid storage" {
    try laws.line(provider, core);
}
