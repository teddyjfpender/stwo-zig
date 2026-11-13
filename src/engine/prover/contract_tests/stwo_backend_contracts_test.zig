//! Consumer-owned laws selected for the stwo_prover_engine boundary.
const provider = @import("stwo_backend_contracts");
const laws = @import("waist_consumer_laws");
const core = @import("stwo_core");

test "cdc: stwo_prover_engine line geometry rejects invalid storage" {
    try laws.line(provider, core);
}
