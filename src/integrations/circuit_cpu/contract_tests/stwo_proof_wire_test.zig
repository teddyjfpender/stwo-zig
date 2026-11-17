//! Consumer-owned laws selected for the stwo_circuit_cpu_integration boundary.
const provider = @import("stwo_proof_wire");
const laws = @import("waist_consumer_laws");
const core = @import("stwo_core");

test "cdc: stwo_circuit_cpu_integration proof framing refuses malformed input without allocation" {
    try laws.framing(provider);
    try laws.framing(provider.ForField(core.fields.om31.OM31));
}
