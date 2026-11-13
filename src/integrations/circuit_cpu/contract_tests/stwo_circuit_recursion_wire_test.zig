//! Consumer-owned laws selected for the stwo_circuit_cpu_integration boundary.
const provider = @import("stwo_circuit_recursion_wire");
const laws = @import("waist_consumer_laws");

test "cdc: stwo_circuit_cpu_integration recursive decoder preserves truncation and shape refusal" {
    try laws.recursionDecode(provider);
}
