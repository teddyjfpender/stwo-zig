//! Actual SDK consumer namespace and provider behavior.
const sdk = @import("stwo");
const provider = @import("stwo_circuit_recursion_wire");
const laws = @import("waist_consumer_laws");

comptime {
    if (sdk.recursion_wire != provider) @compileError("SDK provider namespace is not canonical");
}

test "cdc: SDK recursion_wire preserves provider behavior and refusal" {
    try laws.recursionDecode(sdk.recursion_wire);
}
