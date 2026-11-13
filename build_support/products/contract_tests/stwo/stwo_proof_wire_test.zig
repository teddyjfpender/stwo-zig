//! Actual SDK consumer namespace and provider behavior.
const sdk = @import("stwo");
const provider = @import("stwo_proof_wire");
const laws = @import("waist_consumer_laws");

comptime {
    if (sdk.proof_wire != provider) @compileError("SDK provider namespace is not canonical");
}

test "cdc: SDK proof_wire preserves provider behavior and refusal" {
    try laws.framing(sdk.proof_wire);
}
