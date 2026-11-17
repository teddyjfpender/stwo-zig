//! Actual SDK consumer namespace and provider behavior.
const sdk = @import("stwo");
const provider = @import("stwo_core");
const laws = @import("waist_consumer_laws");

comptime {
    if (sdk.core != provider) @compileError("SDK provider namespace is not canonical");
}

test "cdc: SDK core preserves provider behavior and refusal" {
    try laws.field(sdk.core.fields.m31.M31);
}
