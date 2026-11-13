//! Actual SDK consumer namespace and provider behavior.
const sdk = @import("stwo");
const provider = @import("stwo_backend_contracts");
const laws = @import("waist_consumer_laws");

comptime {
    if (sdk.backend != provider) @compileError("SDK provider namespace is not canonical");
}

test "cdc: SDK backend preserves provider behavior and refusal" {
    try laws.nativeGeometry(sdk.backend);
}
