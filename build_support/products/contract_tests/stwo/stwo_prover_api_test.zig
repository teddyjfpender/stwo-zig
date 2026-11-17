//! Actual SDK consumer namespace and provider behavior.
const sdk = @import("stwo");
const provider = @import("stwo_prover_api");
const laws = @import("waist_consumer_laws");

comptime {
    if (sdk.prover_api != provider) @compileError("SDK provider namespace is not canonical");
}

test "cdc: SDK prover_api preserves provider behavior and refusal" {
    try laws.column(sdk.prover_api);
    try laws.diagnostic(sdk.prover_api);
}
