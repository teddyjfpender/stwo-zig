//! Consumer-owned laws selected for the stwo_prover_engine boundary.
const provider = @import("stwo_core");
const laws = @import("waist_consumer_laws");

test "cdc: stwo_prover_engine field authority preserves inverse and zero refusal" {
    try laws.field(provider.fields.m31.M31);
    try laws.field(provider.fields.qm31.QM31);
}
