//! Consumer-owned laws selected for the stwo_riscv_air_lang boundary.
const provider = @import("stwo_core");
const laws = @import("waist_consumer_laws");

test "cdc: stwo_riscv_air_lang field authority preserves inverse and zero refusal" {
    try laws.field(provider.fields.m31.M31);
}
