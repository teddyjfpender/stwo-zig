//! Consumer-owned laws selected for the stwo_riscv_cpu_integration boundary.
const provider = @import("stwo_proof_wire");
const laws = @import("waist_consumer_laws");
const postcard = @import("interop_postcard");
const core = @import("stwo_core");

test "cdc: stwo_riscv_cpu_integration proof framing refuses malformed input without allocation" {
    try laws.framing(provider);
    try laws.postcardDecode(postcard, provider);
    try laws.framing(provider.ForField(core.fields.om31.OM31));
}
