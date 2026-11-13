//! Proof-wire law consumed through the actual injected postcard codec.
const provider = @import("stwo_proof_wire");
const laws = @import("waist_consumer_laws");
const postcard = @import("interop_postcard");

test "cdc: stwo_riscv_rv32 injected postcard retains proof authority and bounded refusal" {
    try laws.framing(provider);
    try laws.postcardDecode(postcard, provider);
}
