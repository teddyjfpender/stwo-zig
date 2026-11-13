//! Consumer-owned laws selected for the stwo_native_cuda_integration boundary.
const provider = @import("stwo_proof_wire");
const laws = @import("waist_consumer_laws");

test "cdc: stwo_native_cuda_integration proof framing refuses malformed input without allocation" {
    try laws.framing(provider);
}
