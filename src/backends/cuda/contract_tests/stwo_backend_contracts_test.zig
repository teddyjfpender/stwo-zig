//! Consumer-owned laws selected for the stwo_cuda_backend boundary.
const provider = @import("stwo_backend_contracts");
const laws = @import("waist_consumer_laws");
const consumer = @import("stwo_cuda_backend");
comptime {
    if (@TypeOf(@as(consumer.frontend_contract.Receipt, undefined).statement) != provider.proof_program.Digest) @compileError("CUDA receipt lost canonical proof-program digest");
}

test "cdc: stwo_cuda_backend native geometry overflow and domain refusal" {
    try laws.nativeGeometry(provider);
}
