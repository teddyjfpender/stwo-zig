const std = @import("std");
const prover_engine = @import("stwo_prover_impl").engine;
const MetalCommitBackend = @import("stwo_metal_backend").MetalCommitBackend;
const poseidon = @import("stwo_native_examples").poseidon;

test "metal: Poseidon engine satisfies the Native example transaction contract" {
    const MetalEngine = poseidon.ProverEngineForBackend(MetalCommitBackend);
    comptime prover_engine.assertProverEngine(MetalEngine);
    try std.testing.expect(@hasDecl(MetalEngine, "Session"));
}
