//! Diagnostic source-JIT qualification; authenticated AOT remains a separate gate.
const std = @import("std");
const metal = @import("stwo_metal_backend");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const Engine = @import("stwo_prover_engine").engine.ProverEngine(metal.MetalCommitBackend, suite.Hasher, suite.MerkleChannel, suite.Channel);
test "Metal BLAKE3 canonical CSP ECDSA proves and independently verifies" {
    try Engine.initializeRuntime(std.heap.smp_allocator, .source_jit);
    defer Engine.Backend.shutdown() catch unreachable;
    const before = try Engine.telemetrySnapshot();
    try @import("secp256k1_proof_harness").cspProof(Engine, "metal_source_jit");
    const delta = (try Engine.telemetrySnapshot()).delta(before);
    try delta.requireMetalDispatch();
    std.debug.print("CSP_METAL dispatches={d} fallbacks={d} runtime=source_jit\n", .{delta.counters.metalDispatchTotal(), delta.counters.cpuFallbackTotal()});
}
