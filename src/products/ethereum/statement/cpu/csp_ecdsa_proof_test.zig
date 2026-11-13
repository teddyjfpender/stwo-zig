//! Canonical Ethereum-instruction CSP proof qualification, owned by this product.
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("ethereum_frontend_component");
const proof_harness = @import("ethereum_frontend_component").csp_proof_harness;
const LegacyEngine = frontend.prover_mod.ProverEngineForBackend(CpuBackend);

test "CSP ECDSA guest proves caller memory and result at canonical security" {
    try proof_harness.cspProof(LegacyEngine, "cpu");
}

test "BLAKE3 CSP ECDSA guest proves and verifies at canonical security" {
    const suite = @import("stwo_core").proof_suites.Blake3;
    const Engine = @import("stwo_prover_engine").engine.ProverEngine(CpuBackend, suite.Hasher, suite.MerkleChannel, suite.Channel);
    try proof_harness.cspProof(Engine, "cpu");
}
