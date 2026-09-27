//! CPU instantiation of the backend-generic compact secp256k1 proof harness.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const proof_harness = @import("secp256k1_proof_harness");

const LegacyEngine = frontend.prover_mod.ProverEngineForBackend(CpuBackend);

test "secp256k1 typed ECDSA bundle proves and independently verifies" {
    _ = try proof_harness.Harness(LegacyEngine).runSelected(std.heap.smp_allocator);
}

test "CSP ECDSA guest proves caller memory and result at canonical security" {
    try proof_harness.cspProof(LegacyEngine, "cpu");
}
test "BLAKE3 CSP ECDSA guest proves and verifies at canonical security" {
    const suite = @import("stwo_core").proof_suites.Blake3;
    const Engine = @import("stwo_prover_engine").engine.ProverEngine(CpuBackend, suite.Hasher, suite.MerkleChannel, suite.Channel);
    try proof_harness.cspProof(Engine, "cpu");
}
