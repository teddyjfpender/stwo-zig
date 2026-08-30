//! CPU instantiation of the backend-generic compact secp256k1 proof harness.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const proof_harness = @import("secp256k1_proof_harness");

const Engine = frontend.prover_mod.ProverEngineForBackend(CpuBackend);

test "secp256k1 typed ECDSA bundle proves and independently verifies" {
    _ = try proof_harness.Harness(Engine).run(std.heap.smp_allocator);
}
