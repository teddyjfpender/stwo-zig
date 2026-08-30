//! CPU instantiation of the backend-generic typed Keccak-f proof harness.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const proof_harness = @import("keccakf_proof_harness");

const Engine = frontend.prover_mod.ProverEngineForBackend(CpuBackend);

test "Keccak-f typed shard and lookup tables prove and independently verify" {
    _ = try proof_harness.run(Engine, std.heap.smp_allocator);
}
