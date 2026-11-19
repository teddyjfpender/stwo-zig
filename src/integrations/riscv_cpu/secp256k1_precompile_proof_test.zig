//! CPU instantiation of the backend-generic compact secp256k1 proof harness.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const proof_harness = @import("secp256k1_proof_harness");

const LegacyEngine = frontend.prover_mod.ProverEngineForBackend(CpuBackend);

test "secp256k1 typed ECDSA bundle proves and independently verifies" {
    const Harness = proof_harness.Harness(LegacyEngine);
    const allocator = std.heap.smp_allocator;
    _ = if (@import("test_options").samples) |samples| try Harness.runSamples(allocator, samples) else try Harness.run(allocator);
}
