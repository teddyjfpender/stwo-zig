//! Retain actual full verifier/parent/publication/receiver bodies without calls.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Stage = @import("prover/block_v5_caller_readonly_recursive_stage_v1.zig");
const Capture = @import("prover/block_v5_caller_readonly_recursive_capture_v1.zig");
const Bus = @import("recursion/block_v5_caller_readonly_recursive_public_bus_v1.zig");
const Leaf = @import("recursion/block_v5_caller_readonly_recursive_leaf_v1.zig");
pub export fn stwo_caller_readonly_recursive_body_gate() void {
    @setEvalBranchQuota(1_000_000);
    const Original = @import("prover/block_v5_caller_readonly_proof_v1.zig");
    inline for (.{ &Original.ForBackend(Cpu).verifyAfterFreshCaller, &Original.ForBackend(Cpu).verifyCaptureOwnedAfterFreshCaller, &Original.ForBackend(Cpu).verifyCaptureBorrowedAfterFreshCaller, &Stage.ForBackend(Cpu).publish, &Stage.ForBackend(Cpu).publishFromVerifiedCapture, &Stage.ForBackend(Cpu).publishConsumingVerifiedCapture, &Capture.ForBackend(Cpu).verifyAfterFreshCaller, &Bus.prepare, &Leaf.verify, &Capture.VerifiedCapture.deinit, &Stage.Artifact.deinit }) |function| std.mem.doNotOptimizeAway(function);
}
