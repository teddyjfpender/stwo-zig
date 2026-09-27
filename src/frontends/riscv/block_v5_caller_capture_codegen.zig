//! Force full actual original caller capture bodies; no function is invoked.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Family = @import("prover/block_v5_precompile_family_proof_v1.zig");
const Fused = @import("prover/block_v5_caller_fused_proof_v1.zig");
const Combined = @import("prover/block_v5_caller_verified_capture_v1.zig");
export fn stwo_caller_capture_body_gate() void {
    inline for (.{ &Family.ForBackend(Cpu).verifyOwned, &Family.ForBackend(Cpu).verifyCaptureOwned, &Family.ForBackend(Cpu).verifyCaptureBorrowed, &Family.VerifiedCapture.validate, &Fused.ForBackend(Cpu).verifyAfterFreshCaller, &Fused.ForBackend(Cpu).verifyCaptureOwnedAfterFreshCaller, &Fused.ForBackend(Cpu).verifyCaptureBorrowedAfterFreshCaller, &Fused.VerifiedCapture.validateAfterFreshCaller, &Combined.ForBackend(Cpu).verifyOwned, &Combined.ForBackend(Cpu).verifyBorrowed, &Combined.Verified.validate, &Combined.Verified.deinit }) |function| std.mem.doNotOptimizeAway(function);
}
