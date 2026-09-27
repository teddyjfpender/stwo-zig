//! Real owned/borrowed canonical B5CT fused verifier bodies; never invoked.
const std = @import("std");
const Fused = @import("prover/block_v5_native_capacity_fused_proof_v1.zig");
const API = Fused.ForBackend(@import("stwo_cpu_backend").CpuBackend);
export fn stwo_capacity_fused_capture_body_gate() void {
    inline for (.{ &API.verifyOwned, &API.verifyCaptureOwned, &API.verifyCaptureBorrowed, &Fused.CaptureAdmission.require, &Fused.CaptureMetadata.init, &Fused.CaptureMetadata.require, &Fused.CaptureMetadata.identity, &Fused.VerifiedCapture.validate, &Fused.VerifiedCapture.identity, &Fused.VerifiedCapture.deinit }) |body| std.mem.doNotOptimizeAway(body);
}
