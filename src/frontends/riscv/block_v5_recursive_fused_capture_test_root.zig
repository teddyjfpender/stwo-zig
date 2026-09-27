//! Original canonical native/caller fused capture bodies and nonproving
//! custody fixtures. No accepted synthetic capture or proof construction.
const std = @import("std");
comptime {
    _ = @import("prover/block_v5_caller_capture_unit_test.zig");
    _ = @import("prover/block_v5_native_capacity_fused_capture_test_v1.zig");
}
test "fused capture bodies: actual native owned borrowed admission capture validation and teardown retained only" {
    const Fused = @import("prover/block_v5_native_capacity_fused_proof_v1.zig");
    const API = Fused.ForBackend(@import("stwo_cpu_backend").CpuBackend);
    inline for (.{ &API.verifyOwned, &API.verifyCaptureOwned, &API.verifyCaptureBorrowed, &Fused.CaptureAdmission.require, &Fused.CaptureMetadata.init, &Fused.CaptureMetadata.require, &Fused.CaptureMetadata.identity, &Fused.VerifiedCapture.validate, &Fused.VerifiedCapture.identity, &Fused.VerifiedCapture.deinit }) |body|
        std.mem.doNotOptimizeAway(body);
}
