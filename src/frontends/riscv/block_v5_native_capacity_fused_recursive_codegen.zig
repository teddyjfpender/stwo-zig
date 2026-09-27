//! Genuine B5CF/recursive bodies retained by address only, never executed.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Admission = @import("prover/block_v5_native_capacity_fused_recursive_admission_v1.zig");
const Capture = @import("prover/block_v5_native_capacity_fused_recursive_capture_v1.zig");
const Bus = @import("recursion/block_v5_native_capacity_fused_recursive_public_bus_v1.zig");
const Leaf = @import("recursion/block_v5_native_capacity_fused_recursive_leaf_v1.zig");
const Stage = @import("prover/block_v5_native_capacity_fused_recursive_stage_v1.zig");
pub export fn stwo_capacity_fused_recursive_body_gate() void {
    inline for (.{ &Admission.Prepared.init, &Admission.Prepared.validate, &Admission.Prepared.deinit, &Capture.ForBackend(Cpu).verifyOwned, &Capture.ForBackend(Cpu).verifyBorrowed, &Capture.VerifiedCapture.validate, &Capture.VerifiedCapture.deinit, &@import("recursion/air/block_v5_native_capacity_fused_composition_v1.zig").prepare, &@import("recursion/air/block_v5_native_capacity_fused_deep_v1.zig").prepare, &@import("recursion/air/block_v5_native_capacity_fused_transcript_v1.zig").planReplay, &@import("recursion/air/block_v5_native_capacity_fused_roots_v1.zig").prepare, &Bus.prepare, &Bus.Values.init, &Bus.Values.clone, &Bus.Values.deinit, &Leaf.verify, &Leaf.OpenEquation.deinit, &Stage.ForBackend(Cpu).publish, &Stage.Artifact.deinit, &Stage.ForBackend(Cpu).SetupCache.provePreparedConsuming }) |body| std.mem.doNotOptimizeAway(body);
}
