//! Retain actual full verifier/parent/publication/receiver bodies without calls.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Stage = @import("prover/block_v5_caller_readonly_global_recursive_stage_v2.zig");
const Capture = @import("prover/block_v5_caller_readonly_global_recursive_capture_v2.zig");
const Bus = @import("recursion/block_v5_caller_readonly_global_recursive_public_bus_v2.zig");
const Leaf = @import("recursion/block_v5_caller_readonly_global_recursive_leaf_v2.zig");
const Receiver = @import("prover/block_v5_caller_readonly_global_receiver_v2.zig");
// Runtime-address retention for the genuine cold replay initializer. No PCS is
// called by this marker; compilation retains its real original commitment body.
fn replay(a: std.mem.Allocator, prefix: *@import("prover/block_v5_precompile_family_proof_v1.zig").ForBackend(Cpu).FirstRound, frame: @import("air/block/memory_event.zig").Frame, authority: @import("prover/block_v5_caller_readonly_global_proof_v2.zig").Authority) !@import("prover/block_v5_caller_readonly_stage_v1.zig").ForBackend(Cpu).Prepared.Observed {
    return @import("prover/block_v5_caller_readonly_stage_v1.zig").ForBackend(Cpu).Prepared.initOpenSource(a, prefix, frame, authority);
}
fn observed(a: std.mem.Allocator, prefix: *@import("prover/block_v5_precompile_family_proof_v1.zig").ForBackend(Cpu).PhysicalFirstRound, frame: @import("air/block/memory_event.zig").Frame, selection: *const @import("prover/block_v5_readonly_input_selection_v1.zig").Owned, observer: @import("prover/block_v5_caller_readonly_witness_v1.zig").Metadata.Observer) !@import("prover/block_v5_caller_readonly_stage_v1.zig").ForBackend(Cpu).Prepared.Observed {
    return @import("prover/block_v5_caller_readonly_stage_v1.zig").ForBackend(Cpu).Prepared.initPhysicalObserved(a, prefix, &prefix.witness.statement, prefix.total_steps, frame, selection, .{}, null, observer);
}
pub export fn stwo_caller_readonly_global_recursive_body_gate() void {
    @setEvalBranchQuota(1_000_000);
    const Original = @import("prover/block_v5_caller_readonly_global_proof_v2.zig");
    inline for (.{ &replay, &observed, &Original.ForBackend(Cpu).proveForCallerFirstRound, &Original.ForBackend(Cpu).verifyAfterFreshCaller, &Receiver.ForBackend(Cpu).verifyOwned, &Original.ForBackend(Cpu).verifyCaptureOwnedAfterFreshCaller, &Original.ForBackend(Cpu).verifyCaptureBorrowedAfterFreshCaller, &Stage.ForBackend(Cpu).publish, &Stage.ForBackend(Cpu).publishFromVerifiedCapture, &Stage.ForBackend(Cpu).publishConsumingVerifiedCapture, &Capture.ForBackend(Cpu).verifyAfterFreshCaller, &Bus.prepare, &Leaf.verify, &Capture.VerifiedCapture.deinit, &Stage.Artifact.deinit }) |function| std.mem.doNotOptimizeAway(function);
}
