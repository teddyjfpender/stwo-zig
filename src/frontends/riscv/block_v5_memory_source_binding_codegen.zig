//! Actual page binding and original-root replay bodies; never run PCS/proofs.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Component = @import("prover/block_v5_memory_source_binding_component_v1.zig").Component;
const Replay = @import("prover/block_v5_memory_source_page_replay_v1.zig").ForBackend(Cpu);
test "source binding bodies: actual four-tree point-domain adapter and streamed original-root recommit retained" {
    inline for (.{ &Replay.persist, &Replay.loadRecommitted, &Replay.Reader.take, &Replay.Reader.deinit, &Replay.Loaded.deinit, &Component.asProverComponent, &Component.asVerifierComponent, &Component.evaluateConstraintQuotientsAtPoint, &Component.evaluateConstraintQuotientsOnDomain }) |body| std.mem.doNotOptimizeAway(body);
}
