//! Retain actual commitment/fixed-recommit/shared-lease/candidate bodies only.
//! This test never calls PCS, STARK/FRI, recursive proofs, guest or device code.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Round = @import("prover/block_v5_memory_source_first_round_v1.zig").ForBackend(Cpu);
test "source first bodies: actual bounded commitment fixed reconstruction and original-tree lease retained" {
    inline for (.{ &Round.collectPage, &Round.verifyFixedRoot, &Round.lease, &Round.prepareChunk, &Round.FirstRound.deinit, &Round.FirstRound.require, &Round.Lease.takeScheme, &Round.Lease.deinit }) |body| std.mem.doNotOptimizeAway(body);
}
