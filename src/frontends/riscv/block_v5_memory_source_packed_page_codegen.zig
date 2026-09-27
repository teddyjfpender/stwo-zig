//! Retain real CPU page commit/replay/lease and exact SHA point/domain bodies;
//! no commitment, polynomial proof, FRI, guest or device is invoked here.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Schema = @import("prover/block_v5_memory_source_batch_raw_schema_v1.zig");
const Round = Schema.Round.ForBackend(Cpu);
const Replay = Schema.Replay.ForBackend(Cpu);
const Component = @import("prover/block_v5_memory_source_sha_connector_component_v1.zig").ForSourceFixed(Schema.FIXED_COUNT);
test "source packed page bodies: actual distinct raw commitments immutable leases streamed recommit and five-tree SHA equations retained" {
    inline for (.{ &Round.collectPage, &Round.verifyFixedRoot, &Round.lease, &Round.FirstRound.require, &Round.FirstRound.deinit, &Replay.persist, &Replay.loadRecommitted, &Replay.Reader.take, &Replay.Loaded.deinit, &Component.asProverComponent, &Component.asVerifierComponent, &Component.evaluateConstraintQuotientsAtPoint, &Component.evaluateConstraintQuotientsOnDomain }) |body| std.mem.doNotOptimizeAway(body);
}

const Stage = @import("prover/block_v5_memory_source_packed_sha_replay_v1.zig").ForBackend(Cpu);
const Kernel = @import("prover/block_v5_memory_source_packed_sha_proof_v1.zig");
const Codec = @import("prover/block_v5_memory_source_packed_sha_codec_v1.zig");
test "source packed page genuine kernel bodies: six-tree commit replay lease one PAGE FRI original CPU receiver and strict eight-tree codec retained" {
    inline for (.{ &Stage.collect, &Stage.replay, &Stage.persist, &Stage.lease, &Stage.Owner.require, &Stage.Owner.deinit, &Stage.Reader.take, &Stage.Reader.deinit, &Stage.Loaded.deinit, &Kernel.ForBackend(Cpu).prove, &Kernel.ForBackend(Cpu).Proved.deinit, &Kernel.verifyOwned, &Kernel.verifyFixedRoots, &Codec.encode, &Codec.decode }) |body| std.mem.doNotOptimizeAway(body);
}
