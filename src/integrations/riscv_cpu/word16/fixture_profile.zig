//! Concrete diagnostic profiling seam. One serial coordinator owns the recorder;
//! AIR components receive no shared hierarchical recorder or task capture.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(Backend, H, MC);
pub const Recorder = @import("stwo_prover_api").stage_profile.Recorder;
pub const Scope = @import("stwo_prover_api").stage_profile.StageScope;
pub fn prove(a: std.mem.Allocator, components: []const engine.air.component_prover.ComponentProver, channel: *Channel, scheme: Scheme, recorder: ?*Recorder) !core.proof.StarkProof(H) {
    var extended = try engine.prove.proveExWithRecorder(Backend, H, MC, a, components, channel, scheme, false, recorder);
    const proof = extended.proof;
    extended.aux.deinit(a);
    return proof;
}
