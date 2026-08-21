//! Poseidon2 extension proving and independent verification surface.

pub const types = @import("types.zig");
pub const trace_geometry = @import("trace_geometry.zig");
pub const component_assembly = @import("component_assembly.zig");
pub const cancellation = @import("cancellation.zig");
pub const proof_artifact = @import("proof_artifact.zig");
pub const proof_finalize = @import("proof_finalize.zig");
pub const orchestration = @import("orchestration.zig");
pub const verifier = @import("verifier.zig");
/// Research-only split PCS prepare/manifest boundary. This retains real
/// commitment schemes but is not accepted by the production proof API.
pub const split_pcs_prepare = @import("split_pcs_prepare.zig");
/// Research-only session-wide PoW candidate. It changes neither the accepted
/// V1 aggregation manifest nor either production proof transcript.
pub const split_joint_pow = @import("split_joint_pow.zig");
/// Research-only completion and independent verification of the base-plus-
/// caller STARK after the split manifest barrier.
pub const split_caller_finish = @import("split_caller_finish.zig");
/// Research-only completion and independent verification of the standalone
/// provider STARK after the split manifest barrier.
pub const split_provider_finish = @import("split_provider_finish.zig");

pub const InteractionClaim = types.InteractionClaim;
pub const ProveOutput = types.ProveOutput;
pub const provePoseidon2WithEngineAndPublicData =
    orchestration.provePoseidon2WithEngineAndPublicData;
pub const provePoseidon2WithEngineAndPublicDataUsingChannel =
    orchestration.provePoseidon2WithEngineAndPublicDataUsingChannel;
pub const provePoseidon2WithEngineAndPublicDataUsingChannelAndPhaseMeter =
    orchestration.provePoseidon2WithEngineAndPublicDataUsingChannelAndPhaseMeter;
pub const verifyPoseidon2WithEngine = verifier.verifyPoseidon2WithEngine;
pub const verifyPoseidon2WithEngineUsingChannel =
    verifier.verifyPoseidon2WithEngineUsingChannel;
