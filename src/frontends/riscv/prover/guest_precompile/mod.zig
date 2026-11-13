//! Poseidon2 extension proving and independent verification surface.

pub const types = @import("stwo_riscv_rv32").prover.guest_precompile.types;
pub const trace_geometry = @import("stwo_riscv_rv32").prover.guest_precompile.trace_geometry;
pub const component_assembly = @import("stwo_riscv_rv32").prover.guest_precompile.component_assembly;
pub const cancellation = @import("stwo_riscv_rv32").prover.guest_precompile.cancellation;
pub const proof_artifact = @import("../../compat/assembly/rv32/prover/guest_precompile/proof_artifact.zig");
pub const proof_finalize = @import("stwo_riscv_rv32").prover.guest_precompile.proof_finalize;
pub const orchestration = @import("stwo_riscv_rv32").prover.guest_precompile.orchestration;
pub const verifier = @import("stwo_riscv_rv32").prover.guest_precompile.verifier;
/// Research-only split PCS prepare/manifest boundary. This retains real
/// commitment schemes but is not accepted by the production proof API.
pub const split_pcs_prepare = @import("stwo_riscv_rv32").prover.guest_precompile.split_pcs_prepare;
/// Research-only completion and independent verification of the base-plus-
/// caller STARK after the split manifest barrier.
pub const split_caller_finish = @import("stwo_riscv_rv32").prover.guest_precompile.split_caller_finish;
/// Research-only completion and independent verification of the standalone
/// provider STARK after the split manifest barrier.
pub const split_provider_finish = @import("stwo_riscv_rv32").prover.guest_precompile.split_provider_finish;

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
