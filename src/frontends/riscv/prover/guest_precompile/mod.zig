//! Poseidon2 extension proving and independent verification surface.

pub const types = @import("stwo_riscv_rv32").prover.guest_precompile.types;
pub const trace_geometry = @import("stwo_riscv_rv32").prover.guest_precompile.trace_geometry;
pub const component_assembly = @import("stwo_riscv_rv32").prover.guest_precompile.component_assembly;
pub const cancellation = @import("stwo_riscv_rv32").prover.guest_precompile.cancellation;
pub const proof_artifact = @import("../../compat/assembly/rv32/prover/guest_precompile/proof_artifact.zig");
pub const ethereum_proof_artifact = @import("ethereum_proof_artifact.zig");
pub const ethereum_segment_proof_artifact =
    @import("ethereum_segment_proof_artifact.zig");
pub const ethereum_segment_source_wire =
    @import("ethereum_segment_source_wire.zig");
pub const proof_finalize = @import("stwo_riscv_rv32").prover.guest_precompile.proof_finalize;
pub const ethereum_witness = @import("ethereum_witness.zig");
pub const ethereum_types = @import("ethereum_types.zig");
pub const ethereum_transcript = @import("ethereum_transcript.zig");
pub const ethereum_preprocessed = @import("ethereum_preprocessed.zig");
pub const ethereum_main = @import("ethereum_main.zig");
pub const ethereum_interaction = @import("ethereum_interaction.zig");
pub const ethereum_assembly = @import("ethereum_assembly.zig");
pub const ethereum_cancellation = @import("ethereum_cancellation.zig");
pub const ethereum_orchestration = @import("ethereum_orchestration.zig");
pub const ethereum_verifier = @import("ethereum_verifier.zig");
pub const ethereum_segment_orchestration =
    @import("ethereum_segment_orchestration.zig");
pub const ethereum_segment_transcript_extension =
    @import("ethereum_segment_transcript_extension.zig");
pub const ethereum_native_provider_omit_protocol_v1 =
    @import("../memory_provider_shards/ethereum_omit_protocol.zig");
pub const ethereum_native_provider_omit_proof_v1 =
    @import("../memory_provider_shards/ethereum_omit_provider_proof.zig");
pub const ethereum_segment_verifier = @import("ethereum_segment_verifier.zig");
pub const ethereum_leaf_matched_ab_execution_profile_v1 =
    @import("ethereum_leaf_matched_ab_execution_profile.zig");
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
pub const EthereumProveOutputForEngine = ethereum_types.ProveOutputForEngine;
pub const proveEthereumWithEngine = ethereum_orchestration.proveWithEngine;
pub const proveEthereumWithEngineUsingExecution =
    ethereum_orchestration.proveWithEngineUsingExecution;
pub const proveEthereumWithEngineUsingChannel =
    ethereum_orchestration.proveWithEngineUsingChannel;
pub const proveEthereumWithEngineUsingChannelAndExecution =
    ethereum_orchestration.proveWithEngineUsingChannelAndExecution;
pub const verifyEthereumWithEngine = ethereum_verifier.verifyWithEngine;
pub const verifyEthereumWithEngineUsingChannel =
    ethereum_verifier.verifyWithEngineUsingChannel;
pub const EthereumSegmentProveOutputForEngine =
    ethereum_types.SegmentProveOutputForEngine;
pub const proveEthereumSegmentWithEngine =
    ethereum_segment_orchestration.proveWithEngine;
pub const proveEthereumSegmentWithEngineUsingExecution =
    ethereum_segment_orchestration.proveWithEngineUsingExecution;
pub const proveEthereumSegmentWithEngineUsingExecutionDiagnosed =
    ethereum_segment_orchestration.proveWithEngineUsingExecutionDiagnosed;
pub const proveEthereumSegmentWithEngineUsingMatchedAbExecutionDiagnosed =
    ethereum_segment_orchestration.proveWithEngineUsingMatchedAbExecutionDiagnosed;
pub const proveEthereumSegmentWithEngineUsingChannelAndExecutionAndTranscriptExtension =
    ethereum_segment_transcript_extension.proveWithEngineUsingChannelAndExecution;
pub const proveEthereumSegmentWithEngineUsingChannelAndExecutionAndNativeProviderOmission =
    ethereum_segment_transcript_extension.proveWithEngineUsingChannelAndExecutionAndNativeProviderOmission;
pub const verifyEthereumSegmentWithEngineUsingChannelAndTranscriptExtension =
    ethereum_segment_transcript_extension.verifyWithEngineUsingChannel;
pub const verifyEthereumSegmentWithEngineUsingChannelAndNativeProviderOmission =
    ethereum_segment_transcript_extension.verifyWithEngineUsingChannelAndNativeProviderOmission;
pub const verifyEthereumSegmentWithEngineUsingChannelAndNativeProviderOmissionCapture =
    ethereum_segment_transcript_extension.verifyWithEngineUsingChannelAndNativeProviderOmissionCapture;
pub const verifyEthereumSegmentWithEngineAndEthereumV3CaptureUsingChannelAndTranscriptExtension =
    ethereum_segment_transcript_extension.verifyWithEngineAndEthereumV3CaptureUsingChannel;
pub const EthereumSegmentProveDiagnostic =
    ethereum_segment_orchestration.ProveDiagnostic;
pub const EthereumSegmentGeometrySnapshot =
    ethereum_segment_orchestration.GeometrySnapshot;
pub const inspectEthereumSegmentPreEngineGeometry =
    ethereum_segment_orchestration.inspectPreEngineGeometry;
pub const EthereumSegmentProviderCallAuthorityV1 =
    ethereum_segment_orchestration.ProviderCallAuthorityV1;
pub const buildEthereumSegmentProviderCallAuthorityV1 =
    ethereum_segment_orchestration.buildProviderCallAuthorityV1;
pub const verifyEthereumSegmentWithEngine =
    ethereum_segment_verifier.verifyWithEngine;
pub const verifyEthereumSegmentWithEngineUsingChannel =
    ethereum_segment_verifier.verifyWithEngineUsingChannel;
pub const verifyEthereumSegmentWithEngineAndCapture =
    ethereum_segment_verifier.verifyWithEngineAndCapture;
pub const verifyEthereumSegmentWithEngineAndCaptureUsingChannel =
    ethereum_segment_verifier.verifyWithEngineAndCaptureUsingChannel;
pub const VerifiedEthereumSegmentV3CaptureForEngine =
    ethereum_segment_verifier.VerifiedEthereumSegmentV3CaptureForEngine;
pub const verifyEthereumSegmentWithEngineAndEthereumV3Capture =
    ethereum_segment_verifier.verifyWithEngineAndEthereumV3Capture;
pub const verifyEthereumSegmentWithEngineAndEthereumV3CaptureUsingChannel =
    ethereum_segment_verifier.verifyWithEngineAndEthereumV3CaptureUsingChannel;

pub const ecdsa_csp = @import("../../compat/assembly/rv32/prover/guest_precompile/ecdsa_csp.zig");
