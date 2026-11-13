//! Product composition facade; native declarations retain their canonical owners.
const native = @import("stwo_riscv_frontend").prover_mod.guest_precompile;
pub const EthereumProveOutputForEngine = ethereum_types.ProveOutputForEngine;
pub const EthereumSegmentGeometrySnapshot =
    ethereum_segment_orchestration.GeometrySnapshot;
pub const EthereumSegmentProveDiagnostic =
    ethereum_segment_orchestration.ProveDiagnostic;
pub const EthereumSegmentProveOutputForEngine =
    ethereum_types.SegmentProveOutputForEngine;
pub const EthereumSegmentProviderCallAuthorityV1 =
    ethereum_segment_orchestration.ProviderCallAuthorityV1;
pub const InteractionClaim = native.InteractionClaim;
pub const ProveOutput = native.ProveOutput;
pub const VerifiedEthereumSegmentV3CaptureForEngine =
    ethereum_segment_verifier.VerifiedEthereumSegmentV3CaptureForEngine;
pub const buildEthereumSegmentProviderCallAuthorityV1 =
    ethereum_segment_orchestration.buildProviderCallAuthorityV1;
pub const cancellation = native.cancellation;
pub const component_assembly = native.component_assembly;
pub const ecdsa_csp = @import("ecdsa_csp.zig");
pub const ethereum_assembly = @import("ethereum_assembly.zig");
pub const ethereum_cancellation = @import("ethereum_cancellation.zig");
pub const ethereum_interaction = @import("ethereum_interaction.zig");
pub const ethereum_leaf_matched_ab_execution_profile_v1 =
    @import("ethereum_leaf_matched_ab_execution_profile.zig");
pub const ethereum_main = @import("ethereum_main.zig");
pub const ethereum_native_provider_omit_proof_v1 =
    @import("../memory_provider_shards/ethereum_omit_provider_proof.zig");
pub const ethereum_native_provider_omit_protocol_v1 =
    @import("../memory_provider_shards/ethereum_omit_protocol.zig");
pub const ethereum_orchestration = @import("ethereum_orchestration.zig");
pub const ethereum_preprocessed = @import("ethereum_preprocessed.zig");
pub const ethereum_proof_artifact = @import("ethereum_proof_artifact.zig");
pub const ethereum_segment_orchestration =
    @import("ethereum_segment_orchestration.zig");
pub const ethereum_segment_proof_artifact =
    @import("ethereum_segment_proof_artifact.zig");
pub const ethereum_segment_source_wire =
    @import("ethereum_segment_source_wire.zig");
pub const ethereum_segment_transcript_extension =
    @import("ethereum_segment_transcript_extension.zig");
pub const ethereum_segment_verifier = @import("ethereum_segment_verifier.zig");
pub const ethereum_transcript = @import("ethereum_transcript.zig");
pub const ethereum_types = @import("ethereum_types.zig");
pub const ethereum_verifier = @import("ethereum_verifier.zig");
pub const ethereum_witness = @import("ethereum_witness.zig");
pub const inspectEthereumSegmentPreEngineGeometry =
    ethereum_segment_orchestration.inspectPreEngineGeometry;
pub const orchestration = native.orchestration;
pub const proof_artifact = native.proof_artifact;
pub const proof_finalize = native.proof_finalize;
pub const proveEthereumSegmentWithEngine =
    ethereum_segment_orchestration.proveWithEngine;
pub const proveEthereumSegmentWithEngineUsingChannelAndExecutionAndNativeProviderOmission =
    ethereum_segment_transcript_extension.proveWithEngineUsingChannelAndExecutionAndNativeProviderOmission;
pub const proveEthereumSegmentWithEngineUsingChannelAndExecutionAndTranscriptExtension =
    ethereum_segment_transcript_extension.proveWithEngineUsingChannelAndExecution;
pub const proveEthereumSegmentWithEngineUsingExecution =
    ethereum_segment_orchestration.proveWithEngineUsingExecution;
pub const proveEthereumSegmentWithEngineUsingExecutionDiagnosed =
    ethereum_segment_orchestration.proveWithEngineUsingExecutionDiagnosed;
pub const proveEthereumSegmentWithEngineUsingMatchedAbExecutionDiagnosed =
    ethereum_segment_orchestration.proveWithEngineUsingMatchedAbExecutionDiagnosed;
pub const proveEthereumWithEngine = ethereum_orchestration.proveWithEngine;
pub const proveEthereumWithEngineUsingChannel =
    ethereum_orchestration.proveWithEngineUsingChannel;
pub const proveEthereumWithEngineUsingChannelAndExecution =
    ethereum_orchestration.proveWithEngineUsingChannelAndExecution;
pub const proveEthereumWithEngineUsingExecution =
    ethereum_orchestration.proveWithEngineUsingExecution;
pub const provePoseidon2WithEngineAndPublicData = native.provePoseidon2WithEngineAndPublicData;
pub const provePoseidon2WithEngineAndPublicDataUsingChannel = native.provePoseidon2WithEngineAndPublicDataUsingChannel;
pub const provePoseidon2WithEngineAndPublicDataUsingChannelAndPhaseMeter = native.provePoseidon2WithEngineAndPublicDataUsingChannelAndPhaseMeter;
pub const split_caller_finish = native.split_caller_finish;
pub const split_pcs_prepare = native.split_pcs_prepare;
pub const split_provider_finish = native.split_provider_finish;
pub const trace_geometry = native.trace_geometry;
pub const types = native.types;
pub const verifier = native.verifier;
pub const verifyEthereumSegmentWithEngine =
    ethereum_segment_verifier.verifyWithEngine;
pub const verifyEthereumSegmentWithEngineAndCapture =
    ethereum_segment_verifier.verifyWithEngineAndCapture;
pub const verifyEthereumSegmentWithEngineAndCaptureUsingChannel =
    ethereum_segment_verifier.verifyWithEngineAndCaptureUsingChannel;
pub const verifyEthereumSegmentWithEngineAndEthereumV3Capture =
    ethereum_segment_verifier.verifyWithEngineAndEthereumV3Capture;
pub const verifyEthereumSegmentWithEngineAndEthereumV3CaptureUsingChannel =
    ethereum_segment_verifier.verifyWithEngineAndEthereumV3CaptureUsingChannel;
pub const verifyEthereumSegmentWithEngineAndEthereumV3CaptureUsingChannelAndTranscriptExtension =
    ethereum_segment_transcript_extension.verifyWithEngineAndEthereumV3CaptureUsingChannel;
pub const verifyEthereumSegmentWithEngineUsingChannel =
    ethereum_segment_verifier.verifyWithEngineUsingChannel;
pub const verifyEthereumSegmentWithEngineUsingChannelAndNativeProviderOmission =
    ethereum_segment_transcript_extension.verifyWithEngineUsingChannelAndNativeProviderOmission;
pub const verifyEthereumSegmentWithEngineUsingChannelAndNativeProviderOmissionCapture =
    ethereum_segment_transcript_extension.verifyWithEngineUsingChannelAndNativeProviderOmissionCapture;
pub const verifyEthereumSegmentWithEngineUsingChannelAndTranscriptExtension =
    ethereum_segment_transcript_extension.verifyWithEngineUsingChannel;
pub const verifyEthereumWithEngine = ethereum_verifier.verifyWithEngine;
pub const verifyEthereumWithEngineUsingChannel =
    ethereum_verifier.verifyWithEngineUsingChannel;
pub const verifyPoseidon2WithEngine = native.verifyPoseidon2WithEngine;
pub const verifyPoseidon2WithEngineUsingChannel = native.verifyPoseidon2WithEngineUsingChannel;
