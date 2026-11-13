//! Product composition facade; native declarations retain their canonical owners.
const native = @import("stwo_riscv_frontend").prover_mod;
pub const EthereumExecutionOptions =
    guest_precompile.ethereum_orchestration.ExecutionOptions;
pub const EthereumLeafMatchedAbExecutionAuthorityV1 =
    guest_precompile.ethereum_leaf_matched_ab_execution_profile_v1.Authority;
pub const EthereumProveOutputForEngine =
    guest_precompile.EthereumProveOutputForEngine;
pub const EthereumSegmentGeometrySnapshot =
    guest_precompile.EthereumSegmentGeometrySnapshot;
pub const EthereumSegmentProveDiagnostic =
    guest_precompile.EthereumSegmentProveDiagnostic;
pub const EthereumSegmentProveOutputForEngine =
    guest_precompile.EthereumSegmentProveOutputForEngine;
pub const EthereumSegmentProviderCallAuthorityV1 =
    guest_precompile.EthereumSegmentProviderCallAuthorityV1;
pub const ExecutionOptions = native.ExecutionOptions;
pub const ExecutionOptionsV2 = native.ExecutionOptionsV2;
pub const ExtendedProof = native.ExtendedProof;
pub const FamilyComponentDesc = native.FamilyComponentDesc;
pub const Hasher = native.Hasher;
pub const InfraComponentDesc = native.InfraComponentDesc;
pub const InfraKind = native.InfraKind;
pub const MAX_COMPONENTS = native.MAX_COMPONENTS;
pub const MAX_EXECUTION_STEPS = native.MAX_EXECUTION_STEPS;
pub const MAX_INFRA_COMPONENTS = native.MAX_INFRA_COMPONENTS;
pub const OwnedRiscVStatement = native.OwnedRiscVStatement;
pub const Poseidon2InteractionClaim = native.Poseidon2InteractionClaim;
pub const Poseidon2ProveOutput = native.Poseidon2ProveOutput;
pub const Proof = native.Proof;
pub const ProofCaptureForEngine = native.ProofCaptureForEngine;
pub const ProofForEngine = native.ProofForEngine;
pub const ProveOutput = native.ProveOutput;
pub const ProveOutputV2 = native.ProveOutputV2;
pub const ProverEngineForBackend = native.ProverEngineForBackend;
pub const ProverError = native.ProverError;
pub const PublicData = native.PublicData;
pub const PublicDataV2 = native.PublicDataV2;
pub const PublishedIo = native.PublishedIo;
pub const QueryCapture = native.QueryCapture;
pub const RecursiveLeafCaptureForEngine = native.RecursiveLeafCaptureForEngine;
pub const RelationDiagnostic = native.RelationDiagnostic;
pub const RiscVInteractionClaim = native.RiscVInteractionClaim;
pub const RiscVStatement = native.RiscVStatement;
pub const RiscVStatementV2 = native.RiscVStatementV2;
pub const RunAdmissionError = native.RunAdmissionError;
pub const RunAdmissionRejection = native.RunAdmissionRejection;
pub const SECURE_PCS_CONFIG = native.SECURE_PCS_CONFIG;
pub const StatementAdmission = native.StatementAdmission;
pub const StatementAdmissionV2 = native.StatementAdmissionV2;
pub const VerifiedEthereumSegmentV3CaptureForEngine =
    guest_precompile.VerifiedEthereumSegmentV3CaptureForEngine;
pub const VerifiedSegmentV2CaptureForEngine = native.VerifiedSegmentV2CaptureForEngine;
pub const admitRunForProving = native.admitRunForProving;
pub const assertProverEngine = native.assertProverEngine;
pub const blake3_commitment_components = native.blake3_commitment_components;
pub const blake3_commitment_sharing = native.blake3_commitment_sharing;
pub const blake3_ethereum_artifact = @import("stwo_riscv_frontend").prover_mod.blake3_profile_artifact.ForProfile(true);
pub const blake3_ethereum_proof = @import("prover/blake3_ethereum_proof.zig");
pub const blake3_ethereum_witness = @import("prover/blake3_ethereum_witness.zig");
pub const blake3_execution = native.blake3_execution;
pub const blake3_execution_artifact = native.blake3_execution_artifact;
pub const blake3_poseidon_proof = native.blake3_poseidon_proof;
pub const blake3_poseidon_witness = native.blake3_poseidon_witness;
pub const blake3_profile_artifact = @import("prover/blake3_profile_artifact.zig");
pub const blake3_segment_execution = native.blake3_segment_execution;
pub const blake3_verified_public = native.blake3_verified_public;
pub const buildEthereumSegmentProviderCallAuthorityV1 =
    guest_precompile.buildEthereumSegmentProviderCallAuthorityV1;
pub const classifyCompletion = native.classifyCompletion;
pub const classifyPublicIo = native.classifyPublicIo;
pub const classifyRunAdmission = native.classifyRunAdmission;
pub const deriveIncrementalEthereumPreprocessedRootV4 =
    @import("prover/incremental_ethereum_verifier.zig").deriveExpectedPreprocessedRoot;
pub const deriveIncrementalEthereumPreprocessedRootWithFixedProgramV1 =
    @import("prover/incremental_ethereum_verifier.zig").deriveExpectedPreprocessedRootWithFixedProgramV1;
pub const diagnoseRiscVRelationsWithEngineAndPublicData = native.diagnoseRiscVRelationsWithEngineAndPublicData;
pub const ethereum_native_provider_omit_proof_v1 =
    guest_precompile.ethereum_native_provider_omit_proof_v1;
pub const ethereum_native_provider_omit_protocol_v1 =
    guest_precompile.ethereum_native_provider_omit_protocol_v1;
pub const guest_precompile = @import("prover/guest_precompile/mod.zig");
pub const inspectEthereumSegmentPreEngineGeometry =
    guest_precompile.inspectEthereumSegmentPreEngineGeometry;
pub const inspectRiscVSegmentLookupV2FullCohort = native.inspectRiscVSegmentLookupV2FullCohort;
pub const main_trace_plan_execution_production = native.main_trace_plan_execution_production;
pub const proof_phase_meter = native.proof_phase_meter;
pub const proveAndVerifyElfWithEngine = native.proveAndVerifyElfWithEngine;
pub const proveEthereumSegmentWithEngine =
    guest_precompile.proveEthereumSegmentWithEngine;
pub const proveEthereumSegmentWithEngineUsingChannelAndExecutionAndNativeProviderOmission =
    guest_precompile.proveEthereumSegmentWithEngineUsingChannelAndExecutionAndNativeProviderOmission;
pub const proveEthereumSegmentWithEngineUsingChannelAndExecutionAndTranscriptExtension =
    guest_precompile.proveEthereumSegmentWithEngineUsingChannelAndExecutionAndTranscriptExtension;
pub const proveEthereumSegmentWithEngineUsingExecution =
    guest_precompile.proveEthereumSegmentWithEngineUsingExecution;
pub const proveEthereumSegmentWithEngineUsingExecutionDiagnosed =
    guest_precompile.proveEthereumSegmentWithEngineUsingExecutionDiagnosed;
pub const proveEthereumSegmentWithEngineUsingMatchedAbExecutionDiagnosed =
    guest_precompile.proveEthereumSegmentWithEngineUsingMatchedAbExecutionDiagnosed;
pub const proveEthereumWithEngine = guest_precompile.proveEthereumWithEngine;
pub const proveEthereumWithEngineUsingChannel =
    guest_precompile.proveEthereumWithEngineUsingChannel;
pub const proveEthereumWithEngineUsingExecution =
    guest_precompile.proveEthereumWithEngineUsingExecution;
pub const provePoseidon2WithEngineAndPublicData = native.provePoseidon2WithEngineAndPublicData;
pub const provePoseidon2WithEngineAndPublicDataUsingChannel = native.provePoseidon2WithEngineAndPublicDataUsingChannel;
pub const provePoseidon2WithEngineAndPublicDataUsingChannelAndPhaseMeter = native.provePoseidon2WithEngineAndPublicDataUsingChannelAndPhaseMeter;
pub const proveRiscVSegmentLookupV1CompatibilityWithEngine = native.proveRiscVSegmentLookupV1CompatibilityWithEngine;
pub const proveRiscVSegmentLookupV1CompatibilityWithEngineUsingChannel = native.proveRiscVSegmentLookupV1CompatibilityWithEngineUsingChannel;
pub const proveRiscVSegmentLookupV2WithEngine = native.proveRiscVSegmentLookupV2WithEngine;
pub const proveRiscVSegmentLookupV2WithEngineUsingChannel = native.proveRiscVSegmentLookupV2WithEngineUsingChannel;
pub const proveRiscVSegmentV2WithEngine = native.proveRiscVSegmentV2WithEngine;
pub const proveRiscVSegmentV2WithEngineUsingChannel = native.proveRiscVSegmentV2WithEngineUsingChannel;
pub const proveRiscVSegmentV2WithEngineUsingChannelAndExecution = native.proveRiscVSegmentV2WithEngineUsingChannelAndExecution;
pub const proveRiscVSegmentV2WithEngineUsingChannelAndExecutionAndTranscriptExtension = native.proveRiscVSegmentV2WithEngineUsingChannelAndExecutionAndTranscriptExtension;
pub const proveRiscVTraceOnlyNoPublicIo = native.proveRiscVTraceOnlyNoPublicIo;
pub const proveRiscVTraceOnlyNoPublicIoUsingChannel = native.proveRiscVTraceOnlyNoPublicIoUsingChannel;
pub const proveRiscVWithEngineAndPublicData = native.proveRiscVWithEngineAndPublicData;
pub const proveRiscVWithEngineAndPublicDataUsingChannel = native.proveRiscVWithEngineAndPublicDataUsingChannel;
pub const proveRiscVWithEngineAndPublicDataUsingChannelAndExecution = native.proveRiscVWithEngineAndPublicDataUsingChannelAndExecution;
pub const proveRiscVWithEngineAndPublicDataUsingChannelAndPhaseMeter = native.proveRiscVWithEngineAndPublicDataUsingChannelAndPhaseMeter;
pub const proveRiscVWithEngineAndPublicDataWithExecution = native.proveRiscVWithEngineAndPublicDataWithExecution;
pub const selected_base_claims_v3 = native.selected_base_claims_v3;
pub const verifier_diagnostic_wiring_source = native.verifier_diagnostic_wiring_source;
pub const verifyEthereumSegmentWithEngine =
    guest_precompile.verifyEthereumSegmentWithEngine;
pub const verifyEthereumSegmentWithEngineAndCapture =
    guest_precompile.verifyEthereumSegmentWithEngineAndCapture;
pub const verifyEthereumSegmentWithEngineAndCaptureUsingChannel =
    guest_precompile.verifyEthereumSegmentWithEngineAndCaptureUsingChannel;
pub const verifyEthereumSegmentWithEngineAndEthereumV3Capture =
    guest_precompile.verifyEthereumSegmentWithEngineAndEthereumV3Capture;
pub const verifyEthereumSegmentWithEngineAndEthereumV3CaptureUsingChannel =
    guest_precompile.verifyEthereumSegmentWithEngineAndEthereumV3CaptureUsingChannel;
pub const verifyEthereumSegmentWithEngineAndEthereumV3CaptureUsingChannelAndTranscriptExtension =
    guest_precompile.verifyEthereumSegmentWithEngineAndEthereumV3CaptureUsingChannelAndTranscriptExtension;
pub const verifyEthereumSegmentWithEngineUsingChannel =
    guest_precompile.verifyEthereumSegmentWithEngineUsingChannel;
pub const verifyEthereumSegmentWithEngineUsingChannelAndNativeProviderOmission =
    guest_precompile.verifyEthereumSegmentWithEngineUsingChannelAndNativeProviderOmission;
pub const verifyEthereumSegmentWithEngineUsingChannelAndTranscriptExtension =
    guest_precompile.verifyEthereumSegmentWithEngineUsingChannelAndTranscriptExtension;
pub const verifyEthereumWithEngine = guest_precompile.verifyEthereumWithEngine;
pub const verifyEthereumWithEngineUsingChannel =
    guest_precompile.verifyEthereumWithEngineUsingChannel;
pub const verifyPoseidon2WithEngine = native.verifyPoseidon2WithEngine;
pub const verifyPoseidon2WithEngineUsingChannel = native.verifyPoseidon2WithEngineUsingChannel;
pub const verifyRiscVSegmentLookupV1CompatibilityWithEngine = native.verifyRiscVSegmentLookupV1CompatibilityWithEngine;
pub const verifyRiscVSegmentLookupV1CompatibilityWithEngineUsingChannel = native.verifyRiscVSegmentLookupV1CompatibilityWithEngineUsingChannel;
pub const verifyRiscVSegmentLookupV2WithEngine = native.verifyRiscVSegmentLookupV2WithEngine;
pub const verifyRiscVSegmentLookupV2WithEngineUsingChannel = native.verifyRiscVSegmentLookupV2WithEngineUsingChannel;
pub const verifyRiscVSegmentV2WithEngine = native.verifyRiscVSegmentV2WithEngine;
pub const verifyRiscVSegmentV2WithEngineUsingChannel = native.verifyRiscVSegmentV2WithEngineUsingChannel;
pub const verifyRiscVSegmentV2WithEngineUsingChannelAndCapture = native.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture;
pub const verifyRiscVSegmentV2WithEngineUsingChannelAndTranscriptExtension = native.verifyRiscVSegmentV2WithEngineUsingChannelAndTranscriptExtension;
pub const verifyRiscVWithEngine = native.verifyRiscVWithEngine;
pub const verifyRiscVWithEngineUsingChannel = native.verifyRiscVWithEngineUsingChannel;
pub const verifyRiscVWithEngineUsingChannelAndProofCapture = native.verifyRiscVWithEngineUsingChannelAndProofCapture;
pub const verifyRiscVWithEngineUsingChannelAndQueryCapture = native.verifyRiscVWithEngineUsingChannelAndQueryCapture;
pub const verifyRiscVWithEngineUsingChannelAndRecursiveLeafCapture = native.verifyRiscVWithEngineUsingChannelAndRecursiveLeafCapture;
