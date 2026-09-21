//! CPU binding for the shared native FRI core.
const owner = @import("stwo_riscv_frontend").recursion.detached_fri_core_v2.ForBackend(@import("stwo_cpu_backend").CpuBackend);

pub const OuterProofCapture = owner.OuterProofCapture;
pub const POSEIDON2_ROSTER_ROW = owner.POSEIDON2_ROSTER_ROW;
pub const POSEIDON2_PARTIAL_COUNT = owner.POSEIDON2_PARTIAL_COUNT;
pub const POSEIDON2_COMPOSITION_CLAIM_INDICES = owner.POSEIDON2_COMPOSITION_CLAIM_INDICES;
pub const RELATION_REPLAY_FORMAT_VERSION = owner.RELATION_REPLAY_FORMAT_VERSION;
pub const RELATION_REPLAY_DOMAIN = owner.RELATION_REPLAY_DOMAIN;
pub const RELATION_REPLAY_HEAP_ALLOCATIONS = owner.RELATION_REPLAY_HEAP_ALLOCATIONS;
pub const POSEIDON2_AUXILIARY_CLAIM_FORMAT_VERSION = owner.POSEIDON2_AUXILIARY_CLAIM_FORMAT_VERSION;
pub const POSEIDON2_AUXILIARY_CLAIM_SEAL_DOMAIN = owner.POSEIDON2_AUXILIARY_CLAIM_SEAL_DOMAIN;
pub const SEGMENT_GLOBAL_CLOSURE_FORMAT_VERSION = owner.SEGMENT_GLOBAL_CLOSURE_FORMAT_VERSION;
pub const SEGMENT_GLOBAL_CLOSURE_CHECKED_DOMAINS = owner.SEGMENT_GLOBAL_CLOSURE_CHECKED_DOMAINS;
pub const SEGMENT_GLOBAL_CLOSURE_VERIFIER_TUPLE_LEDGER_ALLOCATIONS = owner.SEGMENT_GLOBAL_CLOSURE_VERIFIER_TUPLE_LEDGER_ALLOCATIONS;
pub const V2_ROWS_18_35_PREFLIGHT_FORMAT_VERSION = owner.V2_ROWS_18_35_PREFLIGHT_FORMAT_VERSION;
pub const V2_ROWS_18_35_HEAP_ALLOCATIONS = owner.V2_ROWS_18_35_HEAP_ALLOCATIONS;
pub const V2_CORE_ROWS_18_34_PREFLIGHT_FORMAT_VERSION = owner.V2_CORE_ROWS_18_34_PREFLIGHT_FORMAT_VERSION;
pub const V2_CORE_COHORT_FORMAT_VERSION = owner.V2_CORE_COHORT_FORMAT_VERSION;
pub const V2_CORE_COHORT_HOT_HEAP_ALLOCATIONS = owner.V2_CORE_COHORT_HOT_HEAP_ALLOCATIONS;
pub const V2_CORE_FIRST_ROW = owner.V2_CORE_FIRST_ROW;
pub const V2_CORE_LAST_ROW = owner.V2_CORE_LAST_ROW;
pub const V2_CORE_ROW_COUNT = owner.V2_CORE_ROW_COUNT;
pub const V2_UNIVERSAL_ROSTER_COMPONENT_COUNT = owner.V2_UNIVERSAL_ROSTER_COMPONENT_COUNT;
pub const V2_AUTHORITY_SOURCE_COMPONENT_COUNT = owner.V2_AUTHORITY_SOURCE_COMPONENT_COUNT;
pub const V2_TARGET_COMPONENT_COUNT = owner.V2_TARGET_COMPONENT_COUNT;
pub const RelationReplayReceiptV1 = owner.RelationReplayReceiptV1;
pub const Poseidon2AuxiliaryClaimSealV1 = owner.Poseidon2AuxiliaryClaimSealV1;
pub const VerifiedOuterProofV1 = owner.VerifiedOuterProofV1;
pub const SegmentProviderClaimV2 = owner.SegmentProviderClaimV2;
pub const SegmentGlobalClosureReceiptV2 = owner.SegmentGlobalClosureReceiptV2;
pub const VerifiedOuterProofV2 = owner.VerifiedOuterProofV2;
pub const FORMAT_VERSION = owner.FORMAT_VERSION;
pub const TRANSCRIPT_DOMAIN = owner.TRANSCRIPT_DOMAIN;
pub const SEGMENT_CIRCUIT_ID = owner.SEGMENT_CIRCUIT_ID;
pub const LEFT_CIRCUIT_ID = owner.LEFT_CIRCUIT_ID;
pub const RIGHT_CIRCUIT_ID = owner.RIGHT_CIRCUIT_ID;
pub const PCS_SEGMENT_CIRCUIT_ID = owner.PCS_SEGMENT_CIRCUIT_ID;
pub const PCS_LEFT_CIRCUIT_ID = owner.PCS_LEFT_CIRCUIT_ID;
pub const PCS_RIGHT_CIRCUIT_ID = owner.PCS_RIGHT_CIRCUIT_ID;
pub const VM_BINARY_CAPACITY_CIRCUIT_ID = owner.VM_BINARY_CAPACITY_CIRCUIT_ID;
pub const COMPOSITION_DIAGNOSTIC_ENV = owner.COMPOSITION_DIAGNOSTIC_ENV;
pub const captureProfileConfig = owner.captureProfileConfig;
pub const Error = owner.Error;
pub const V2CoreRows18Through34PreflightReceipt = owner.V2CoreRows18Through34PreflightReceipt;
pub const preflightV2CoreRows18Through34 = owner.preflightV2CoreRows18Through34;
pub const NATIVE_V2_CORE_FORMAT_VERSION = owner.NATIVE_V2_CORE_FORMAT_VERSION;
pub const NATIVE_V2_CORE_FIRST_ROW = owner.NATIVE_V2_CORE_FIRST_ROW;
pub const NATIVE_V2_CORE_LAST_ROW = owner.NATIVE_V2_CORE_LAST_ROW;
pub const NATIVE_V2_CORE_ROW_COUNT = owner.NATIVE_V2_CORE_ROW_COUNT;
pub const NATIVE_V2_CORE_HOT_TREE_HEAP_ALLOCATIONS = owner.NATIVE_V2_CORE_HOT_TREE_HEAP_ALLOCATIONS;
pub const NATIVE_V2_CORE_COLD_DOMAIN_AUDIT_ALLOCATION_CALLS = owner.NATIVE_V2_CORE_COLD_DOMAIN_AUDIT_ALLOCATION_CALLS;
pub const NATIVE_V2_CORE_INTERACTION_GENERATION_IS_COLD = owner.NATIVE_V2_CORE_INTERACTION_GENERATION_IS_COLD;
pub const NATIVE_V2_CORE_PROVIDER_INSTANCE_COUNT = owner.NATIVE_V2_CORE_PROVIDER_INSTANCE_COUNT;
pub const NATIVE_V2_CORE_RETAINS_SELF_POINTERS = owner.NATIVE_V2_CORE_RETAINS_SELF_POINTERS;
pub const NativeSegmentCoreAuthorityInputsV2 = owner.NativeSegmentCoreAuthorityInputsV2;
pub const NativeSegmentCoreAuthorityInputsV4 = owner.NativeSegmentCoreAuthorityInputsV4;
pub const NativeSegmentCoreGeneratedV2 = owner.NativeSegmentCoreGeneratedV2;
pub const NativeSegmentCoreComponentsV2 = owner.NativeSegmentCoreComponentsV2;
pub const NativeSegmentCoreV2 = owner.NativeSegmentCoreV2;
pub const NativeSegmentCoreLogSizesV2 = owner.NativeSegmentCoreLogSizesV2;
pub const selectPaddedNativeCoreLogSizesV2 = owner.selectPaddedNativeCoreLogSizesV2;
pub const NativeSegmentCoreComponentsForManifest = owner.NativeSegmentCoreComponentsForManifest;
pub const auditNativeSegmentCoreTypedAirRows = owner.auditNativeSegmentCoreTypedAirRows;
pub const initNativeSegmentCoreComponentsForManifest = owner.initNativeSegmentCoreComponentsForManifest;
pub const independentlyRebuildNativeSegmentCoreV2 = owner.independentlyRebuildNativeSegmentCoreV2;
pub const MutationProbeMode = owner.MutationProbeMode;
pub const ExecutionOptions = owner.ExecutionOptions;
pub const TupleClosureReport = owner.TupleClosureReport;
pub const TupleClosureFrontierReceipt = owner.TupleClosureFrontierReceipt;
pub const TUPLE_CLOSURE_FRONTIER_MASK = owner.TUPLE_CLOSURE_FRONTIER_MASK;
pub const VerifierPlans = owner.VerifierPlans;
pub const V2Rows18Through35PreflightReceipt = owner.V2Rows18Through35PreflightReceipt;
pub const preflightV2Rows18Through35 = owner.preflightV2Rows18Through35;
pub const SegmentPublicInputs = owner.SegmentPublicInputs;
pub const SegmentStatementInputs = owner.SegmentStatementInputs;
pub const SegmentTranscriptInputs = owner.SegmentTranscriptInputs;
pub const PreparedQueryWitness = owner.PreparedQueryWitness;
pub const AssemblyProfile = owner.AssemblyProfile;
pub const Receipt = owner.Receipt;
pub const proveAndVerifyCaptured = owner.proveAndVerifyCaptured;
pub const proveAndVerifyCapturedWithExecution = owner.proveAndVerifyCapturedWithExecution;
pub const proveAndVerifyCapturedWithVmAirExecution = owner.proveAndVerifyCapturedWithVmAirExecution;
pub const proveAndVerifyCapturedWithVmAirExecutionAndCapture = owner.proveAndVerifyCapturedWithVmAirExecutionAndCapture;
pub const proveAndVerifyCapturedWithVmAirExecutionAndAdmission = owner.proveAndVerifyCapturedWithVmAirExecutionAndAdmission;
pub const proveAndVerifyCapturedWithVmAirExecutionAndAdmissionV2 = owner.proveAndVerifyCapturedWithVmAirExecutionAndAdmissionV2;
pub const classifyCapturedTupleClosureWithVmAir = owner.classifyCapturedTupleClosureWithVmAir;
pub const manifestIdForSeal = owner.manifestIdForSeal;
pub const validateCompositionDiagnosticRoster = owner.validateCompositionDiagnosticRoster;
pub const diagnoseCompositionComponents = owner.diagnoseCompositionComponents;

test "segment global closure: native SegmentV2 core owner API is compile-complete" {
    try owner.testMovedCoremain_0();
}
test "segment global closure: recursion Poseidon2 native leaf segment closure rejects cross-domain cancellation" {
    try owner.testMovedCoremain_1();
}
test "segment global closure: recursion Poseidon2 native leaf segment closure receipt mutations and atomicity" {
    try owner.testMovedCoremain_2();
}
test "native SegmentV2 core admits only the canonical empty domain audit" {
    try owner.testMovedCore07_0();
}
test "fallible verifier handoff clears caller ownership atomically" {
    try owner.testMovedCore15_0();
}
test "outer verifier Poseidon2 auxiliary custody rejects every partial alias" {
    try owner.testMovedCore16_0();
}
test "outer verifier relation replay rejects checkpoint and identity mutation" {
    try owner.testMovedCore16_1();
}
test "composition diagnostic resolves legacy and universal gate names" {
    try owner.testMovedCore26_0();
}
