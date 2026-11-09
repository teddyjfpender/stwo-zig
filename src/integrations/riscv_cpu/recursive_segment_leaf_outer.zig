//! CPU binding for the shared native-leaf preparation owner.
const frontend = @import("stwo_riscv_frontend");
const core = @import("recursive_fri_outer.zig");

/// The native ingestion binding uses the Poseidon2-M31 suite. Other suites
/// cannot populate the universal Poseidon verifier rows.
pub const Engine = frontend.recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
pub const NativeCapture = frontend.prover_mod.VerifiedSegmentV2CaptureForEngine(Engine);

// Keep the remaining integration dependency narrow and visible. The shared
// preparation owner does not select or import the concrete core authority.
const CorePreflight = struct {
    pub const V2CoreRows18Through34PreflightReceipt = core.V2CoreRows18Through34PreflightReceipt;
    pub const V2Rows18Through35PreflightReceipt = core.V2Rows18Through35PreflightReceipt;
    pub const V2_TARGET_COMPONENT_COUNT = core.V2_TARGET_COMPONENT_COUNT;
    pub const V2_UNIVERSAL_ROSTER_COMPONENT_COUNT = core.V2_UNIVERSAL_ROSTER_COMPONENT_COUNT;
    pub const VerifierPlans = core.VerifierPlans;
    pub const preflightV2CoreRows18Through34 = core.preflightV2CoreRows18Through34;
    pub const preflightV2Rows18Through35 = core.preflightV2Rows18Through35;
};
const owner = frontend.recursion.detached_native_leaf_preparation_v2.Preparation(NativeCapture, CorePreflight);

pub const Digest = owner.Digest;
pub const Sha256Digest = owner.Sha256Digest;
pub const FORMAT_VERSION = owner.FORMAT_VERSION;
pub const SCHEMA_VERSION = owner.SCHEMA_VERSION;
pub const CALL_LAYOUT_SCHEMA_VERSION = owner.CALL_LAYOUT_SCHEMA_VERSION;
pub const BUNDLE_ID_DOMAIN = owner.BUNDLE_ID_DOMAIN;
pub const CALL_LAYOUT_ID_DOMAIN = owner.CALL_LAYOUT_ID_DOMAIN;
pub const CALL_BUFFER_ID_DOMAIN = owner.CALL_BUFFER_ID_DOMAIN;
pub const TRACE_ID_DOMAIN = owner.TRACE_ID_DOMAIN;
pub const CAPTURE_CUSTODY_REQUIRED = owner.CAPTURE_CUSTODY_REQUIRED;
pub const TRANSCRIPT_PROGRAM_V2_EXACT = owner.TRANSCRIPT_PROGRAM_V2_EXACT;
pub const SHARED_ROW34_PROVIDER_COUNT = owner.SHARED_ROW34_PROVIDER_COUNT;
pub const ROW34_BOUNDARY_PREFIX_AVAILABLE = owner.ROW34_BOUNDARY_PREFIX_AVAILABLE;
pub const ROW34_COMPLETE_LAYOUT_SUPPORTED = owner.ROW34_COMPLETE_LAYOUT_SUPPORTED;
pub const ROW34_VERIFIER_CORE_RANGE_POPULATED = owner.ROW34_VERIFIER_CORE_RANGE_POPULATED;
pub const ROW34_CALL_SET_COMPLETE = owner.ROW34_CALL_SET_COMPLETE;
pub const ROWS_0_9_PUBLISHABLE = owner.ROWS_0_9_PUBLISHABLE;
pub const EXACT_47_DOMAIN_CLOSURE_AVAILABLE = owner.EXACT_47_DOMAIN_CLOSURE_AVAILABLE;
pub const OUTER_STARK_VERIFIED = owner.OUTER_STARK_VERIFIED;
pub const PRODUCTION_ACTIVATION = owner.PRODUCTION_ACTIVATION;
pub const Error = owner.Error;
pub const CallRange = owner.CallRange;
pub const SharedPoseidonCallLayoutV2 = owner.SharedPoseidonCallLayoutV2;
pub const OwnedCompletePoseidonScheduleV2 = owner.OwnedCompletePoseidonScheduleV2;
pub const OwnedAuthorityTracesV2 = owner.OwnedAuthorityTracesV2;
pub const PreparedNativeV2LeafOuter = owner.PreparedNativeV2LeafOuter;
