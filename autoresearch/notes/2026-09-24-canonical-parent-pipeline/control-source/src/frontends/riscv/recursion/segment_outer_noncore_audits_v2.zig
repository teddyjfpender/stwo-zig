//! Verifier-rebuildable exact-domain custody for SegmentV2 non-core rows.
//!
//! This module composes the authenticated relation plans and rows already
//! owned by transcript (0--9), statement (10--11), public (12--17), range
//! provider (35), boundary source (36--37), and committed verifier-input
//! provider (38) authorities. It does not accept detached row claims or
//! aggregate-only closure. Every row claim is checked against its exact
//! 47-domain decomposition before one pointer-free receipt is returned. Rows
//! 18--34 remain exclusively owned by the verifier core.
const shard_0 = @import("segment_outer_noncore_audits_v2_contract.zig");
const shard_1 = @import("segment_outer_noncore_audits_v2_rebuild.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SCHEMA_VERSION = shard_0.SCHEMA_VERSION;
pub const COMPONENT_COUNT = shard_0.COMPONENT_COUNT;
pub const DOMAIN_COUNT = shard_0.DOMAIN_COUNT;
pub const NONCORE_ROW_COUNT = shard_0.NONCORE_ROW_COUNT;
pub const CORE_FIRST_ROW = shard_0.CORE_FIRST_ROW;
pub const CORE_LAST_ROW = shard_0.CORE_LAST_ROW;
pub const CORE_ROW_COUNT = shard_0.CORE_ROW_COUNT;
pub const NONCORE_ROW_INDICES = shard_0.NONCORE_ROW_INDICES;
pub const NONCORE_ROW_MASK = shard_0.NONCORE_ROW_MASK;
pub const CORE_ROW_MASK = shard_0.CORE_ROW_MASK;
pub const ALL_ROW_MASK = shard_0.ALL_ROW_MASK;
/// `auditPreparedDomainSums` makes two bounded temporary allocations per
/// typed framework plan. Eighteen rows use that path. The single-domain range
/// provider, the two prepared boundary-domain receipts, and the committed
/// verifier-input provider receipt allocate nothing.
pub const COLD_TYPED_AUDIT_ALLOCATION_CALLS = shard_0.COLD_TYPED_AUDIT_ALLOCATION_CALLS;
pub const HOT_AUDIT_HEAP_ALLOCATIONS = shard_0.HOT_AUDIT_HEAP_ALLOCATIONS;
pub const HOT_INSTALL_HEAP_ALLOCATIONS = shard_0.HOT_INSTALL_HEAP_ALLOCATIONS;
pub const REBUILD_AND_INSTALL_REDUNDANT_AUDIT_PASSES = shard_0.REBUILD_AND_INSTALL_REDUNDANT_AUDIT_PASSES;
pub const FAILS_BEFORE_FIRST_EXTERNAL_WRITE = shard_0.FAILS_BEFORE_FIRST_EXTERNAL_WRITE;
pub const NONCORE_AUDITS_AVAILABLE = shard_0.NONCORE_AUDITS_AVAILABLE;
pub const WHOLE_COHORT_AUDITS_AVAILABLE = shard_0.WHOLE_COHORT_AUDITS_AVAILABLE;
pub const PRODUCTION_ACTIVATION = shard_0.PRODUCTION_ACTIVATION;
pub const ROW17_LOGICAL_ROWS = shard_0.ROW17_LOGICAL_ROWS;
pub const ROW17_TYPED_EVENT_TERMS = shard_0.ROW17_TYPED_EVENT_TERMS;
pub const ROW17_ACTIVE_RELATION_EVENTS = shard_0.ROW17_ACTIVE_RELATION_EVENTS;
pub const RECEIPT_ID_DOMAIN = shard_0.RECEIPT_ID_DOMAIN;
pub const RELATION_CONTEXT_ID_DOMAIN = shard_0.RELATION_CONTEXT_ID_DOMAIN;
pub const Error = shard_0.Error;
pub const TranscriptInputsV2 = shard_0.TranscriptInputsV2;
pub const StatementInputsV2 = shard_0.StatementInputsV2;
pub const PublicInputsV2 = shard_0.PublicInputsV2;
pub const RangeInputsV2 = shard_0.RangeInputsV2;
/// This must be the independently rebuilt capture-backed boundary authority,
/// never the source-preflight-only `PreparedOuterAuthorityV2`.
pub const BoundaryInputsV2 = shard_0.BoundaryInputsV2;
pub const VerifierInputProviderInputsV2 = shard_0.VerifierInputProviderInputsV2;
pub const InputsV2 = shard_0.InputsV2;
pub const Custody = shard_0.Custody;
/// Pointer-free, exact-domain non-core receipt. `rows` and `claims` use the
/// order in `NONCORE_ROW_INDICES`; no absent core row is represented by a
/// fabricated zero audit.
pub const AuditsV2 = shard_0.AuditsV2;
/// Rebuilds every non-core audit into stack staging. No caller-owned output is
/// exposed until every source, claim, relation context, and row decomposition
/// has succeeded.
pub const rebuild = shard_1.rebuild;
/// Replays every authenticated non-core source and only then installs all 22
/// rows into cohort storage. This is the preferred integration API: callers
/// cannot accidentally install a receipt rebuilt from different Tree-2
/// owners, logical rows, range requests, or boundary capture.
pub const rebuildAndInstall = shard_1.rebuildAndInstall;
/// Cold revalidation for a retained receipt. This deliberately performs the
/// full authenticated replay rather than trusting its digest as a MAC.
pub const validateAgainstInputs = shard_1.validateAgainstInputs;
