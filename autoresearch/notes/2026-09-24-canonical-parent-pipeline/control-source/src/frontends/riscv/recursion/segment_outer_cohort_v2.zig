//! Fail-closed assembly boundary for the append-only 39-row SegmentV2 outer
//! cohort.
//!
//! This module owns no AIR equation and fabricates no proof capability.  It
//! binds the typed catalog, exact authority roster, committed-tree geometry,
//! the one shared row-34 Poseidon schedule, proof-gate claims/components, and
//! all 47 interaction-domain residuals into versioned pointer-free receipts.
//! Production readiness remains unavailable until every named source exposes
//! verifier-custody components, tree commitments, and domain audits.
const shard_0 = @import("segment_outer_cohort_v2_contract.zig");
const shard_1 = @import("segment_outer_cohort_v2_cohort_plan_v2.zig");
const shard_2 = @import("segment_outer_cohort_v2_cohort.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const ROSTER_FORMAT_VERSION = shard_0.ROSTER_FORMAT_VERSION;
pub const TREE_PLAN_FORMAT_VERSION = shard_0.TREE_PLAN_FORMAT_VERSION;
pub const PROVIDER_SCHEDULE_FORMAT_VERSION = shard_0.PROVIDER_SCHEDULE_FORMAT_VERSION;
pub const GATE_RECEIPT_FORMAT_VERSION = shard_0.GATE_RECEIPT_FORMAT_VERSION;
pub const CLOSURE_RECEIPT_FORMAT_VERSION = shard_0.CLOSURE_RECEIPT_FORMAT_VERSION;
pub const PUBLIC_WIRE_BOUNDARY_FORMAT_VERSION = shard_0.PUBLIC_WIRE_BOUNDARY_FORMAT_VERSION;
pub const READINESS_RECEIPT_FORMAT_VERSION = shard_0.READINESS_RECEIPT_FORMAT_VERSION;
pub const COMPONENT_COUNT = shard_0.COMPONENT_COUNT;
pub const DOMAIN_COUNT = shard_0.DOMAIN_COUNT;
pub const TREE_COUNT = shard_0.TREE_COUNT;
pub const ALL_COMPONENT_MASK = shard_0.ALL_COMPONENT_MASK;
pub const ALL_DOMAIN_MASK = shard_0.ALL_DOMAIN_MASK;
pub const TRANSCRIPT_ROWS_MASK = shard_0.TRANSCRIPT_ROWS_MASK;
pub const STATEMENT_ROWS_MASK = shard_0.STATEMENT_ROWS_MASK;
pub const PUBLIC_ROWS_MASK = shard_0.PUBLIC_ROWS_MASK;
pub const CORE_ROWS_MASK = shard_0.CORE_ROWS_MASK;
pub const RANGE_ROW_MASK = shard_0.RANGE_ROW_MASK;
pub const BOUNDARY_ROWS_MASK = shard_0.BOUNDARY_ROWS_MASK;
pub const VERIFIER_INPUT_PROVIDER_ROW_MASK = shard_0.VERIFIER_INPUT_PROVIDER_ROW_MASK;
pub const ROW_34 = shard_0.ROW_34;
pub const ROW_35 = shard_0.ROW_35;
pub const ROW_10 = shard_0.ROW_10;
/// Measured canonical SegmentV2 ingress. These are measurement evidence, not
/// protocol constants: admission derives counts from the authenticated shared
/// layout and validates the resulting minimal log size.
pub const MEASURED_TRANSCRIPT_POSEIDON_CALLS = shard_0.MEASURED_TRANSCRIPT_POSEIDON_CALLS;
pub const MEASURED_AUTHORITY_POSEIDON_CALLS = shard_0.MEASURED_AUTHORITY_POSEIDON_CALLS;
pub const MEASURED_CORE_POSEIDON_CALLS = shard_0.MEASURED_CORE_POSEIDON_CALLS;
pub const MEASURED_TOTAL_POSEIDON_CALLS = shard_0.MEASURED_TOTAL_POSEIDON_CALLS;
pub const MEASURED_POSEIDON_LOG_SIZE = shard_0.MEASURED_POSEIDON_LOG_SIZE;
pub const HOT_ASSEMBLY_HEAP_ALLOCATIONS = shard_0.HOT_ASSEMBLY_HEAP_ALLOCATIONS;
pub const HOT_VALIDATION_HEAP_ALLOCATIONS = shard_0.HOT_VALIDATION_HEAP_ALLOCATIONS;
pub const HOT_IDENTITY_HEAP_ALLOCATIONS = shard_0.HOT_IDENTITY_HEAP_ALLOCATIONS;
pub const FAILS_BEFORE_FIRST_EXTERNAL_WRITE = shard_0.FAILS_BEFORE_FIRST_EXTERNAL_WRITE;
pub const PRODUCTION_ACTIVATION = shard_0.PRODUCTION_ACTIVATION;
pub const PLAN_ID_DOMAIN = shard_0.PLAN_ID_DOMAIN;
pub const ROSTER_ID_DOMAIN = shard_0.ROSTER_ID_DOMAIN;
pub const TREE_PLAN_ID_DOMAIN = shard_0.TREE_PLAN_ID_DOMAIN;
pub const CAPABILITY_ID_DOMAIN = shard_0.CAPABILITY_ID_DOMAIN;
pub const GATE_RECEIPT_ID_DOMAIN = shard_0.GATE_RECEIPT_ID_DOMAIN;
pub const CLOSURE_RECEIPT_ID_DOMAIN = shard_0.CLOSURE_RECEIPT_ID_DOMAIN;
pub const AUDIT_ID_DOMAIN = shard_0.AUDIT_ID_DOMAIN;
pub const PUBLIC_WIRE_BOUNDARY_ID_DOMAIN = shard_0.PUBLIC_WIRE_BOUNDARY_ID_DOMAIN;
pub const BOUNDARY_AUDIT_ID_DOMAIN = shard_0.BOUNDARY_AUDIT_ID_DOMAIN;
pub const READINESS_RECEIPT_ID_DOMAIN = shard_0.READINESS_RECEIPT_ID_DOMAIN;
pub const Error = shard_0.Error;
pub const RowAuthority = shard_0.RowAuthority;
pub const RosterPlanV2 = shard_0.RosterPlanV2;
pub const RowTreeGeometryV2 = shard_0.RowTreeGeometryV2;
pub const TreePlanV2 = shard_0.TreePlanV2;
pub const ProviderOrigin = shard_0.ProviderOrigin;
pub const ProviderRangeV2 = shard_0.ProviderRangeV2;
pub const ProviderCallCountsV2 = shard_0.ProviderCallCountsV2;
/// One contiguous provider instance, with three non-overlapping source-owned
/// ranges. It never permits separate row-34 components or corrective claims.
pub const ProviderScheduleV2 = shard_0.ProviderScheduleV2;
pub const Capability = shard_0.Capability;
pub const CAPABILITY_COUNT = shard_0.CAPABILITY_COUNT;
pub const ALL_CAPABILITY_MASK = shard_0.ALL_CAPABILITY_MASK;
/// APIs which are present in the tree today. Availability is kept separate
/// from proof evidence: no bit here says that one concrete proof populated a
/// row, closed a domain, or produced a commitment.
pub const LANDED_CAPABILITY_MASK = shard_0.LANDED_CAPABILITY_MASK;
pub const LANDED_COMPONENT_ROW_MASK = shard_0.LANDED_COMPONENT_ROW_MASK;
pub const MISSING_COMPONENT_ROW_MASK = shard_0.MISSING_COMPONENT_ROW_MASK;
pub const CapabilityLedgerV2 = shard_1.CapabilityLedgerV2;
/// Allocation-free protocol plan. It authenticates only immutable geometry
/// and scheduling; runtime claims/components are admitted separately through
/// `GateReceiptV2` after a complete proof gate seals.
pub const CohortPlanV2 = shard_1.CohortPlanV2;
/// Exact claims/components capture from the sealed 39-row gate. This is the
/// only cohort API which may report complete component coverage.
pub const GateReceiptV2 = shard_1.GateReceiptV2;
/// Versioned verifier-owned boundary for the arithmetic lowering's live
/// constants and designated zero outputs.  It is not a fabricated component
/// claim: the concrete cohort derives it from its pre-challenge-sealed core and
/// the already drawn universal relation.  `term_count` retains geometry that
/// is intentionally disjoint from committed logical/event row accounting.
pub const PublicWireBoundaryV2 = shard_1.PublicWireBoundaryV2;
pub const ClosureSummaryV2 = shard_1.ClosureSummaryV2;
/// Verifies every row claim and every universal domain. It also enforces that
/// the two shared providers contribute only in their respective domains.
/// Audit custody is deliberately addressed by the receipt layer below.
pub const verifyInteractionClosure = shard_1.verifyInteractionClosure;
/// Boundary-aware whole-cohort closure used by the concrete SegmentV2 proof.
/// The boundary is a typed, identity-bound scalar projection of canonical base
/// tuples; omission and sign substitution therefore remain distinguishable
/// from an ordinary row-claim failure.
pub const verifyInteractionClosureV2 = shard_1.verifyInteractionClosureV2;
pub const AuditCustody = shard_1.AuditCustody;
/// Algebraically exact closure receipt tied to a complete gate. Its custody is
/// explicit and cannot be confused with independent-verifier evidence.
pub const GeneratedClosureReceiptV2 = shard_2.GeneratedClosureReceiptV2;
/// Pointer-free statement of exactly what remains before this cohort may be
/// handed to the proof engine.  A receipt is useful while red: it prevents a
/// caller from turning source availability into proof evidence and gives
/// review tooling one deterministic object to compare across revisions.
pub const ProductionReadinessReceiptV2 = shard_2.ProductionReadinessReceiptV2;
/// Compile-valid engine surface while the two missing authority owners are
/// being completed.  It is intentionally unconstructible: this keeps the CPU
/// engine contract type-checkable without inventing trace data, detached
/// claims, or a green readiness bit.  Once both owners expose concrete input
/// and generated-interaction types, this seam is replaced by composition and
/// a named production alias is exported.
pub const Cohort = shard_2.Cohort;
pub const CONCRETE_PRODUCTION_COHORT_AVAILABLE = shard_2.CONCRETE_PRODUCTION_COHORT_AVAILABLE;
