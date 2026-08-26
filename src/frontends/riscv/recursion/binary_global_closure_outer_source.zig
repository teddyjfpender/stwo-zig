//! Binary-parent authority for universal recursion relation closure.
//!
//! This module is a verifier-side aggregation boundary, not a new AIR and not
//! a parent prover. It consumes an exact ordered decomposition of rows 0--34's
//! framework claims by all 47 universal relation domains, plus the separately
//! authenticated row-35 `range_check_8_8` provider claim. Row 35 may contribute
//! only to that one domain; it can never be used as an arbitrary corrective
//! vector. Every domain and the framework-wide claimed sum must close to zero.
//!
//! `fillInto` is two-pass and failure-atomic for its fresh destination. The
//! first pass validates every tag, field word, row total, authority identity,
//! and alias boundary without writing scratch. The second pass uses one
//! retained, pointer-free workspace and performs no allocation.
const shard_0 = @import("binary_global_closure_outer_source_contract.zig");
const shard_1 = @import("binary_global_closure_outer_source_public_boundary_claim_v2.zig");
const shard_2 = @import("binary_global_closure_outer_source_closure_receipt_v2.zig");
const shard_3 = @import("binary_global_closure_outer_source_fill_into_v2.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SOURCE_AUTHORITY_FORMAT_VERSION = shard_0.SOURCE_AUTHORITY_FORMAT_VERSION;
pub const PROVIDER_CLAIM_FORMAT_VERSION = shard_0.PROVIDER_CLAIM_FORMAT_VERSION;
pub const WORKSPACE_FORMAT_VERSION = shard_0.WORKSPACE_FORMAT_VERSION;
pub const FORMAT_VERSION_V2 = shard_0.FORMAT_VERSION_V2;
pub const SOURCE_AUTHORITY_FORMAT_VERSION_V2 = shard_0.SOURCE_AUTHORITY_FORMAT_VERSION_V2;
pub const BOUNDARY_SOURCE_FORMAT_VERSION_V2 = shard_0.BOUNDARY_SOURCE_FORMAT_VERSION_V2;
pub const BOUNDARY_CLAIM_FORMAT_VERSION_V2 = shard_0.BOUNDARY_CLAIM_FORMAT_VERSION_V2;
pub const CLOSURE_INPUT_FORMAT_VERSION_V2 = shard_0.CLOSURE_INPUT_FORMAT_VERSION_V2;
pub const CLOSURE_RECEIPT_FORMAT_VERSION_V2 = shard_0.CLOSURE_RECEIPT_FORMAT_VERSION_V2;
pub const CONTEXT_SEAM_FORMAT_VERSION_V2 = shard_0.CONTEXT_SEAM_FORMAT_VERSION_V2;
pub const PREFIX_ROW_COUNT = shard_0.PREFIX_ROW_COUNT;
pub const TOTAL_ROW_COUNT = shard_0.TOTAL_ROW_COUNT;
pub const DOMAIN_COUNT = shard_0.DOMAIN_COUNT;
pub const PROVIDER_ROW = shard_0.PROVIDER_ROW;
pub const PROVIDER_DOMAIN = shard_0.PROVIDER_DOMAIN;
pub const WIRE_BOUNDARY_DOMAIN = shard_0.WIRE_BOUNDARY_DOMAIN;
pub const VERIFIER_INPUT_BOUNDARY_DOMAIN = shard_0.VERIFIER_INPUT_BOUNDARY_DOMAIN;
pub const PRESENT = shard_0.PRESENT;
pub const ACTIVE = shard_0.ACTIVE;
pub const PROTOCOL_SUBSTRATE_ONLY = shard_0.PROTOCOL_SUBSTRATE_ONLY;
pub const WHOLE_FRONTEND_VERIFIED = shard_0.WHOLE_FRONTEND_VERIFIED;
pub const PARENT_PROOF_VERIFICATION = shard_0.PARENT_PROOF_VERIFICATION;
pub const PARENT_PROOF_PRODUCTION = shard_0.PARENT_PROOF_PRODUCTION;
pub const PRODUCTION_ACTIVATION = shard_0.PRODUCTION_ACTIVATION;
pub const SOURCE_AUTHORITY_DOMAIN = shard_0.SOURCE_AUTHORITY_DOMAIN;
pub const ROSTER_PREFIX_DOMAIN = shard_0.ROSTER_PREFIX_DOMAIN;
pub const PROVIDER_CLAIM_ID_DOMAIN = shard_0.PROVIDER_CLAIM_ID_DOMAIN;
pub const INPUT_ID_DOMAIN = shard_0.INPUT_ID_DOMAIN;
pub const CLOSURE_ID_DOMAIN = shard_0.CLOSURE_ID_DOMAIN;
pub const SOURCE_AUTHORITY_DOMAIN_V2 = shard_0.SOURCE_AUTHORITY_DOMAIN_V2;
pub const BOUNDARY_SOURCE_ID_DOMAIN_V2 = shard_0.BOUNDARY_SOURCE_ID_DOMAIN_V2;
pub const BOUNDARY_CLAIM_ID_DOMAIN_V2 = shard_0.BOUNDARY_CLAIM_ID_DOMAIN_V2;
pub const CONTEXT_SEAM_ID_DOMAIN_V2 = shard_0.CONTEXT_SEAM_ID_DOMAIN_V2;
pub const INPUT_ID_DOMAIN_V2 = shard_0.INPUT_ID_DOMAIN_V2;
pub const CLOSURE_ID_DOMAIN_V2 = shard_0.CLOSURE_ID_DOMAIN_V2;
pub const Error = shard_0.Error;
/// Exact heap-allocation contract. Authority preparation, workspace creation,
/// first fill, and every reused-workspace fill are fixed-storage operations.
pub const AllocationLedgerV1 = shard_0.AllocationLedgerV1;
/// V2 retains the same fixed-storage hot-path contract. Boundary publications
/// and the temporal seam are pointer-free values admitted before filling.
pub const AllocationLedgerV2 = shard_0.AllocationLedgerV2;
pub const DomainClaimV1 = shard_0.DomainClaimV1;
/// One verifier-owned framework claim decomposed in exact universal registry
/// order. `claimed_sum` must equal the sum of all 47 domain values.
pub const RowClaimsV1 = shard_0.RowClaimsV1;
/// Separately admitted row-35 claim. `snapshot_id` identifies the immutable
/// binary range-provider snapshot from which the challenge-dependent claim was
/// computed; `source_authority_id` pins its one-source binary request ledger.
pub const ProviderClaimV1 = shard_0.ProviderClaimV1;
/// Fixed source contract for the 35 ordered prefix rows, the universal
/// relation registry, and the only provider authorized at row 35.
pub const SourceAuthorityV1 = shard_0.SourceAuthorityV1;
/// Cold capability. It contains no borrowed pointers and is not a wire type.
pub const PreparedAuthorityV1 = shard_0.PreparedAuthorityV1;
pub const prepareAuthority = shard_0.prepareAuthority;
/// The two public boundaries that are allowed to participate in V2 closure.
/// Their tags are semantic: a publication for one kind cannot be moved to the
/// other domain even when its scalar value happens to close the same residual.
pub const BoundaryKindV2 = shard_0.BoundaryKindV2;
pub const boundaryDomainV2 = shard_0.boundaryDomainV2;
/// Identity of one independently authenticated public-boundary producer.
/// `snapshot_id` names the immutable producer snapshot whose exact tuple
/// multiset is committed by each corresponding boundary claim.
pub const BoundarySourceV2 = shard_0.BoundarySourceV2;
/// Fixed ordering prevents a caller from using the wire publication as the
/// verifier-input publication (or vice versa).
pub const BoundaryAuthoritiesV2 = shard_0.BoundaryAuthoritiesV2;
/// Reserved full temporal-recursion context. No V2 API accepts a value of
/// this type: it is present so the future authority boundary cannot be added
/// piecemeal or silently omit one of the required bindings.
pub const RequiredContextV2 = shard_0.RequiredContextV2;
pub const ContextAvailabilityV2 = shard_0.ContextAvailabilityV2;
/// Fail-closed temporal seam. The only constructor in V2 publishes
/// `unavailable`; even a structurally complete caller-fabricated context is
/// rejected until a future prepared authority owns its authentication.
pub const ContextSeamV2 = shard_1.ContextSeamV2;
/// Versioned authority record for global closure. Its temporal seam is fixed
/// to unavailable; callers may select only already-authenticated boundary
/// source publications.
pub const SourceAuthorityV2 = shard_1.SourceAuthorityV2;
/// Cold, pointer-free capability consumed by V2 input preparation and fill.
pub const PreparedAuthorityV2 = shard_1.PreparedAuthorityV2;
pub const prepareAuthorityV2 = shard_1.prepareAuthorityV2;
/// Independently produced boundary evidence. The global closure layer does not
/// derive this scalar from its residual; it accepts it only when the source
/// and snapshot exactly match the prepared verifier authority.
pub const BoundaryEvidenceV2 = shard_0.BoundaryEvidenceV2;
pub const PublicBoundaryClaimV2 = shard_1.PublicBoundaryClaimV2;
pub const PublicBoundariesV2 = shard_1.PublicBoundariesV2;
/// Retained scratch for the second pass. Reinitializing these fixed arrays is
/// cheaper and safer than allocating one accumulator per proof.
pub const Workspace = shard_1.Workspace;
/// Fully materialized, pointer-free V2 closure input. The inherited V1 input
/// digest seals all 35 rows plus row 35's provider; the V2 identity additionally
/// seals the two independently authenticated public-boundary publications.
pub const ClosureInputV2 = shard_2.ClosureInputV2;
/// Canonical successful result. `prefix_totals` preserves the diagnostic
/// contribution before row 35; `closed_totals` and `framework_total` are
/// required to be exactly zero.
pub const ClosureReceiptV1 = shard_2.ClosureReceiptV1;
/// Canonical V2 result. The two public claims are retained with their complete
/// tuple provenance, and the reserved temporal context remains explicitly
/// unavailable. Successful substrate closure is therefore not equivalent to
/// temporal-recursion admission.
pub const ClosureReceiptV2 = shard_2.ClosureReceiptV2;
/// Allocation-free hot fill. The destination must equal `ClosureReceiptV1.fresh()`.
/// No destination field is written until every validation and closure check
/// has succeeded.
pub const fillInto = shard_2.fillInto;
/// Allocation-free V2 hot fill. Public boundaries are consumed only from the
/// two source-authenticated claims already sealed by `ClosureInputV2`; this
/// function never observes or constructs a residual-negation correction.
pub const fillIntoV2 = shard_3.fillIntoV2;
