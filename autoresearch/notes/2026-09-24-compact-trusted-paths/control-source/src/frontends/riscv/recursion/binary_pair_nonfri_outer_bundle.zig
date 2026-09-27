//! Authenticated binary-parent assembly boundary for universal rows 0--17/35.
//!
//! This module owns no AIR equation. It composes the existing authenticated
//! transcript source (rows 0--9), statement source (rows 10--11 and the
//! separately owned row-35 provider), and binary VM-public source (inactive
//! rows 12--16 plus live row 17). Rows 18--34 remain the FRI bundle's sole
//! responsibility.
//!
//! Row 35 is never accepted as a detached corrective scalar. The generation
//! path seals the claim beside the actual retained provider-batch identity.
//! The cold audit path then proves that this claim is the range-only provider
//! audit and cancels the exact range contribution reconstructed from rows
//! 0--17. The resulting pointer-free handoff is suitable for the all-36
//! global-closure authority. A true verifier-custody adapter remains an
//! explicit unavailable seam until the independent outer verifier publishes
//! the same domain audit receipt transactionally.
//!
//! Hot fills require a fresh-zero destination for every owned column. The
//! transactional preflight authenticates the manifest exactly once, reads its
//! sealed placement table directly thereafter, and represents ownership as
//! the two roster-contiguous column ranges `[0, 18)` and row 35. No manifest
//! hash or placement lookup occurs inside the quadratic alias scan.
const shard_0 = @import("binary_pair_nonfri_outer_bundle_contract.zig");
const shard_1 = @import("binary_pair_nonfri_outer_bundle_owned_tree_ranges.zig");
const shard_2 = @import("binary_pair_nonfri_outer_bundle_bundle.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const GENERATED_FORMAT_VERSION = shard_0.GENERATED_FORMAT_VERSION;
pub const AUDITED_FORMAT_VERSION = shard_0.AUDITED_FORMAT_VERSION;
pub const FIRST_PREFIX_ROW = shard_0.FIRST_PREFIX_ROW;
pub const PREFIX_ROW_COUNT = shard_0.PREFIX_ROW_COUNT;
pub const LAST_PREFIX_ROW = shard_0.LAST_PREFIX_ROW;
pub const SHARED_PROVIDER_ROW = shard_0.SHARED_PROVIDER_ROW;
pub const OWNED_ROW_COUNT = shard_0.OWNED_ROW_COUNT;
pub const PROTOCOL_SUBSTRATE_ONLY = shard_0.PROTOCOL_SUBSTRATE_ONLY;
pub const WHOLE_FRONTEND_VERIFIED = shard_0.WHOLE_FRONTEND_VERIFIED;
pub const COMPLETE_PARENT_STARK_VERIFIED = shard_0.COMPLETE_PARENT_STARK_VERIFIED;
pub const PRODUCTION_ACTIVATION = shard_0.PRODUCTION_ACTIVATION;
/// Current source costs. The bundle itself performs no heap allocation.
/// Rows 12--17 still inherit their source's transactional staging cost.
pub const HOT_BUNDLE_OVERHEAD_HEAP_ALLOCATIONS = shard_0.HOT_BUNDLE_OVERHEAD_HEAP_ALLOCATIONS;
pub const HOT_TREE_HEAP_ALLOCATIONS = shard_0.HOT_TREE_HEAP_ALLOCATIONS;
pub const HOT_ALL_TREES_HEAP_ALLOCATIONS = shard_0.HOT_ALL_TREES_HEAP_ALLOCATIONS;
pub const HOT_TREE_PAIR_AUTHENTICATIONS = shard_0.HOT_TREE_PAIR_AUTHENTICATIONS;
pub const HOT_ALL_TREES_PAIR_AUTHENTICATIONS = shard_0.HOT_ALL_TREES_PAIR_AUTHENTICATIONS;
pub const GENERATED_RECEIPT_HEAP_ALLOCATIONS = shard_0.GENERATED_RECEIPT_HEAP_ALLOCATIONS;
pub const AUDITED_HANDOFF_HEAP_ALLOCATIONS = shard_0.AUDITED_HANDOFF_HEAP_ALLOCATIONS;
/// Exact successful-preflight work per committed tree. `Manifest.placement`
/// revalidates and rehashes all 36 rows, so the hot boundary must never use it
/// after the one explicit validation. Nineteen reads check owned geometry and
/// fresh-zero storage; three reads prepare the prefix/provider range ends.
pub const HOT_PREFLIGHT_MANIFEST_VALIDATIONS_PER_TREE = shard_0.HOT_PREFLIGHT_MANIFEST_VALIDATIONS_PER_TREE;
pub const HOT_PREFLIGHT_DIRECT_PLACEMENT_READS_PER_TREE = shard_0.HOT_PREFLIGHT_DIRECT_PLACEMENT_READS_PER_TREE;
pub const HOT_PREFLIGHT_OWNERSHIP_RANGES_PER_TREE = shard_0.HOT_PREFLIGHT_OWNERSHIP_RANGES_PER_TREE;
pub const HOT_ALIAS_LOOP_PLACEMENT_READS_PER_TREE = shard_0.HOT_ALIAS_LOOP_PLACEMENT_READS_PER_TREE;
/// Rollback runs only after a successful preflight, so it may use the same
/// authenticated placement table without another manifest hash.
pub const HOT_ROLLBACK_DIRECT_PLACEMENT_READS_PER_TREE = shard_0.HOT_ROLLBACK_DIRECT_PLACEMENT_READS_PER_TREE;
/// The prover/generator custody path is implemented below. Independent
/// verifier custody must not be simulated with caller-authored claims.
pub const VERIFIER_DOMAIN_AUDIT_CUSTODY_EXPOSED = shard_0.VERIFIER_DOMAIN_AUDIT_CUSTODY_EXPOSED;
pub const BUNDLE_ID_DOMAIN = shard_0.BUNDLE_ID_DOMAIN;
pub const GENERATED_ID_DOMAIN = shard_0.GENERATED_ID_DOMAIN;
pub const AUDITED_ID_DOMAIN = shard_0.AUDITED_ID_DOMAIN;
pub const Error = shard_0.Error;
pub const Claims = shard_0.Claims;
pub const DomainAudits = shard_0.DomainAudits;
/// Pointer-free receipt emitted only after all three real generators commit.
pub const GeneratedInteractionsV1 = shard_0.GeneratedInteractionsV1;
/// Pointer-free, verifier-ready handoff for rows 0--17 and row 35. It is not
/// a complete global closure: rows 18--34 must be inserted by the FRI owner.
pub const AuditedInteractionsV1 = shard_0.AuditedInteractionsV1;
pub const Components = shard_0.Components;
pub const VerifierDomainAuditAdapterV1 = shard_0.VerifierDomainAuditAdapterV1;
/// Source-custody bundle. Transcript and statement proof profiles may differ;
/// their shared parent context and exact statement preimages are cross-bound.
pub const Bundle = shard_2.Bundle;
