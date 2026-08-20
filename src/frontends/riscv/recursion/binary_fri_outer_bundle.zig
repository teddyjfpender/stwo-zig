//! Neutral rows-18--34 assembly for an authenticated binary recursion node.
//!
//! This bundle deliberately knows nothing about the V1 shadow's split
//! `core_request`/`poseidon2_provider` child roles.  It accepts only the two
//! children already admitted by `binary_fri_outer_source`, writes their exact
//! FRI/composition cohort, and delegates row 34 to the existing native
//! Poseidon2 component.  Joining this neutral cohort to a complete parent
//! statement remains protocol substrate until a versioned parent child-role
//! and session authority exists.

const shard_0 = @import("binary_fri_outer_bundle_adapters_for_manifest.zig");
const shard_1 = @import("binary_fri_outer_bundle_bundle_for_source_schedule_and_manifest.zig");
const shard_2 = @import("binary_fri_outer_bundle_bind_owned_columns.zig");

pub const AdaptersForManifest = shard_0.AdaptersForManifest;
pub const CompositionInputAdapter = shard_0.CompositionInputAdapter;
pub const CompositionControlAdapter = shard_0.CompositionControlAdapter;
pub const QueryBitsAdapter = shard_0.QueryBitsAdapter;
pub const QueryMappingAdapter = shard_0.QueryMappingAdapter;
pub const MerkleRootAdapter = shard_0.MerkleRootAdapter;
pub const TraceMerkleAdapter = shard_0.TraceMerkleAdapter;
pub const PcsAdapter = shard_0.PcsAdapter;
pub const FriLeafAdapter = shard_0.FriLeafAdapter;
pub const FriNodeAdapter = shard_0.FriNodeAdapter;
pub const FriAnchorAdapter = shard_0.FriAnchorAdapter;
pub const FriControlAdapter = shard_0.FriControlAdapter;
pub const FriInputAdapter = shard_0.FriInputAdapter;
pub const MultiplyAdapter = shard_0.MultiplyAdapter;
pub const InverseAdapter = shard_0.InverseAdapter;
pub const LinearAdapter = shard_0.LinearAdapter;
pub const MerklePathAdapter = shard_0.MerklePathAdapter;
pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const GENERATED_FORMAT_VERSION = shard_0.GENERATED_FORMAT_VERSION;
pub const AUDITED_FORMAT_VERSION = shard_0.AUDITED_FORMAT_VERSION;
pub const PROTOCOL_SUBSTRATE_ONLY = shard_0.PROTOCOL_SUBSTRATE_ONLY;
pub const WHOLE_FRONTEND_VERIFIED = shard_0.WHOLE_FRONTEND_VERIFIED;
pub const COMPLETE_PARENT_STARK_VERIFIED = shard_0.COMPLETE_PARENT_STARK_VERIFIED;
pub const PRODUCTION_ACTIVATION = shard_0.PRODUCTION_ACTIVATION;
pub const CHILD_ROLE_SESSION_AUTHORITY_VERSION = shard_0.CHILD_ROLE_SESSION_AUTHORITY_VERSION;
pub const ProviderCustody = shard_0.ProviderCustody;
pub const FIRST_ROW = shard_0.FIRST_ROW;
pub const LAST_ROW = shard_0.LAST_ROW;
pub const ROW_COUNT = shard_0.ROW_COUNT;
pub const TYPED_ROW_COUNT = shard_0.TYPED_ROW_COUNT;
pub const PREPROCESSED_COLUMNS_PER_ROW = shard_0.PREPROCESSED_COLUMNS_PER_ROW;
pub const MAIN_COLUMNS_PER_ROW = shard_0.MAIN_COLUMNS_PER_ROW;
pub const INTERACTION_COLUMNS_PER_ROW = shard_0.INTERACTION_COLUMNS_PER_ROW;
pub const PREPROCESSED_COLUMN_COUNT = shard_0.PREPROCESSED_COLUMN_COUNT;
pub const MAIN_COLUMN_COUNT = shard_0.MAIN_COLUMN_COUNT;
pub const INTERACTION_COLUMN_COUNT = shard_0.INTERACTION_COLUMN_COUNT;
pub const HOT_TREE_HEAP_ALLOCATIONS = shard_0.HOT_TREE_HEAP_ALLOCATIONS;
pub const HOT_ALL_TREES_HEAP_ALLOCATIONS = shard_0.HOT_ALL_TREES_HEAP_ALLOCATIONS;
pub const ROW34_REPLAYED_SCALAR_PERMUTATIONS = shard_0.ROW34_REPLAYED_SCALAR_PERMUTATIONS;
pub const BUNDLE_ID_DOMAIN = shard_0.BUNDLE_ID_DOMAIN;
pub const GENERATED_ID_DOMAIN = shard_0.GENERATED_ID_DOMAIN;
pub const AUDITED_ID_DOMAIN = shard_0.AUDITED_ID_DOMAIN;
pub const Error = shard_0.Error;
pub const Claims = shard_0.Claims;
pub const DomainAudits = shard_0.DomainAudits;
/// Pointer-free publication emitted only after all 17 interaction rows have
/// been generated from retained authority. Row 34 keeps its two native
/// recurrence claims; `poseidon2Total` is only the roster projection.
pub const GeneratedInteractionsV1 = shard_0.GeneratedInteractionsV1;
/// Independent domain replay of the generated claims. This remains a
/// prover-side/cold audit receipt; it is not mislabeled as final recursive
/// verifier custody while the parent protocol is substrate-only.
pub const AuditedInteractionsV1 = shard_0.AuditedInteractionsV1;
pub const ComponentsForManifest = shard_0.ComponentsForManifest;
pub const Components = shard_0.Components;
/// Owns every cold workspace needed by the neutral rows-18--34 cohort.
pub const Bundle = shard_0.Bundle;
/// Version-parametric concrete owner for rows 18--34. The AIR programs and
/// witness source remain unique; only manifest/claim/gate placement changes.
pub const BundleForManifest = shard_0.BundleForManifest;
/// Authority-parametric owner for rows 18--34.  The source type is a narrow
/// dependency-injection seam for independently authenticated child-proof
/// profiles (for example the 39-claim SegmentV2 temporal child).  It must
/// expose the exact `binary_fri_outer_source.Source` contract; all AIR,
/// witness, provider, and hot-writer implementations remain unique here.
///
/// Keeping this seam at comptime preserves direct calls and monomorphized hot
/// loops.  There is no virtual dispatch, function-pointer table, or runtime
/// proof-kind branch in the trace-generation path.
pub const BundleForSourceAndManifest = shard_0.BundleForSourceAndManifest;
/// Schedule-parametric form used by authenticated proof kinds whose prefix
/// call ranges differ from frozen SegmentV2. The schedule contract is resolved
/// entirely at comptime, preserving the same direct hot loops as V2.
pub const BundleForSourceScheduleAndManifest = shard_1.BundleForSourceScheduleAndManifest;
