//! Versioned 39-component manifest for resumed-segment outer proofs.
//!
//! The first 36 component indices preserve the frozen universal roster. Two
//! authenticated V2 boundary sources are appended at indices 36 and 37, then
//! the committed verifier-input provider is appended at index 38. This keeps
//! all prior claimed-sum indices and column placements stable while making the
//! additional source equations and their independent producer proof-visible.
//! The module owns geometry and proof ordering only; component equations stay
//! in their typed AIR definitions.
const shard_0 = @import("segment_outer_adapter_manifest_v2_contract.zig");
const shard_1 = @import("segment_outer_adapter_manifest_v2_proof_gate.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const TRANSCRIPT_FORMAT_VERSION = shard_0.TRANSCRIPT_FORMAT_VERSION;
pub const TRANSCRIPT_DOMAIN = shard_0.TRANSCRIPT_DOMAIN;
pub const DOMAIN = shard_0.DOMAIN;
pub const CLAIM_DOMAIN = shard_0.CLAIM_DOMAIN;
pub const PROGRAM_GEOMETRY_DOMAIN = shard_0.PROGRAM_GEOMETRY_DOMAIN;
pub const TREE_COUNT = shard_0.TREE_COUNT;
pub const PREPROCESSED_TREE_INDEX = shard_0.PREPROCESSED_TREE_INDEX;
pub const MAIN_TREE_INDEX = shard_0.MAIN_TREE_INDEX;
pub const INTERACTION_TREE_INDEX = shard_0.INTERACTION_TREE_INDEX;
pub const UNIVERSAL_COMPONENT_COUNT = shard_0.UNIVERSAL_COMPONENT_COUNT;
pub const SOURCE_COMPONENT_COUNT = shard_0.SOURCE_COMPONENT_COUNT;
pub const PROVIDER_COMPONENT_COUNT = shard_0.PROVIDER_COMPONENT_COUNT;
pub const COMPONENT_COUNT = shard_0.COMPONENT_COUNT;
pub const STATEMENT_SOURCE_INDEX = shard_0.STATEMENT_SOURCE_INDEX;
pub const PUBLIC_LOGUP_SOURCE_INDEX = shard_0.PUBLIC_LOGUP_SOURCE_INDEX;
pub const VERIFIER_INPUT_PROVIDER_INDEX = shard_0.VERIFIER_INPUT_PROVIDER_INDEX;
pub const Error = shard_0.Error;
/// V2 keeps all prior numeric indices unchanged and append-admits one committed
/// provider. The explicit enum prevents a caller-selected integer from
/// entering component admission.
pub const ComponentKey = shard_0.ComponentKey;
pub const keyIndex = shard_0.keyIndex;
pub const fromUniversal = shard_0.fromUniversal;
pub const Geometry = shard_0.Geometry;
pub const Placement = shard_0.Placement;
pub const AdapterBinding = shard_0.AdapterBinding;
pub const TypedCatalogV2 = shard_0.TypedCatalogV2;
pub const V2_AUTHORITY_CHANGED_MASK = shard_0.V2_AUTHORITY_CHANGED_MASK;
pub const V1_AUTHORITY_UNCHANGED_MASK = shard_0.V1_AUTHORITY_UNCHANGED_MASK;
pub const APPENDED_SOURCE_MASK = shard_0.APPENDED_SOURCE_MASK;
pub const APPENDED_PROVIDER_MASK = shard_0.APPENDED_PROVIDER_MASK;
/// All six authorities are mandatory even for focused component tests. This
/// prevents a test-only builder from accidentally becoming a production path
/// that leaves statement/public source custody unbound.
pub const AuthorityIds = shard_0.AuthorityIds;
pub const Manifest = shard_0.Manifest;
pub const ClaimVector = shard_1.ClaimVector;
pub const ProofGate = shard_1.ProofGate;
pub const build = shard_1.build;
/// Strict geometry assembly for focused tests and higher-level composition.
/// Unlike the removed generic builder, this accepts a validated typed catalog
/// as a whole and therefore cannot smuggle V1 rows 10--17 into a V2 manifest.
pub const assemble = shard_1.assemble;
/// Statement-independent identity of the exact SegmentV2 AIR program.
///
/// `Manifest.seal` remains the full source-authority identity and therefore
/// differs across honest leaves. Recursive composition uses this digest only
/// after each child has independently validated its full manifest. No source
/// manifest, statement, publication, or boundary identity is discarded at
/// the admission boundary.
pub const programGeometryShaId = shard_1.programGeometryShaId;
pub const requireSameProgramGeometry = shard_1.requireSameProgramGeometry;
