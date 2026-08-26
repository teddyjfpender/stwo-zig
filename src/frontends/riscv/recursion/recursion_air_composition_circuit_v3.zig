//! Proof-kind-aware V3 authority for the shared recursion composition circuit.
//!
//! V2 is the frozen 36-physical-claim plus two-Poseidon-partial protocol.  A
//! SegmentV2 leaf proves 39 physical component claims, so silently projecting
//! it into V2 would discard three authenticated LogUp totals.  V3 instead
//! fixes one 41-element claim-input ABI for every branch:
//!
//!   * segment leaf: claims 0..38, Poseidon partials 39 and 40;
//!   * binary node: claims 0..35, zero padding 36..38, partials 39 and 40;
//!   * empty leaf: canonical zero in every slot.
//!
//! The inactive tail is an explicit protocol rule, not host-side convenience.
//! This module owns that rule, the heterogeneous per-kind program roster, and
//! the authenticated graph/input view.  It deliberately does not mutate or
//! reinterpret `recursion_air_composition_circuit.zig` (V2).

const shard_0 = @import("recursion_air_composition_circuit_v3_canonical_empty_program_v3.zig");
const shard_1 = @import("recursion_air_composition_circuit_v3_program_roster_v3.zig");
const shard_2 = @import("recursion_air_composition_circuit_v3_circuit_view_v3.zig");
const shard_3 = @import("recursion_air_composition_circuit_v3_heterogeneous_session_v3.zig");
const shard_4 = @import("recursion_air_composition_circuit_v3_write_inputs_from_validated_profile_and_policy.zig");
const authority_validation = @import("recursion_air_composition_circuit_v3_authority_validation.zig");

pub const capture_layout_v3 = shard_0.capture_layout_v3;
pub const segment_recorder_v3 = shard_0.segment_recorder_v3;
pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SCHEMA_VERSION = shard_0.SCHEMA_VERSION;
pub const CIRCUIT_DOMAIN = shard_0.CIRCUIT_DOMAIN;
pub const ORDERED_PROGRAM_DOMAIN = shard_0.ORDERED_PROGRAM_DOMAIN;
pub const PROGRAM_DESCRIPTOR_DOMAIN = shard_0.PROGRAM_DESCRIPTOR_DOMAIN;
pub const PROGRAM_ROSTER_DOMAIN = shard_0.PROGRAM_ROSTER_DOMAIN;
pub const CONFIGURATION_DOMAIN = shard_0.CONFIGURATION_DOMAIN;
pub const CLAIM_INPUT_CONTENT_DOMAIN = shard_0.CLAIM_INPUT_CONTENT_DOMAIN;
pub const CANONICAL_EMPTY_PROGRAM_DOMAIN = shard_0.CANONICAL_EMPTY_PROGRAM_DOMAIN;
pub const CANONICAL_EMPTY_AIR_ID_DOMAIN = shard_0.CANONICAL_EMPTY_AIR_ID_DOMAIN;
pub const ProofKind = shard_0.ProofKind;
pub const AirProgramId = shard_0.AirProgramId;
pub const UNIVERSAL_PHYSICAL_CLAIM_COUNT = shard_0.UNIVERSAL_PHYSICAL_CLAIM_COUNT;
pub const SEGMENT_PHYSICAL_CLAIM_COUNT = shard_0.SEGMENT_PHYSICAL_CLAIM_COUNT;
pub const EMPTY_PHYSICAL_CLAIM_COUNT = shard_0.EMPTY_PHYSICAL_CLAIM_COUNT;
pub const MAX_PHYSICAL_CLAIM_COUNT = shard_0.MAX_PHYSICAL_CLAIM_COUNT;
pub const POSEIDON_PARTIAL_COUNT = shard_0.POSEIDON_PARTIAL_COUNT;
pub const POSEIDON_ROSTER_ROW = shard_0.POSEIDON_ROSTER_ROW;
pub const POSEIDON_AUX_START = shard_0.POSEIDON_AUX_START;
pub const COMPOSITION_CLAIM_INPUT_COUNT = shard_0.COMPOSITION_CLAIM_INPUT_COUNT;
pub const RELATION_CHALLENGE_COUNT = shard_0.RELATION_CHALLENGE_COUNT;
pub const STATEMENT_WORD_COUNT = shard_0.STATEMENT_WORD_COUNT;
pub const PROGRAM_KIND_COUNT = shard_0.PROGRAM_KIND_COUNT;
pub const CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT = shard_0.CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT;
/// V3.1 reuses the first Segment-only tail slot for the deterministic public
/// statement contribution of a proofless empty leaf.  Rows 0--35 retain zero
/// claims, and the two Poseidon auxiliary slots remain zero.
pub const CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX = shard_0.CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX;
pub const CANONICAL_EMPTY_PROGRAM_SCHEMA_VERSION = shard_0.CANONICAL_EMPTY_PROGRAM_SCHEMA_VERSION;
pub const CANONICAL_EMPTY_CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT = shard_0.CANONICAL_EMPTY_CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT;
pub const HEAP_ALLOCATIONS_PER_CLAIM_WRITE = shard_0.HEAP_ALLOCATIONS_PER_CLAIM_WRITE;
pub const HEAP_ALLOCATIONS_PER_INPUT_WRITE = shard_0.HEAP_ALLOCATIONS_PER_INPUT_WRITE;
pub const HEAP_ALLOCATIONS_PER_AUTHORITY_MINT = shard_0.HEAP_ALLOCATIONS_PER_AUTHORITY_MINT;
pub const LEGACY_V2_PROFILE_ACCEPTED = shard_0.LEGACY_V2_PROFILE_ACCEPTED;
pub const LOSSY_SEGMENT_PROJECTION_AVAILABLE = shard_0.LOSSY_SEGMENT_PROJECTION_AVAILABLE;
pub const PROOF_KIND_AWARE_INPUT_AUTHORITY_AVAILABLE = shard_0.PROOF_KIND_AWARE_INPUT_AUTHORITY_AVAILABLE;
pub const HETEROGENEOUS_PROGRAM_ROSTER_AVAILABLE = shard_0.HETEROGENEOUS_PROGRAM_ROSTER_AVAILABLE;
pub const CLAIM_POLICY_GRAPH_CONSTRAINTS_AVAILABLE = shard_0.CLAIM_POLICY_GRAPH_CONSTRAINTS_AVAILABLE;
/// The cold transaction and exact three-program orchestration exist, but the
/// production capability stays false until a real independently initialized
/// empty cohort joins the already-real Segment and binary lanes in one graph.
pub const HETEROGENEOUS_GRAPH_SESSION_SUBSTRATE_AVAILABLE = shard_0.HETEROGENEOUS_GRAPH_SESSION_SUBSTRATE_AVAILABLE;
/// A finalized heterogeneous recorder now mints and retains a graph authority.
/// Production admission remains false until the independently initialized
/// parent verifier consumes that authority end to end.
pub const RECORDER_MINT_SUBSTRATE_AVAILABLE = shard_0.RECORDER_MINT_SUBSTRATE_AVAILABLE;
pub const HETEROGENEOUS_GRAPH_RECORDER_AVAILABLE = shard_0.HETEROGENEOUS_GRAPH_RECORDER_AVAILABLE;
/// This is the production-admission flag, not the recorder's internal mint
/// substrate.  There is no public constructor: only a successfully finalized
/// `HeterogeneousSessionV3` can produce the retained authority.
pub const CIRCUIT_AUTHORITY_MINT_AVAILABLE = shard_0.CIRCUIT_AUTHORITY_MINT_AVAILABLE;
pub const Error = shard_0.Error;
pub const ManifestFamilyV3 = shard_0.ManifestFamilyV3;
pub const ClaimPolicyV3 = shard_0.ClaimPolicyV3;
pub const TrustedManifestsV3 = shard_0.TrustedManifestsV3;
pub const AirProgramIdsV3 = shard_0.AirProgramIdsV3;
/// Statement-specific authority for the proofless empty base case.
///
/// A binary proof has a verifier capture from which OODS samples and claims
/// are authenticated.  An empty leaf has no proof, so reusing Binary's layout
/// with caller-supplied zeros would leave the public statement unauthenticated.
/// This authority instead binds the exact verified empty publication, the
/// dedicated zero-shell layout, and the universal manifest into Empty's AIR
/// program id.  Segment and Binary descriptors remain byte-for-byte unchanged.
pub const CanonicalEmptyProgramV3 = shard_0.CanonicalEmptyProgramV3;
pub const proofKindIndex = shard_0.proofKindIndex;
/// The selected kind describes the verified child.  Its selectors are active
/// only while the enclosing parent is a binary recursion node; a non-binary
/// parent therefore exposes the canonical all-zero selector vector.
pub const activeProofKindSelectors = shard_0.activeProofKindSelectors;
/// Pointer-free description of the exact ordered component program selected
/// by one proof kind.  `source_claim_count` is distinct from
/// `program_roster_count`: the empty program still has constrained rows, but
/// its entire externally supplied claim vector is canonical zero.
pub const ProgramDescriptorV3 = shard_1.ProgramDescriptorV3;
pub const ProgramRosterV3 = shard_1.ProgramRosterV3;
/// Hash-free hot-path projection of a previously authenticated V3
/// configuration.  Geometry validation is constant time and never replays a
/// manifest or roster hash.
pub const InputProfileV3 = shard_1.InputProfileV3;
/// Complete pointer-free V3 input and program authority.  The fixed graph
/// input count is derived from the same `InputProfile` compiler used by V2;
/// only the claimed-sum dimension changes from 38 to 41.
pub const ConfigurationV3 = shard_1.ConfigurationV3;
/// Opaque capability minted by the heterogeneous recorder.  Callers cannot
/// construct its representation or a detached self-hashed graph authority.
pub const CircuitAuthorityV3 = shard_1.CircuitAuthorityV3;
/// Opaque borrow of one finalized recorder product.  Its representation is
/// the recorder-owned storage itself, so no detached graph/configuration tuple
/// can be assembled by a caller.
pub const CircuitViewV3 = shard_2.CircuitViewV3;
pub const WitnessV3 = shard_2.WitnessV3;
pub const HeterogeneousProgramStatisticsV3 = shard_2.HeterogeneousProgramStatisticsV3;
/// Opaque owned result of the complete three-program recording transaction.
/// The retained authority is minted inside `HeterogeneousSessionV3.finish`,
/// after the private builder is finalized and the complete recording is
/// validated.  Production row-18 admission remains separately fail closed
/// until an independently initialized parent verifier consumes `validatedView`.
pub const RecordedHeterogeneousCircuitV3 = shard_3.RecordedHeterogeneousCircuitV3;
/// Cold, fail-closed construction transaction for the exact SegmentV2,
/// binary, and empty composition programs.  Capture geometry is derived once;
/// all hot row replays use borrowed symbolic inputs and separate denominator
/// caches for the Segment and universal quotient geometries.
pub const HeterogeneousSessionV3 = shard_3.HeterogeneousSessionV3;
pub const reconstructSplitCompositionForLayout = shard_4.reconstructSplitCompositionForLayout;
/// Strict, allocation-free claim assembler.  Every rejection occurs before
/// the first destination write, including overlap and canonicity failures.
pub const writeClaimInputs = shard_4.writeClaimInputs;
pub const validateClaimInputs = shard_4.validateClaimInputs;
/// Versioned empty-provider policy.  The legacy empty encoding remains all
/// zero; only a descriptor authenticated with `canonical_empty_provider` may
/// place the deterministic public-statement contribution in slot 36.
pub const validateClaimInputsForPolicy = shard_4.validateClaimInputsForPolicy;
/// Records the V3 claim policy into the recursive arithmetic graph.  The
/// caller supplies selectors already bound to the parent activation rule; this
/// function adds no host-only assumption:
///
///   * binary selector gates three zero-tail equations;
///   * empty selector gates all 41 zero equations; and
///   * segment-or-binary gates the ordered Poseidon partial closure.
///
/// The fixed output count makes graph-size regressions visible.  Recording is
/// allocation-free after the caller reserves the cold builder capacity.
pub const recordClaimPolicyConstraints = shard_4.recordClaimPolicyConstraints;
pub const recordClaimPolicyConstraintsForPolicy = shard_4.recordClaimPolicyConstraintsForPolicy;
/// Graph-side custody for the proofless-empty provider.  The empty selector
/// gates three independent obligations: the exact 412-word publication, the
/// complete zero sample workspace, and the deterministic public-statement
/// LogUp contribution stored in V3 claim slot 36.  No host-only comparison is
/// relied upon after the graph is recorded.
pub const recordCanonicalEmptyProviderConstraints = shard_4.recordCanonicalEmptyProviderConstraints;
/// Shape-only hot path.  The caller must have authenticated a
/// `ConfigurationV3` and pass its exact `inputProfile()` projection; this
/// function deliberately performs no manifest or AIR-program authentication.
pub const writeInputsFromValidatedProfile = shard_4.writeInputsFromValidatedProfile;
pub const writeInputs = shard_4.writeInputs;
/// Non-authoritative content digest for diagnostics and mutation detection.
/// It deliberately does not identify a circuit configuration or AIR program;
/// protocol publications must bind this content under their trusted
/// `ConfigurationV3.identity` instead of using this digest alone.
pub const claimInputContentDigest = authority_validation.claimInputContentDigest;
