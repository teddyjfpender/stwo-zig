//! Verified binary-node authority for universal recursion rows 18--34.
//!
//! The first responsibility of this source is custody, not column writing.
//! Each child must arrive through all three native-verifier publications:
//! the authenticated pair record, its canonical fixed proof wire, and the
//! retained FRI/PCS capture.  `Source.init` proves that those publications are
//! the same proof before any recursive witness is admitted.  In particular it
//! re-derives the fixed-wire proof id, compares every FRI/Merkle value retained
//! by `captured_fri.Owned`, and checks every transcript-derived challenge and
//! full query word against the pair authority's recorded execution.
//!
//! Row 18 has one additional trust boundary.  The repository does not yet
//! contain a production recursion-AIR graph producer, so this module does not
//! manufacture one from caller-provided values.  A graph is accepted only
//! through `VerifiedChildCompositionAuthority`, whose complete identity is
//! pinned by a trusted AIR-program-to-circuit profile supplied outside the
//! proof.  The row writers below remain fail-closed until that authority is
//! present for both children.

const shard_0 = @import("binary_fri_outer_source_claims.zig");
const shard_1 = @import("binary_fri_outer_source_trusted_composition_profile_v1.zig");
const shard_2 = @import("binary_fri_outer_source_composition_rows_authority.zig");
const shard_3 = @import("binary_fri_outer_source_fri_rows_authority.zig");
const shard_4 = @import("binary_fri_outer_source_arithmetic_rows_authority.zig");
const shard_5 = @import("binary_fri_outer_source_source_for_boundary.zig");
const shard_6 = @import("binary_fri_outer_source_retain_non_path_poseidon_calls.zig");
const shard_7 = @import("binary_fri_outer_source_materialize_child_paths.zig");
const shard_8 = @import("binary_fri_outer_source_composition_source_value.zig");
const shard_9 = @import("binary_fri_outer_source_validate_captured_against_wire.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const FIRST_ROW = shard_0.FIRST_ROW;
pub const LAST_ROW = shard_0.LAST_ROW;
pub const FIRST_FRI_ROW = shard_0.FIRST_FRI_ROW;
pub const LAST_FRI_INPUT_ROW = shard_0.LAST_FRI_INPUT_ROW;
pub const CHILD_COUNT = shard_0.CHILD_COUNT;
pub const LEFT_CHILD = shard_0.LEFT_CHILD;
pub const RIGHT_CHILD = shard_0.RIGHT_CHILD;
pub const LEFT_RECURSION_VERIFIER_ID = shard_0.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID = shard_0.RIGHT_RECURSION_VERIFIER_ID;
pub const SEGMENT_FRI_CIRCUIT_ID = shard_0.SEGMENT_FRI_CIRCUIT_ID;
pub const LEFT_FRI_CIRCUIT_ID = shard_0.LEFT_FRI_CIRCUIT_ID;
pub const RIGHT_FRI_CIRCUIT_ID = shard_0.RIGHT_FRI_CIRCUIT_ID;
pub const SEGMENT_PCS_CIRCUIT_ID = shard_0.SEGMENT_PCS_CIRCUIT_ID;
pub const LEFT_PCS_CIRCUIT_ID = shard_0.LEFT_PCS_CIRCUIT_ID;
pub const RIGHT_PCS_CIRCUIT_ID = shard_0.RIGHT_PCS_CIRCUIT_ID;
pub const SEGMENT_ARITHMETIC_CAPACITY_CIRCUIT_ID = shard_0.SEGMENT_ARITHMETIC_CAPACITY_CIRCUIT_ID;
pub const VM_COMPOSITION_CAPACITY_CIRCUIT_ID = shard_0.VM_COMPOSITION_CAPACITY_CIRCUIT_ID;
pub const LEFT_COMPOSITION_STATEMENT_SCOPE = shard_0.LEFT_COMPOSITION_STATEMENT_SCOPE;
pub const RIGHT_COMPOSITION_STATEMENT_SCOPE = shard_0.RIGHT_COMPOSITION_STATEMENT_SCOPE;
pub const UNIVERSAL_CLAIMED_SUM_COUNT = shard_0.UNIVERSAL_CLAIMED_SUM_COUNT;
pub const POSEIDON2_ROSTER_ROW = shard_0.POSEIDON2_ROSTER_ROW;
pub const POSEIDON2_PARTIAL_COUNT = shard_0.POSEIDON2_PARTIAL_COUNT;
pub const COMPOSITION_CLAIMED_SUM_COUNT = shard_0.COMPOSITION_CLAIMED_SUM_COUNT;
pub const POSEIDON2_PARTIAL_CLAIM_START = shard_0.POSEIDON2_PARTIAL_CLAIM_START;
pub const POSEIDON2_INTERACTION_COLUMN_COUNT = shard_0.POSEIDON2_INTERACTION_COLUMN_COUNT;
pub const POSEIDON2_PROVIDER_SAMPLE_COUNT = shard_0.POSEIDON2_PROVIDER_SAMPLE_COUNT;
pub const NO_POSEIDON2_SAMPLE_LAYOUT = shard_0.NO_POSEIDON2_SAMPLE_LAYOUT;
pub const ROW_COUNT = shard_0.ROW_COUNT;
pub const TYPED_RELATION_ROW_COUNT = shard_0.TYPED_RELATION_ROW_COUNT;
pub const UNIVERSAL_ROSTER_ROW_COUNT = shard_0.UNIVERSAL_ROSTER_ROW_COUNT;
pub const COMPOSITION_ROW_COUNT = shard_0.COMPOSITION_ROW_COUNT;
pub const ROWS_18_19_WORKSPACE_HEAP_ALLOCATIONS = shard_0.ROWS_18_19_WORKSPACE_HEAP_ALLOCATIONS;
pub const ROWS_18_19_REUSED_HOT_HEAP_ALLOCATIONS = shard_0.ROWS_18_19_REUSED_HOT_HEAP_ALLOCATIONS;
pub const ROWS_20_29_WORKSPACE_HEAP_ALLOCATIONS = shard_0.ROWS_20_29_WORKSPACE_HEAP_ALLOCATIONS;
pub const ROWS_20_29_REUSED_HOT_HEAP_ALLOCATIONS = shard_0.ROWS_20_29_REUSED_HOT_HEAP_ALLOCATIONS;
pub const ROWS_30_32_WORKSPACE_HEAP_ALLOCATIONS = shard_0.ROWS_30_32_WORKSPACE_HEAP_ALLOCATIONS;
pub const ROWS_30_32_REUSED_HOT_HEAP_ALLOCATIONS = shard_0.ROWS_30_32_REUSED_HOT_HEAP_ALLOCATIONS;
pub const ROW_33_WORKSPACE_HEAP_ALLOCATIONS = shard_0.ROW_33_WORKSPACE_HEAP_ALLOCATIONS;
pub const ROW_33_REUSED_HOT_HEAP_ALLOCATIONS = shard_0.ROW_33_REUSED_HOT_HEAP_ALLOCATIONS;
pub const RELATION_ROWS_WORKSPACE_HEAP_ALLOCATIONS = shard_0.RELATION_ROWS_WORKSPACE_HEAP_ALLOCATIONS;
pub const RELATION_ROWS_REUSED_HOT_HEAP_ALLOCATIONS = shard_0.RELATION_ROWS_REUSED_HOT_HEAP_ALLOCATIONS;
pub const RELATION_INTERACTION_WORKSPACE_HEAP_ALLOCATIONS = shard_0.RELATION_INTERACTION_WORKSPACE_HEAP_ALLOCATIONS;
pub const RELATION_INTERACTION_REUSED_HOT_HEAP_ALLOCATIONS = shard_0.RELATION_INTERACTION_REUSED_HOT_HEAP_ALLOCATIONS;
pub const MERKLE_PATH_MAIN_COLUMN_COUNT = shard_0.MERKLE_PATH_MAIN_COLUMN_COUNT;
pub const COMPOSITION_PREPROCESSED_COLUMN_COUNT = shard_0.COMPOSITION_PREPROCESSED_COLUMN_COUNT;
pub const COMPOSITION_MAIN_COLUMN_COUNT = shard_0.COMPOSITION_MAIN_COLUMN_COUNT;
pub const COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW = shard_0.COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW;
pub const COMPOSITION_MAIN_COLUMNS_PER_ROW = shard_0.COMPOSITION_MAIN_COLUMNS_PER_ROW;
pub const FriRow = shard_0.FriRow;
pub const FRI_ROW_COUNT = shard_0.FRI_ROW_COUNT;
pub const ARITHMETIC_ROW_COUNT = shard_0.ARITHMETIC_ROW_COUNT;
pub const ARITHMETIC_PREPROCESSED_COLUMN_COUNT = shard_0.ARITHMETIC_PREPROCESSED_COLUMN_COUNT;
pub const ARITHMETIC_MAIN_COLUMN_COUNT = shard_0.ARITHMETIC_MAIN_COLUMN_COUNT;
pub const ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW = shard_0.ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW;
pub const ARITHMETIC_MAIN_COLUMNS_PER_ROW = shard_0.ARITHMETIC_MAIN_COLUMNS_PER_ROW;
pub const PREPROCESSED_COLUMN_COUNT = shard_0.PREPROCESSED_COLUMN_COUNT;
pub const MAIN_COLUMN_COUNT = shard_0.MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMNS_PER_ROW = shard_0.PREPROCESSED_COLUMNS_PER_ROW;
pub const MAIN_COLUMNS_PER_ROW = shard_0.MAIN_COLUMNS_PER_ROW;
pub const TYPED_INTERACTION_COLUMNS_PER_ROW = shard_0.TYPED_INTERACTION_COLUMNS_PER_ROW;
pub const TYPED_INTERACTION_COLUMN_COUNT = shard_0.TYPED_INTERACTION_COLUMN_COUNT;
/// Rows 18--33 each have one typed framework claim.  Row 34 intentionally
/// exposes the native provider's two recurrence claims separately: consumers
/// may use their sum for the roster vector, but verifier replay must retain
/// both coordinates.
pub const Claims = shard_0.Claims;
pub const Poseidon2DomainAudit = shard_0.Poseidon2DomainAudit;
pub const DomainAudits = shard_0.DomainAudits;
pub const COMPOSITION_PROFILE_FORMAT_VERSION = shard_0.COMPOSITION_PROFILE_FORMAT_VERSION;
pub const COMPOSITION_PROFILE_DOMAIN = shard_0.COMPOSITION_PROFILE_DOMAIN;
pub const COMPOSITION_AUTHORITY_FORMAT_VERSION = shard_0.COMPOSITION_AUTHORITY_FORMAT_VERSION;
pub const COMPOSITION_AUTHORITY_DOMAIN = shard_0.COMPOSITION_AUTHORITY_DOMAIN;
pub const SOURCE_AUTHORITY_DOMAIN = shard_0.SOURCE_AUTHORITY_DOMAIN;
/// V2 removes the process-local source address that V1 accidentally included
/// in a proof-visible identity. Address equality remains an operational
/// capability check in `PreparedAuthority.validateFor`; the canonical digest
/// is now a pure function of the transitive semantic authority below.
pub const PREPARED_AUTHORITY_FORMAT_VERSION = shard_0.PREPARED_AUTHORITY_FORMAT_VERSION;
pub const PREPARED_AUTHORITY_DOMAIN = shard_0.PREPARED_AUTHORITY_DOMAIN;
pub const Error = shard_0.Error;
/// Root-owned mapping from one admitted AIR program to its reviewed recursive
/// composition circuit.  This value is protocol configuration, never proof
/// material.  Supplying only a self-sealed graph is intentionally insufficient.
pub const TrustedCompositionProfileV1 = shard_1.TrustedCompositionProfileV1;
/// Typed capability for one child recursion-composition graph.  The graph and
/// its evaluated values stay verifier-owned; this record binds them to the
/// child proof id and to a separately trusted profile.
pub const VerifiedChildCompositionAuthority = shard_1.VerifiedChildCompositionAuthority;
pub const ChildInput = shard_1.ChildInput;
/// One graph lane owned outside rows 18--34 but sharing rows 30--32. The
/// canonical all-36 cohort uses this for row 11's statement-semantics circuit,
/// ensuring that every live `recursion_wire` edge is lowered by one plan.
/// Both borrowed slices remain owned by the admitted non-FRI authority.
pub const SharedArithmeticInput = shard_1.SharedArithmeticInput;
/// Minimal recorder-authenticated composition view consumed by the shared
/// rows-30--32 lowering plan. Integrations mint this only from an opaque
/// finalized recorder; it carries no claims, proof bytes, or detached witness
/// values and therefore cannot masquerade as the frozen V1 child authority.
pub const AuthenticatedCompositionLane = shard_1.AuthenticatedCompositionLane;
/// Challenge-evaluated publication of one exact, pre-challenge tuple source.
/// The global closure layer may authenticate and carry this value, but never
/// derives it by negating an observed residual.
pub const PublicBoundaryEvidence = shard_1.PublicBoundaryEvidence;
/// Challenge-independent identity of one exact public-boundary tuple source.
/// Preparing this descriptor never evaluates a LogUp denominator; the later
/// evidence pass must reproduce all four fields from the same authenticated
/// source before publishing its challenge-dependent claim.
pub const PublicBoundaryDescriptor = shard_1.PublicBoundaryDescriptor;
pub const PublicBoundaryIndexRange = shard_1.PublicBoundaryIndexRange;
/// Auditable geometry behind the authenticated-recorder boundary.  Retaining
/// these counts explicitly prevents a source digest from hiding an off-by-one
/// pad range or a widened partial-claim suffix.
pub const AuthenticatedRecorderVerifierInputBoundaryDescriptor = shard_1.AuthenticatedRecorderVerifierInputBoundaryDescriptor;
/// One-pass post-challenge publication of the authenticated-recorder source.
/// Keeping the geometry beside the claim lets the parent authority compare
/// the challenge-independent facts without rescanning the recorder schedule.
pub const AuthenticatedRecorderVerifierInputBoundaryEvidence = shard_1.AuthenticatedRecorderVerifierInputBoundaryEvidence;
/// Exact rows 18--19 authority.  Row 18 is compiled from two root-admitted
/// recorder graphs and their source bindings.  Every bound graph input is
/// compared with the successful native verifier's fixed wire, transcript
/// draw, statement words, or capture before its schedule value is retained.
/// The VM lane is a protocol-owned one-input capacity graph and is inactive
/// for a binary proof; it exists solely because the universal row ABI carries
/// all proof kinds in one authenticated schedule.
pub const CompositionRowsAuthority = shard_2.CompositionRowsAuthority;
pub const FriRowsAuthority = shard_3.FriRowsAuthority;
pub const ArithmeticRowsAuthority = shard_4.ArithmeticRowsAuthority;
pub const MerkleRowsAuthority = shard_4.MerkleRowsAuthority;
/// Cold, fail-atomic custody source for the frozen V1 boundary.
pub const Source = shard_5.Source;
/// Version-neutral, monomorphized source seam for an integration-owned
/// authenticated child profile. `Boundary` must expose `PairPrepared`,
/// `RootPin`, `Wire`, and `Child` types plus allocation-free
/// `validateSource`, `fillQueryWords`, and `sourceAuthorityDigest` methods.
/// No function pointers or runtime proof-kind branches enter hot writers.
pub const AuthenticatedSource = shard_6.AuthenticatedSource;
