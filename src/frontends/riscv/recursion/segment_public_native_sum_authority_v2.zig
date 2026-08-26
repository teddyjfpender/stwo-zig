//! Authenticated SegmentV2 native-public-sum composition authority.
//!
//! This is the missing arithmetic lane behind public-spine rows 15 and
//! 30--32.  Its dense inputs use the exact order already emitted by
//! `segment_public_outer_source_v2.PreparedV2`:
//!
//! 1. every canonical SegmentV2 wire word;
//! 2. four published QM31 relation sums and their published total (20 M31
//!    words); and
//! 3. `(z, alpha)` for registers, memory, program and Merkle relations (32
//!    M31 words).
//!
//! The graph independently recomputes `statement_v2.nativeRelationSums`,
//! including the retained continuation-tree leaf and empty-root compensation,
//! and exposes five zero outputs: one per domain and one for the total.
//! Published sums are therefore witnesses to an equality, never arithmetic
//! authority.
//!
//! Parsing and relation algebra have deliberately separate authorities.  Row
//! 11 proves canonical tags, u16 limbs, byte decompositions, retained-section
//! order/ranges and the exact raw-wire bridge.  The arithmetic graph consumes
//! that bridge tuple-by-tuple.  Existing `arithmetic_circuit` operations have
//! no lookup/bit-decomposition primitive, so the graph specializes optional
//! event topology and byte constants only after re-authenticating the
//! verifier-owned canonical wire.  The complete graph digest, exact node use
//! counts, wire identity and `PreparedV2` source identities are sealed
//! together.  No digest-trusted witness controls this specialization.
//!
//! Construction is cold and owning.  Hot evaluation uses caller-owned scratch
//! and destination buffers, allocates nothing, and commits the destination
//! only after validation, complete replay and all five zero checks succeed.
const shard_0 = @import("segment_public_native_sum_authority_v2_contract.zig");
const shard_1 = @import("segment_public_native_sum_authority_v2_add_boundary_terms.zig");
const shard_2 = @import("segment_public_native_sum_authority_v2_source_v2.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SCHEMA_VERSION = shard_0.SCHEMA_VERSION;
pub const CIRCUIT_ID = shard_0.CIRCUIT_ID;
pub const DOMAIN_COUNT = shard_0.DOMAIN_COUNT;
pub const PUBLISHED_WORD_COUNT = shard_0.PUBLISHED_WORD_COUNT;
pub const CHALLENGE_WORD_COUNT = shard_0.CHALLENGE_WORD_COUNT;
pub const OUTPUT_COUNT = shard_0.OUTPUT_COUNT;
pub const INPUT_SUFFIX_WORD_COUNT = shard_0.INPUT_SUFFIX_WORD_COUNT;
pub const AUTHORITY_DOMAIN = shard_0.AUTHORITY_DOMAIN;
pub const EVALUATION_DOMAIN = shard_0.EVALUATION_DOMAIN;
pub const HOT_HEAP_ALLOCATIONS = shard_0.HOT_HEAP_ALLOCATIONS;
pub const DESTINATION_FAILS_ATOMICALLY = shard_0.DESTINATION_FAILS_ATOMICALLY;
pub const POINTER_STABLE_OWNERSHIP = shard_0.POINTER_STABLE_OWNERSHIP;
pub const EXACT_GRAPH_AND_USE_COUNTS_SEALED = shard_0.EXACT_GRAPH_AND_USE_COUNTS_SEALED;
pub const ROW11_OWNS_CANONICAL_PARSING = shard_0.ROW11_OWNS_CANONICAL_PARSING;
pub const GRAPH_OWNS_RELATION_ARITHMETIC = shard_0.GRAPH_OWNS_RELATION_ARITHMETIC;
pub const PUBLISHED_SUMS_ARE_NOT_AUTHORITY = shard_0.PUBLISHED_SUMS_ARE_NOT_AUTHORITY;
pub const Error = shard_0.Error;
pub const RelationDomainV2 = shard_0.RelationDomainV2;
pub const PublishedCoordinateV2 = shard_0.PublishedCoordinateV2;
pub const PublishedTotalCoordinateV2 = shard_0.PublishedTotalCoordinateV2;
pub const ChallengeCoordinateV2 = shard_0.ChallengeCoordinateV2;
pub const InputSourceV2 = shard_0.InputSourceV2;
pub const InputBindingV2 = shard_0.InputBindingV2;
pub const TermCountsV2 = shard_0.TermCountsV2;
/// Cold, pointer-stable owner of the exact graph and its lowering authority.
/// No pointer into the caller's `PreparedV2` or canonical wire is retained.
pub const SourceV2 = shard_2.SourceV2;
pub const EvaluationBuffersV2 = shard_0.EvaluationBuffersV2;
/// Compact owning handoff from the public native-sum graph to the shared
/// verifier-arithmetic lowering rows. Construction is cold and independently
/// evaluates the complete authenticated graph. Only the committed node values
/// survive construction; the three temporary replay buffers are released
/// immediately, so retaining this lane does not multiply the graph's resident
/// storage.
///
/// The returned `lowering.Evaluation` always borrows `values`. The allocation,
/// rather than this movable wrapper's address, is therefore pointer-stable.
pub const OwnedEvaluationV2 = shard_2.OwnedEvaluationV2;
