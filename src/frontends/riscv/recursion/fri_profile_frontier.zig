//! Allocation-free FRI profile frontier for recursive-verifier engineering.
//!
//! This is a cost model, not protocol authority and not a security proof. It
//! preserves the exact configured query-plus-PoW ledger used by `PcsConfig`,
//! then exposes the trade between larger prover domains and fewer recursive
//! verifier queries. Protocol V1 remains frozen until real proof measurements
//! and a reviewed versioned decision select a candidate.
const shard_0 = @import("fri_profile_frontier_fri_path_dimensions_v1.zig");
const shard_1 = @import("fri_profile_frontier_comparison_v1.zig");

pub const MAX_CANDIDATES = shard_0.MAX_CANDIDATES;
pub const MAX_OBSERVATIONS = shard_0.MAX_OBSERVATIONS;
pub const MAX_COMPARISONS = shard_0.MAX_COMPARISONS;
pub const MAX_OBSERVED_TREES = shard_0.MAX_OBSERVED_TREES;
pub const MAX_OBSERVED_FRI_LAYERS = shard_0.MAX_OBSERVED_FRI_LAYERS;
pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const MEASUREMENT_FORMAT_VERSION = shard_0.MEASUREMENT_FORMAT_VERSION;
pub const COMPARISON_FORMAT_VERSION = shard_0.COMPARISON_FORMAT_VERSION;
pub const DIGEST_DOMAIN = shard_0.DIGEST_DOMAIN;
pub const OBSERVATION_DIGEST_DOMAIN = shard_0.OBSERVATION_DIGEST_DOMAIN;
pub const OBSERVATION_SET_DIGEST_DOMAIN = shard_0.OBSERVATION_SET_DIGEST_DOMAIN;
pub const COMPARISON_DIGEST_DOMAIN = shard_0.COMPARISON_DIGEST_DOMAIN;
pub const COMPARISON_SET_DIGEST_DOMAIN = shard_0.COMPARISON_SET_DIGEST_DOMAIN;
pub const PROTOCOL_ACTIVATION = shard_0.PROTOCOL_ACTIVATION;
pub const FROZEN_V1_MUTATED = shard_0.FROZEN_V1_MUTATED;
pub const HEAP_ALLOCATIONS_PER_OBSERVATION = shard_0.HEAP_ALLOCATIONS_PER_OBSERVATION;
pub const HEAP_ALLOCATIONS_PER_INGEST = shard_0.HEAP_ALLOCATIONS_PER_INGEST;
pub const HEAP_ALLOCATIONS_PER_COMPARISON = shard_0.HEAP_ALLOCATIONS_PER_COMPARISON;
pub const Error = shard_0.Error;
pub const Candidate = shard_0.Candidate;
pub const Frontier = shard_0.Frontier;
/// Builds the nondominated subset in increasing blowup order. Construction is
/// fixed-capacity and allocation-free; the tiny O(k²) filter is cold-path
/// design analysis over at most sixteen candidates, never proof work.
pub const build = shard_0.build;
pub const v1Comparison = shard_0.v1Comparison;
/// Receipt origin is part of every comparison key. Leaf graph-node work and
/// binary outer AIR-constraint work are intentionally never summed or ranked
/// against one another.
pub const ObservationSourceV1 = shard_0.ObservationSourceV1;
/// Explicit unit for the exact verifier-work counter supplied by the receipt
/// adapter. Keeping the unit in the identity prevents a graph-node count from
/// being silently compared with an AIR-constraint count.
pub const VerifierWorkUnitV1 = shard_0.VerifierWorkUnitV1;
pub const MeasuredProfileV1 = shard_0.MeasuredProfileV1;
/// Fixed-capacity exact dimensions for all commitment-tree query paths in one
/// accepted proof capture. `path_count` and `authentication_digest_count` are
/// redundant on purpose and are checked against the per-tree depths.
pub const TreePathDimensionsV1 = shard_0.TreePathDimensionsV1;
pub const FriLayerDimensionsV1 = shard_0.FriLayerDimensionsV1;
/// Exact active FRI layer dimensions from the accepted capture. The terminal
/// value count is measured rather than inferred, while the authentication and
/// fold totals are re-derived from the layer table and query count.
pub const FriPathDimensionsV1 = shard_0.FriPathDimensionsV1;
pub const VerifierWorkV1 = shard_0.VerifierWorkV1;
/// Dependency-safe adapter schema populated at the leaf or binary proof root.
/// It contains values only: no proof, capture, allocator, timer, or receipt
/// pointer crosses into this frontend cost model.
pub const ObservationInputV1 = shard_0.ObservationInputV1;
pub const ObservationV1 = shard_1.ObservationV1;
pub const ObservationSetV1 = shard_1.ObservationSetV1;
pub const DeltaDirectionV1 = shard_1.DeltaDirectionV1;
/// Exact integer comparison. It deliberately does not compute percentages or
/// a scalar score; consumers can display the pair without rounding or implied
/// weighting.
pub const ExactDeltaV1 = shard_1.ExactDeltaV1;
pub const ParetoRelationV1 = shard_1.ParetoRelationV1;
pub const ComparisonV1 = shard_1.ComparisonV1;
pub const ComparisonSetV1 = shard_1.ComparisonSetV1;
pub const OBSERVATION_STATIC_BYTES = shard_1.OBSERVATION_STATIC_BYTES;
pub const OBSERVATION_SET_STATIC_BYTES = shard_1.OBSERVATION_SET_STATIC_BYTES;
pub const COMPARISON_STATIC_BYTES = shard_1.COMPARISON_STATIC_BYTES;
pub const COMPARISON_SET_STATIC_BYTES = shard_1.COMPARISON_SET_STATIC_BYTES;
