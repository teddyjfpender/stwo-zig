//! Hash-consed recorder for recursion AIR composition graphs.
//!
//! This module is deliberately oblivious to the 36-component roster.  It
//! replays the two authenticated compiler products used by every typed AIR
//! component -- `direct_constraint_program.Program` and
//! `relation_interaction.Runtime.Plan` -- over a symbolic QM31 scalar.  The
//! resulting DAG is the same `composition_circuit.CircuitGraph` consumed by
//! row 18, so native evaluation and recursive evaluation share constraint
//! authority instead of maintaining two implementations.
const shard_0 = @import("composition_graph_recorder_builder.zig");
const shard_1 = @import("composition_graph_recorder_record_component.zig");
const shard_2 = @import("composition_graph_recorder_support.zig");

pub const Error = shard_0.Error;
pub const Input = shard_0.Input;
/// Cold graph builder.  Callers create every verifier-owned input first,
/// activate the builder, replay authenticated programs, constrain the final
/// equality, deactivate, and finish.  Constants and commutative operations are
/// canonicalized and hash-consed; recording never allocates in a row loop.
pub const Builder = shard_0.Builder;
/// Field interface accepted by typed generic AIR evaluators.
pub const Scalar = shard_0.Scalar;
pub const Circuit = shard_0.Circuit;
/// Replay the exact authenticated direct-expression program over graph values.
/// Structural preflight precedes every array access so a corrupted cached
/// program fails closed instead of becoming a graph-construction primitive.
pub const replayDirect = shard_0.replayDirect;
pub const Pair = shard_0.Pair;
/// Symbolic counterpart of the 47-domain universal challenge bundle.
pub const ChallengeSet = shard_0.ChallengeSet;
/// Replay one exact authenticated LogUp plan.  The `Runtime` comptime argument
/// is the same specialization that produced `plan`; no schema switch or
/// component-specific lookup transcription exists here.
pub const replayRelation = shard_1.replayRelation;
/// Exact framework LogUp constraint used by the universal typed adapter.
pub const frameworkConstraint = shard_1.frameworkConstraint;
/// Records one complete universal typed component in the exact native adapter
/// order: direct compiler roots first, followed by LogUp recurrence roots.
/// The caller supplies already-bound mask values and the cached inverse of the
/// component's coset vanishing polynomial. `claimed_sum_shift` is deliberately
/// explicit: recursive callers must derive it from the claimed-sum graph input,
/// never embed the concrete child proof's claim as a circuit constant. This
/// function performs no component dispatch and allocates no memory.
pub const recordComponent = shard_1.recordComponent;
/// Horner convention shared by native STWO composition accumulation.
pub const accumulate = shard_1.accumulate;
pub const fromPartialEvals = shard_1.fromPartialEvals;
pub const pointFromSeed = shard_1.pointFromSeed;
pub const DenominatorCache = shard_1.DenominatorCache;
/// Cached inverse of the component-domain vanishing polynomial at the OODS
/// point.  Equal log sizes across the 36-row roster share one graph node.
pub const quotientDenominator = shard_1.quotientDenominator;
/// Recombines the split composition-tree columns exactly as the native
/// verifier does.  `chunks` are secure values reconstructed from their four
/// sampled base columns in chunk order.
pub const reconstructSplitComposition = shard_1.reconstructSplitComposition;
