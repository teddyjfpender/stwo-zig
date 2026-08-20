//! Shared lowering for every recursively verified arithmetic graph.
//!
//! Rows 24 and 29 own disjoint input relations but deliberately share rows
//! 30--32. This compiler concatenates all selected graphs within each proof
//! mode and overlays the segment and binary schedules row-for-row. Constants
//! and designated zero outputs stay explicit public wire anchors, so adding a
//! graph cannot create an untracked boundary term.
const shard_0 = @import("verifier_arithmetic_lowering_reference.zig");
const shard_1 = @import("verifier_arithmetic_lowering_plan.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const DOMAIN = shard_0.DOMAIN;
pub const REFERENCE_FORMAT_VERSION = shard_0.REFERENCE_FORMAT_VERSION;
pub const REFERENCE_DOMAIN = shard_0.REFERENCE_DOMAIN;
pub const ProofKind = shard_0.ProofKind;
pub const Mode = shard_0.Mode;
pub const Error = shard_0.Error;
pub const PublicClaimError = shard_0.PublicClaimError;
/// The graph-derived input boundary is a cold trust-boundary audit.  It
/// authenticates the lowering plan and evaluations before allocating its one
/// reusable use-count scratch buffer.
pub const InputClaimError = shard_0.InputClaimError;
pub const Counts = shard_0.Counts;
/// Borrowed graph authority. `circuit_identity` is the producer's complete
/// profile/graph/input seal; `graph.identity_digest` independently seals the
/// operation DAG lowered here.
pub const Lane = shard_0.Lane;
pub const Reference = shard_0.Reference;
pub const Evaluation = shard_0.Evaluation;
pub const Evaluations = shard_0.Evaluations;
pub const PublicWireTerm = shard_0.PublicWireTerm;
pub const InvocationBuffers = shard_0.InvocationBuffers;
pub const Plan = shard_1.Plan;
pub const computeUseCountsInto = shard_0.computeUseCountsInto;
