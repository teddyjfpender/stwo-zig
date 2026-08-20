//! Fixed FRI verifier graph lowering into rows 30--32.
//!
//! One cold compiler derives the mode-indexed multiplication, inversion, and
//! linear-operation schedules directly from the authenticated row-29 circuit
//! authority. Proof-time materialization replays concrete circuit evaluations
//! into caller-owned invocation buffers without allocating. Constants and
//! designated zero outputs are retained as explicit public wire anchors, so
//! the arithmetic relation closes without an untracked verifier contribution.
const shard_0 = @import("fri_verifier_lowering_core.zig");
const shard_1 = @import("fri_verifier_lowering_plan.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const DOMAIN = shard_0.DOMAIN;
pub const Error = shard_0.Error;
pub const PublicClaimError = shard_0.PublicClaimError;
pub const ProofKind = shard_0.ProofKind;
pub const Reference = shard_0.Reference;
pub const Evaluations = shard_0.Evaluations;
pub const Counts = shard_0.Counts;
pub const PublicWireTerm = shard_0.PublicWireTerm;
pub const ActivePublicTerms = shard_0.ActivePublicTerms;
pub const InvocationBuffers = shard_0.InvocationBuffers;
pub const Plan = shard_1.Plan;
