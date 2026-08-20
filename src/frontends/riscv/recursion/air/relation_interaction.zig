//! Authenticated multi-schema LogUp compiler for recursion typed AIR.
//!
//! A cold pass validates the typed program, seals its semantic identity and
//! exact universal registry order, and compiles the transitive expression DAG
//! of relation tuples and weights into compact slot instructions. The hot row
//! path evaluates that DAG once, uses direct schema-indexed challenge access,
//! batches consecutive events exactly as the source macro does, and writes one
//! contiguous interaction-column slab.
const shard_0 = @import("relation_interaction_tuple_ledger.zig");
const shard_1 = @import("relation_interaction_runtime.zig");
const shard_2 = @import("relation_interaction_fixture.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const MAX_ARENA_NODES = shard_0.MAX_ARENA_NODES;
pub const MAX_COMPILED_NODES = shard_0.MAX_COMPILED_NODES;
pub const MAX_ARITY = shard_0.MAX_ARITY;
pub const Error = shard_0.Error;
pub const AuthenticationError = shard_0.AuthenticationError;
pub const RowError = shard_0.RowError;
pub const InteractionError = shard_0.InteractionError;
pub const ClaimError = shard_0.ClaimError;
pub const DomainAuditError = shard_0.DomainAuditError;
pub const DomainAudit = shard_0.DomainAudit;
pub const TupleContribution = shard_0.TupleContribution;
pub const TUPLE_DIAGNOSTIC_PREFIX_ARITY = shard_0.TUPLE_DIAGNOSTIC_PREFIX_ARITY;
pub const TupleClosureReport = shard_0.TupleClosureReport;
pub const TupleLedger = shard_0.TupleLedger;
pub const allDomainMask = shard_0.allDomainMask;
pub const EvalOp = shard_0.EvalOp;
pub const EvalNode = shard_0.EvalNode;
pub const EventPlan = shard_0.EventPlan;
pub const BatchPlan = shard_0.BatchPlan;
pub const Entry = shard_0.Entry;
pub const Runtime = shard_1.Runtime;
