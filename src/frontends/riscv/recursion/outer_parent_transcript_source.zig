//! Typed two-child transcript authority for the recursive-parent boundary.
//!
//! Each child must arrive as one custody bundle: the native verifier capture,
//! its verifier-published receipt and seal, the admitted outer wire, and the
//! matching candidate.  The source never reconstructs the custom outer
//! prefix from proof bytes.  It starts at the receipt's authenticated
//! `pre_core_channel`, replays the exact OUTER_CONFIG PCS/FRI continuation,
//! and checks every derived draw against the successful native capture.
//!
//! The 36 universal-roster claims and log sizes are retained in canonical
//! roster order for each child.  They authenticate the prefix that produced
//! the checkpoint; they are not mixed a second time by this continuation.
//!
//! This module deliberately stops before parent-proof production.  It does
//! not turn either child into `pair_node.VerifiedChildV1`, and its status can
//! never be interpreted as evidence for a complete recursive parent until a
//! separate AIR proof and independent verifier exist.
const shard_0 = @import("outer_parent_transcript_source_child_witness_v1.zig");
const shard_1 = @import("outer_parent_transcript_source_prepared.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SOURCE_ID_DOMAIN = shard_0.SOURCE_ID_DOMAIN;
pub const CHILD_COUNT = shard_0.CHILD_COUNT;
pub const CLAIM_ROW_COUNT = shard_0.CLAIM_ROW_COUNT;
pub const QUERY_COUNT = shard_0.QUERY_COUNT;
pub const MAX_FRI_ROUNDS = shard_0.MAX_FRI_ROUNDS;
/// This source closes transcript custody only.  The value is intentionally a
/// distinct enum rather than a boolean that a caller could reinterpret.
pub const ProductionStatus = shard_0.ProductionStatus;
pub const CURRENT_STATUS = shard_0.CURRENT_STATUS;
pub const COMPLETE_PARENT_PROOF_VERIFIED = shard_0.COMPLETE_PARENT_PROOF_VERIFIED;
pub const HEAP_ALLOCATIONS_PER_PREPARE = shard_0.HEAP_ALLOCATIONS_PER_PREPARE;
pub const Error = shard_0.Error;
/// The exact universal claim schedule authenticated by one outer verifier.
/// Array index is the `universal_roster.Component` discriminant.
pub const UniversalClaimsV1 = shard_0.UniversalClaimsV1;
/// Every verifier-derived core continuation value required by later typed AIR
/// witnesses.  FRI alpha padding is canonical zero beyond `fri_round_count`.
pub const CoreReplayV1 = shard_0.CoreReplayV1;
/// Checked cost ledger for the allocation-free hot path.  Pair-node format
/// validation is a cold trust-boundary cost and is intentionally reported
/// separately from the exact core transcript continuation.
pub const PerformanceCountsV1 = shard_0.PerformanceCountsV1;
pub const BoundContextV1 = shard_0.BoundContextV1;
pub const ChildWitnessV1 = shard_0.ChildWitnessV1;
pub const ChildBundle = shard_0.ChildBundle;
pub const PairInputsV1 = shard_0.PairInputsV1;
pub const Prepared = shard_1.Prepared;
