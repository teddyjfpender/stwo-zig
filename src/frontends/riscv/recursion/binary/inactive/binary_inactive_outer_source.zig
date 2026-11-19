//! Binary-node authority for universal rows 12--17.
//!
//! Rows 12--16 are the VM-public families.  A binary node has no VM-public
//! witness, so their typed witnesses are canonically inactive: every main
//! value and every relation weight is zero.  Row 17 is deliberately different.
//! It is the proof-kind control consumer and, in binary mode, consumes the
//! public-LogUp control step from each recursion-verifier lane.  Treating row
//! 17 as inactive would leave the matching row-0 schedule emissions open.
//!
//! This source borrows the already authenticated, proof-independent typed AIR
//! owners and preprocessing from `segment_public_outer_source.Source`.  It
//! does not borrow a segment witness and does not duplicate any constraint.
//! All three committed-tree writes stage the complete six-row cohort before
//! touching caller storage.

const shard_0 = @import("binary_inactive_outer_source_claims.zig");
const shard_1 = @import("binary_inactive_outer_source_source.zig");
const shard_2 = @import("binary_inactive_outer_source_stage.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const FIRST_ROW = shard_0.FIRST_ROW;
pub const LAST_INACTIVE_ROW = shard_0.LAST_INACTIVE_ROW;
pub const CONTROL_ROW = shard_0.CONTROL_ROW;
pub const ROW_COUNT = shard_0.ROW_COUNT;
pub const INACTIVE_ROW_COUNT = shard_0.INACTIVE_ROW_COUNT;
/// One retained logical-row allocation per family.  Hash witnesses allocate
/// zero Poseidon calls in binary mode; the allocator is never entered for the
/// empty call slices.
pub const COLD_PREPARED_RETAINED_ALLOCATIONS = shard_0.COLD_PREPARED_RETAINED_ALLOCATIONS;
pub const COLD_PREPARE_HEAP_ALLOCATIONS = shard_0.COLD_PREPARE_HEAP_ALLOCATIONS;
pub const HOT_TREE_HEAP_ALLOCATIONS = shard_0.HOT_TREE_HEAP_ALLOCATIONS;
pub const HOT_ALL_TREES_HEAP_ALLOCATIONS = shard_0.HOT_ALL_TREES_HEAP_ALLOCATIONS;
pub const HOT_PAIR_AUTHENTICATIONS_PER_TREE = shard_0.HOT_PAIR_AUTHENTICATIONS_PER_TREE;
pub const POSEIDON_CALLS_PER_BINARY_NODE = shard_0.POSEIDON_CALLS_PER_BINARY_NODE;
pub const Error = shard_0.Error;
pub const LogSizes = shard_0.LogSizes;
pub const DomainAudits = shard_0.DomainAudits;
pub const Parameters = shard_0.Parameters;
pub const Claims = shard_0.Claims;
pub const Components = shard_0.Components;
pub const Prepared = shard_1.Prepared;
pub const Source = shard_1.Source;
