//! Production outer-proof source for universal binary-node rows 0--9.
//!
//! This module is the only bridge from verifier-owned transcript schedules and
//! `binary_pair_authority.Prepared` into committed recursion columns. It owns
//! row 0 from the same VM schedule and exact pair of recursion schedules,
//! authenticates every typed AIR and relation program once, and transactionally
//! fills universal-manifest tree placements. No proof-derived scalar is
//! accepted outside the already root-authenticated pair aggregate, and no hot
//! tree fill repeats pair-node authentication.

const shard_0 = @import("binary_transcript_outer_source_executors.zig");
const shard_1 = @import("binary_transcript_outer_source_source.zig");
const shard_2 = @import("binary_transcript_outer_source_stage.zig");
const shard_3 = @import("binary_transcript_outer_source_source_column_count.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const FIRST_ROW = shard_0.FIRST_ROW;
pub const ROW_COUNT = shard_0.ROW_COUNT;
pub const LAST_ROW = shard_0.LAST_ROW;
pub const MIN_LOG_SIZE = shard_0.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = shard_0.MAX_LOG_SIZE;
/// One-time construction cost for the ten authenticated typed AIR owners,
/// their canonical executors, and row-0 preprocessing.
pub const COLD_SOURCE_HEAP_ALLOCATIONS = shard_0.COLD_SOURCE_HEAP_ALLOCATIONS;
/// Fresh, zero-owned destinations and a retained interaction workspace are
/// allocation-free across all three trees.
pub const HOT_REUSED_TREE_HEAP_ALLOCATIONS = shard_0.HOT_REUSED_TREE_HEAP_ALLOCATIONS;
pub const HOT_REUSED_ALL_TREES_HEAP_ALLOCATIONS = shard_0.HOT_REUSED_ALL_TREES_HEAP_ALLOCATIONS;
/// Compatibility `fillInteractionInto` constructs one ten-row logical slab
/// and ten framework workspaces, then delegates to the reusable hot API.
pub const COMPAT_INTERACTION_HEAP_ALLOCATIONS = shard_0.COMPAT_INTERACTION_HEAP_ALLOCATIONS;
pub const INTERACTION_WORKSPACE_HEAP_ALLOCATIONS = shard_0.INTERACTION_WORKSPACE_HEAP_ALLOCATIONS;
pub const HOT_TREE_HEAP_ALLOCATIONS = shard_0.HOT_TREE_HEAP_ALLOCATIONS;
pub const HOT_ALL_TREES_HEAP_ALLOCATIONS = shard_0.HOT_ALL_TREES_HEAP_ALLOCATIONS;
pub const HOT_PAIR_AUTHENTICATIONS_PER_TREE = shard_0.HOT_PAIR_AUTHENTICATIONS_PER_TREE;
pub const LogSizes = shard_0.LogSizes;
pub const DomainAudits = shard_0.DomainAudits;
/// Rows 6 and 7 deliberately have no preprocessing owner and their witness
/// executors accept a caller-selected trace size.  Until a frozen whole-AIR
/// profile owns those two numbers, this explicit verifier input prevents this
/// bridge from silently inventing them from a proof's invocation count.
pub const PowLogSizes = shard_0.PowLogSizes;
/// Exact verifier-owned scalar parameters in universal roster order.  Empty
/// arrays are explicit: transcript, PoW-check, and PoW-frame have no hidden
/// parameter columns.
pub const Parameters = shard_0.Parameters;
pub const Claims = shard_0.Claims;
pub const Components = shard_0.Components;
/// Authority and transactional tree writer for one fixed-wire profile.
///
/// Integration order is fixed: construct after native verification, install
/// these ten log sizes before manifest sealing, fill/commit preprocessed and
/// main trees, draw universal relations, fill/commit interactions, then call
/// `initComponents` and keep the returned value stable through prove/verify.
pub const Source = shard_1.Source;
