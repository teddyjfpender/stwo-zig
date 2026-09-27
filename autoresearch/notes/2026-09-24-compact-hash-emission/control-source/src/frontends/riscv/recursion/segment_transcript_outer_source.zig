//! Production outer-proof source for universal segment-leaf rows 0--9.
//!
//! This module is the only bridge from verifier-owned transcript schedules and
//! `segment_transcript_witness.Prepared` into committed recursion columns.  It
//! owns row 0 from the same two schedules, authenticates every typed AIR and
//! relation program once, and transactionally fills universal-manifest tree
//! placements.  No proof-derived scalar is accepted outside the prepared
//! transcript aggregate.

const shard_0 = @import("segment_transcript_outer_source_executors.zig");
const shard_1 = @import("segment_transcript_outer_source_source.zig");
const shard_2 = @import("segment_transcript_outer_source_stage.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const FIRST_ROW = shard_0.FIRST_ROW;
pub const ROW_COUNT = shard_0.ROW_COUNT;
pub const LAST_ROW = shard_0.LAST_ROW;
pub const MIN_LOG_SIZE = shard_0.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = shard_0.MAX_LOG_SIZE;
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
