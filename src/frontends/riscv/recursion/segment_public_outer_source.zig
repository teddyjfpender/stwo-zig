//! Production outer-proof source for universal segment-leaf rows 12--17.
//!
//! Rows 12--14 are materialized exclusively from
//! `segment_leaf_authority.Prepared`. Rows 15 and 16 bind those values to two
//! verifier-owned arithmetic graphs; row 17 binds the exact public-LogUp slice
//! in both authenticated transcript schedules. The two graphs are exported as
//! explicit `verifier_arithmetic_lowering` lanes. Consequently the full outer
//! proof folds their operations into the shared rows 30--32 and does not own a
//! second transcription of either graph's equations.
//!
//! Main, preprocessing, and interaction writes are failure atomic. Logical
//! relation rows are cached when an instance is prepared, and every framework
//! interaction performs one bulk inversion per component.

const shard_0 = @import("segment_public_outer_source_owners.zig");
const shard_1 = @import("segment_public_outer_source_source.zig");
const shard_2 = @import("segment_public_outer_source_stage.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const FIRST_ROW = shard_0.FIRST_ROW;
pub const ROW_COUNT = shard_0.ROW_COUNT;
pub const LAST_ROW = shard_0.LAST_ROW;
pub const CLAIM_CIRCUIT_ID = shard_0.CLAIM_CIRCUIT_ID;
pub const PUBLIC_LOGUP_CIRCUIT_ID = shard_0.PUBLIC_LOGUP_CIRCUIT_ID;
pub const LogSizes = shard_0.LogSizes;
pub const DomainAudits = shard_0.DomainAudits;
pub const Parameters = shard_0.Parameters;
pub const Claims = shard_0.Claims;
pub const Components = shard_0.Components;
pub const Prepared = shard_1.Prepared;
pub const Source = shard_1.Source;
