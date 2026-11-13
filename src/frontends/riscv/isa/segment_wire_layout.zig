//! Canonical fixed SegmentV2 frame coordinates; no construction or admission policy.

pub const SPAN_STATEMENT_CANONICAL_WORDS = @import("span_word_geometry.zig").For(8, 1).SPAN_STATEMENT_CANONICAL_WORDS;
const V1_PROJECTION_WORD_COUNT = SPAN_STATEMENT_CANONICAL_WORDS;
pub const Side = enum(u1) { entry, exit };

pub const fixed_layout = struct {
    pub const tag: usize = 0;
    pub const format_version: usize = 1;
    pub const schema_version: usize = 2;
    pub const flags: usize = 3;
    pub const session_id: usize = 4;
    pub const job_id: usize = session_id + 8;
    pub const position_id: usize = job_id + 8;
    pub const entry_lineage_id: usize = position_id + 8;
    pub const exit_lineage_id: usize = entry_lineage_id + 8;
    pub const lineage_id: usize = exit_lineage_id + 8;
    pub const base_statement_id: usize = lineage_id + 8;
    pub const base_statement: usize = base_statement_id + 8;
    pub const entry_snapshot_id: usize = base_statement + V1_PROJECTION_WORD_COUNT;
    pub const entry_snapshot_count: usize = entry_snapshot_id + 8;
    pub const entry_continuation_root: usize = entry_snapshot_count + 2;
    pub const exit_snapshot_id: usize = entry_continuation_root + 2;
    pub const exit_snapshot_count: usize = exit_snapshot_id + 8;
    pub const exit_continuation_root: usize = exit_snapshot_count + 2;
    pub const entry_memory_clock_id: usize = exit_continuation_root + 2;
    pub const entry_memory_clock_count: usize = entry_memory_clock_id + 8;
    pub const exit_memory_clock_id: usize = entry_memory_clock_count + 2;
    pub const exit_memory_clock_count: usize = exit_memory_clock_id + 8;
    pub const entry_register_clocks: usize = exit_memory_clock_count + 2;
    pub const exit_register_clocks: usize = entry_register_clocks + 64;
    pub const completion: usize = exit_register_clocks + 64;
};
