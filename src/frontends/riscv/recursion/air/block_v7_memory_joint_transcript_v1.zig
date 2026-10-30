//! Exact terminal-memory facade; finite window mode has a distinct protocol.
pub const ForMode = @import("block_v7_memory_joint_transcript_mode_v1.zig").ForMode;
const Default = ForMode(false);
pub const RELATION_PAIRS = Default.RELATION_PAIRS;
pub const prefixFixed = Default.prefixFixed;
pub const prefix = Default.prefix;
pub const planReplay = Default.planReplay;
