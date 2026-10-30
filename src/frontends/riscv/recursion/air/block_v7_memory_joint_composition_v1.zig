//! Exact terminal-memory facade; finite window mode has a distinct protocol.
pub const ForMode = @import("block_v7_memory_joint_composition_mode_v1.zig").ForMode;
const Default = ForMode(false);
pub const RELATION_COUNT = Default.RELATION_COUNT;
pub const Compiled = Default.Compiled;
pub const compile = Default.compile;
