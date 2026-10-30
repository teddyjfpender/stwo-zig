//! Exact terminal-memory facade; finite window mode has a distinct protocol.
pub const ForMode = @import("block_v7_memory_joint_statement_mode_v1.zig").ForMode;
const Default = ForMode(false);
pub const PUBLIC_CIRCUIT = Default.PUBLIC_CIRCUIT;
pub const Statement = Default.Statement;
pub const init = Default.init;
