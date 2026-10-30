//! Exact terminal-memory facade; finite window mode has a distinct protocol.
pub const ForMode = @import("block_v7_memory_joint_parent_protocol_mode_v1.zig").ForMode;
const Default = ForMode(false);
pub const Bus = Default.Bus;
pub const VERSION = Default.VERSION;
pub const CLAIM_TAG = Default.CLAIM_TAG;
pub const Key = Default.Key;
pub const Admission = Default.Admission;
