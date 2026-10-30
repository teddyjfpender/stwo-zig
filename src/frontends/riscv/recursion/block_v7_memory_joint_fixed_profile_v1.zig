//! Exact terminal-memory facade; finite window mode has a distinct protocol.
pub const ForMode = @import("block_v7_memory_joint_fixed_profile_mode_v1.zig").ForMode;
const Default = ForMode(false);
pub const Input = Default.Input;
pub const Limits = Default.Limits;
pub const Owned = Default.Owned;
