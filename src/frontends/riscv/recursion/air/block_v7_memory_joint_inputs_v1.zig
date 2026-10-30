//! Exact terminal-memory facade; finite window mode has a distinct protocol.
pub const ForMode = @import("block_v7_memory_joint_inputs_mode_v1.zig").ForMode;
const Default = ForMode(false);
pub const publicInputs = Default.publicInputs;
pub const challenges = Default.challenges;
pub const composition = Default.composition;
