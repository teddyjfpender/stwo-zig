//! Exact terminal-memory facade; finite window mode has a distinct protocol.
pub const ForMode = @import("block_v7_memory_joint_public_mode_v1.zig").ForMode;
const Default = ForMode(false);
pub const API = Default.API;
pub const Wire = Default.Wire;
pub const Values = Default.Values;
pub const supply = Default.supply;
pub const scheduleDigest = Default.scheduleDigest;
pub const reconstruct = Default.reconstruct;
pub const requireSameFrame = Default.requireSameFrame;
