//! Compatibility facade: exact joint family, shared four-tree implementation.
const Family = @import("block_v7_memory_joint_family_v1.zig").FixedTranscript;
pub const derive = Family.derive;
pub const deriveWithShared = Family.deriveWithShared;
