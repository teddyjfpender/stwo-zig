//! Compatibility facade: exact joint family, shared four-tree implementation.
const Family = @import("block_v7_memory_joint_family_v1.zig").Fixed;
pub const Limits = Family.Limits;
pub const Owned = Family.Owned;
