//! Compatibility facade: exact joint family, shared four-tree implementation.
const Family = @import("block_v7_memory_joint_family_v1.zig").FixedRoster;
pub const Limits = Family.Limits;
pub const Wire = Family.Wire;
pub const Owned = Family.Owned;
pub const ForBackend = Family.ForBackend;
