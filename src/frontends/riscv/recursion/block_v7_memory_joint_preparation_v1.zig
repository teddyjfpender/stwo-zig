//! Compatibility facade: exact joint family, shared four-tree implementation.
const Family = @import("block_v7_memory_joint_family_v1.zig").Preparation;
pub const Limits = Family.Limits;
pub const Prepared = Family.Prepared;
pub const prepare = Family.prepare;
pub const plan = Family.plan;
pub const planWithShared = Family.planWithShared;
