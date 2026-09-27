//! Explicit typed capacity complete-bundle transport.
const Impl = @import("block_v5_cpu_bundle_policy_v1.zig").ForCapacity(true);
pub const Owned = Impl.Owned;
pub const build = Impl.build;
pub const collect = Impl.collect;
pub const validateStructure = Impl.validateStructure;
