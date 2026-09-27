//! Derive transport allocation bounds exclusively from independent complete
//! receiver pins. No proof, file manifest or received claims choose geometry.
pub const ForCapacity = @import("block_v5_cpu_bundle_policy_impl_v1.zig").ForCapacity;
const Default = ForCapacity(false);
pub const Owned = Default.Owned;
pub const build = Default.build;
pub const collect = Default.collect;
pub const validateStructure = Default.validateStructure;
