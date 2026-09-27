//! Shared typed implementation with unchanged explicit legacy exports.
const Impl = @import("block_v5_cpu_collect_impl_v1.zig");
pub const ForCapacity = Impl.ForCapacity;
const Legacy = ForCapacity(false);
pub const Limits = Legacy.Limits;
pub const Collected = Legacy.Collected;
pub const collect = Legacy.collect;
