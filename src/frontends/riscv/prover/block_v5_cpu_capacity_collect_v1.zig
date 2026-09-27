//! Explicit B5CT/B5CF first pass; the legacy collector remains the default.
const Impl = @import("block_v5_cpu_collect_v1.zig").ForCapacity(true);
pub const Limits = Impl.Limits;
pub const Collected = Impl.Collected;
pub const collect = Impl.collect;
pub const nativeMetadata = Impl.nativeMetadata;
pub const ordinaryEvents = Impl.ordinaryEvents;
