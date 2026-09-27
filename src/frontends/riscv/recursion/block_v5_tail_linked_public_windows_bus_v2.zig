//! B5WM/v2 supply includes independently admitted prefix/frontier coordinates.
const Impl = @import("block_v5_wide_public_windows_bus_impl_v1.zig").ForModules(@import("block_v5_tail_linked_public_windows_v2.zig"));
pub const VERSION = Impl.VERSION;
pub const Source = Impl.Source;
pub const Wire = Impl.Wire;
pub const scheduleDigest = Impl.scheduleDigest;
pub const Values = Impl.Values;
pub const supply = Impl.supply;
