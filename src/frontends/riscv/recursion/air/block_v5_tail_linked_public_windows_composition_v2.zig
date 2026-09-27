//! Same actual public compensation/full-u64 equations for tail-linked windows.
const Impl = @import("block_v5_wide_public_windows_composition_impl_v1.zig").ForModules(@import("../block_v5_tail_linked_public_windows_v2.zig"), @import("../block_v5_tail_linked_public_windows_bus_v2.zig"));
pub const VERSION = Impl.VERSION;
pub const Source = Impl.Source;
pub const Prepared = Impl.Prepared;
pub const prepare = Impl.prepare;
pub const windowEquations = Impl.windowEquations;
