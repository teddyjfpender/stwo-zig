//! Original B5WM/v1 equations; exact scalar and symbolic body is shared.
const Impl = @import("block_v5_wide_public_windows_composition_impl_v1.zig").ForModules(@import("../block_v5_wide_public_windows_v1.zig"), @import("../block_v5_wide_public_windows_bus_v1.zig"));
pub const VERSION = Impl.VERSION;
pub const Source = Impl.Source;
pub const Prepared = Impl.Prepared;
pub const prepare = Impl.prepare;
pub const windowEquations = Impl.windowEquations;
