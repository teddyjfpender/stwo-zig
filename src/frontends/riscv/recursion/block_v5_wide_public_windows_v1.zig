//! Original B5WM/v1 API and bytes, delegated to one typed window implementation.
const Impl = @import("block_v5_wide_public_windows_impl_v1.zig").ForInputPolicy(@import("block_v5_wide_input_policy_v1.zig"));
pub const VERSION = Impl.VERSION;
pub const TAG = Impl.TAG;
pub const Terms = Impl.Terms;
pub const Range = Impl.Range;
pub const Policy = Impl.Policy;
pub const Limits = Impl.Limits;
pub const Coordinate = Impl.Coordinate;
pub const CycleCoordinates = Impl.CycleCoordinates;
pub const Layout = Impl.Layout;
pub const Owner = Impl.Owner;
pub const layoutFor = Impl.layoutFor;
pub const init = Impl.init;
