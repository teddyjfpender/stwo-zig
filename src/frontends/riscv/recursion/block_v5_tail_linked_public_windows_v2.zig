//! Distinct B5WM/v2 frontier public grammar; no old input-root coercion.
const Impl = @import("block_v5_wide_public_windows_impl_v1.zig").ForInputPolicy(@import("block_v5_tail_linked_input_policy_v2.zig"));
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
