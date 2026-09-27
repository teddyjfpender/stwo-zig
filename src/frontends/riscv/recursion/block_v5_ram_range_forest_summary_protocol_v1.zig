//! Same VERSION/key/transcript as producer, summary-only instance owner.
const Recipe = @import("block_v5_ram_range_forest_protocol_v1.zig");
const Impl = @import("block_v5_reusable_wide_public_windows_protocol_impl_v1.zig").ForModules(@import("block_v5_ram_range_forest_summary_bus_v1.zig"), Recipe);
pub const VERSION = Impl.VERSION;
pub const Profile = Impl.Profile;
pub const Context = Impl.Context;
pub const Key = Impl.Key;
pub const Admission = Impl.Admission;
pub const sourceAuthority = Recipe.sourceAuthority;
