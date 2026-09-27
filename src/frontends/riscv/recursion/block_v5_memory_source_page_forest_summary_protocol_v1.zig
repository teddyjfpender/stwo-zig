//! Exact original closed PAGE grammar with statically typed summary-only
//! receiving values. No original proof/channel/PCS math is duplicated.
const Original = @import("block_v5_memory_source_page_forest_protocol_v1.zig");
const Recipe = struct {
    pub const VERSION = Original.VERSION;
    pub const sourceAuthority = Original.sourceAuthority;
};
const Impl = @import("block_v5_reusable_wide_public_windows_protocol_impl_v1.zig").ForModules(@import("block_v5_memory_source_page_forest_summary_bus_v1.zig"), Recipe);
pub const VERSION = Impl.VERSION;
pub const Key = Impl.Key;
pub const Admission = Impl.Admission;
pub const Profile = Impl.Profile;
pub const sourceAuthority = Impl.sourceAuthority;
pub const complete_source_authority = false;
