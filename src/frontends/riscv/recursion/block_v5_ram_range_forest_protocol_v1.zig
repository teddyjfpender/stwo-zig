//! Distinct compact RAM/range parent protocol; every internal wire is closed.
const std = @import("std");
const core = @import("stwo_core");
const Recipe = struct {
    pub const VERSION: u32 = 19;
    pub const sourceAuthority = authority;
};
const Impl = @import("block_v5_reusable_wide_public_windows_protocol_impl_v1.zig").ForModules(@import("block_v5_ram_range_forest_bus_v1.zig"), Recipe);
pub const VERSION = Impl.VERSION;
pub const Profile = Impl.Profile;
pub const Context = Impl.Context;
pub const Key = Impl.Key;
pub const Admission = Impl.Admission;
var cached: [32]u8 = undefined;
var once = std.once(initialize);
fn initialize() void {
    cached = authorityUncached();
}
pub fn authority() [32]u8 {
    once.call();
    return cached;
}
pub fn authorityUncached() [32]u8 {
    var c = core.channel.blake3.Channel{};
    c.mixU32s(&.{ 0x52524641, 19 });
    inline for (.{ @embedFile("block_v5_ram_range_forest_plan_v1.zig"), @embedFile("block_v5_ram_range_forest_authority_v1.zig"), @embedFile("block_v5_ram_range_forest_bus_v1.zig"), @embedFile("block_v5_ram_range_forest_fixed_context_v1.zig"), @embedFile("air/block_v5_ram_range_forest_algebra_v1.zig"), @embedFile("air/block_v5_ram_range_forest_graph_v1.zig") }) |bytes| {
        var hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(bytes, &hash, .{});
        c.mixRoot(hash);
    }
    return c.digestBytes();
}
pub const sourceAuthority = authority;
pub const complete_block_authority = false;
