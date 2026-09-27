//! Versioned final transition grammar, with no external recursion-wire supply.
//! This protocol does not issue canonical complete-block authority.
const std = @import("std");
const core = @import("stwo_core");
const Recipe = struct {
    pub const VERSION: u32 = 22;
    pub const sourceAuthority = authority;
};
const Impl = @import("block_v5_reusable_wide_public_windows_protocol_impl_v1.zig").ForModules(@import("block_v5_requester_memory_public_v1.zig"), Recipe);
pub const VERSION = Impl.VERSION;
pub const Profile = Impl.Profile;
pub const Context = Impl.Context;
pub const Key = Impl.Key;
pub const Admission = Impl.Admission;
pub const sourceAuthority = authority;
var cached: [32]u8 = undefined;
var once = std.once(initialize);
fn initialize() void {
    cached = uncached();
}
fn authority() [32]u8 {
    once.call();
    return cached;
}
fn uncached() [32]u8 {
    var c = core.channel.blake3.Channel{};
    c.mixU32s(&.{ 0x52514d41, 22 });
    inline for (.{ @embedFile("block_v5_requester_memory_public_v1.zig"), @embedFile("air/block_v5_requester_memory_algebra_v1.zig"), @embedFile("air/block_v5_requester_memory_graph_v1.zig"), @embedFile("block_v5_requester_memory_fixed_context_v1.zig") }) |bytes| {
        var h: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(bytes, &h, .{});
        c.mixRoot(h);
    }
    c.mixRoot(@import("block_v5_source_ram_forest_join_protocol_v1.zig").sourceAuthority());
    c.mixRoot(@import("block_v5_requester_public_protocol_v1.zig").sourceAuthority());
    return c.digestBytes();
}
