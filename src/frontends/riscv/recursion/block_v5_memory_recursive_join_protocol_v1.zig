//! Distinct OPEN memory recursive join grammar, not a complete block key.
const core = @import("stwo_core");
const Recipe = struct {
    pub const VERSION: u32 = 18;
    pub const sourceAuthority = authority;
};
const Impl = @import("block_v5_reusable_wide_public_windows_protocol_impl_v1.zig").ForModules(@import("block_v5_memory_recursive_join_public_v1.zig"), Recipe);
pub const VERSION = Impl.VERSION;
pub const Profile = Impl.Profile;
pub const Context = Impl.Context;
pub const Key = Impl.Key;
pub const Admission = Impl.Admission;
pub const sourceAuthority = authority;
pub const complete_block_authority = false;
fn authority() [32]u8 {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42354d41, VERSION });
    inline for (.{ @embedFile("air/block_v5_memory_recursive_join_algebra_v1.zig"), @embedFile("air/block_v5_memory_recursive_join_graph_v1.zig"), @embedFile("block_v5_memory_recursive_join_public_v1.zig"), @embedFile("block_v5_memory_recursive_provider_source_v1.zig") }) |bytes| {
        var digest: [32]u8 = undefined;
        @import("std").crypto.hash.Blake3.hash(bytes, &digest, .{});
        channel.mixRoot(digest);
    }
    channel.mixRoot(@import("block_v5_memory_source_page_forest_protocol_v1.zig").sourceAuthority());
    return channel.digestBytes();
}
