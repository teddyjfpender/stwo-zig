//! Distinct typed PAGE aggregate parent grammar; OPEN for RAM/global joins.
const core = @import("stwo_core");
const std = @import("std");
const Recipe = struct {
    pub const VERSION: u32 = 16;
    pub const sourceAuthority = authority;
};
const Impl = @import("block_v5_reusable_wide_public_windows_protocol_impl_v1.zig").ForModules(@import("block_v5_memory_source_page_forest_bus_v1.zig"), Recipe);
pub const VERSION = Impl.VERSION;
pub const Profile = Impl.Profile;
pub const Key = Impl.Key;
pub const Context = Impl.Context;
pub const Admission = Impl.Admission;
pub const sourceAuthority = authority;
pub const complete_source_authority = false;
pub const complete_block_authority = false;
fn authority() [32]u8 {
    return @import("source_authority_cache_v1.zig").For(computeAuthority).get();
}
// Only compiled recipe bytes enter this cache. Dynamic job policies, expected
// keys, public inputs and proof admission still undergo every original guard.
fn computeAuthority() [32]u8 {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x50474641, VERSION });
    inline for (.{ @embedFile("source_authority_cache_v1.zig"), @embedFile("block_v5_memory_source_page_forest_protocol_v1.zig"), @embedFile("block_v5_memory_source_page_forest_algebra_v1.zig"), @embedFile("block_v5_memory_source_page_forest_plan_v1.zig"), @embedFile("block_v5_memory_source_page_forest_leaf_v1.zig"), @embedFile("block_v5_memory_source_page_forest_bus_v1.zig"), @embedFile("block_v5_memory_source_page_forest_normalizer_v1.zig"), @embedFile("block_v5_memory_source_page_forest_source_v1.zig"), @embedFile("block_v5_memory_source_page_forest_preparation_v1.zig"), @embedFile("block_v5_memory_source_page_forest_fixed_context_v1.zig"), @embedFile("block_v5_memory_source_page_forest_receiver_v1.zig"), @embedFile("air/block_v5_memory_source_page_forest_graph_v1.zig"), @embedFile("air/block_v5_closed_public_supply_v1.zig"), @embedFile("block_v5_public_supply_session_v2.zig"), @embedFile("block_v5_public_supply_identity_v2.zig"), @embedFile("../prover/block_v5_memory_source_page_forest_stage_v1.zig") }) |source| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(source, &digest, .{});
        channel.mixRoot(digest);
    }
    return channel.digestBytes();
}
pub const testing = struct {
    pub const uncachedSourceAuthority = computeAuthority;
};
