//! Exact original B5WM/v1 protocol through the shared typed kernel.
const std = @import("std");
const core = @import("stwo_core");
const Recipe = struct {
    pub const VERSION: u32 = 1;
    pub const sourceAuthority = authority;
};
const Impl = @import("block_v5_reusable_wide_public_windows_protocol_impl_v1.zig").ForModules(@import("block_v5_wide_public_windows_bus_v1.zig"), Recipe);
pub const VERSION = Impl.VERSION;
pub const Profile = Impl.Profile;
pub const Context = Impl.Context;
pub const Key = Impl.Key;
pub const Admission = Impl.Admission;
pub const sourceAuthority = authority;
fn authority() [32]u8 {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42354d53, VERSION });
    inline for (.{ @embedFile("block_v5_wide_public_windows_v1.zig"), @embedFile("block_v5_wide_public_windows_impl_v1.zig"), @embedFile("block_v5_wide_input_policy_v1.zig"), @embedFile("block_v5_wide_public_windows_bus_impl_v1.zig"), @embedFile("block_v5_reusable_wide_public_windows_protocol_impl_v1.zig"), @embedFile("air/block_v5_wide_public_windows_composition_impl_v1.zig"), @embedFile("block_v5_wide_expected_input_owner_v1.zig"), @embedFile("block_v5_wide_public_windows_bus_v1.zig"), @embedFile("block_v5_reusable_wide_public_windows_protocol_v1.zig"), @embedFile("air/block_v5_wide_public_windows_composition_v1.zig"), @embedFile("air/block_v5_global_public_export_rows_v1.zig"), @embedFile("air/block_v5_global_public_tuple_algebra_v1.zig"), @embedFile("block_v5_wide_original_child_source_v1.zig"), @embedFile("block_v5_wide_public_windows_preparation_v1.zig"), @embedFile("block_v5_wide_public_windows_preparation_impl_v1.zig"), @embedFile("block_v5_wide_public_windows_receiver_impl_v1.zig"), @embedFile("block_v5_wide_public_windows_source_impl_v1.zig"), @embedFile("../prover/block_v5_wide_public_windows_stage_impl_v1.zig"), @embedFile("block_v5_wide_public_windows_receiver_v1.zig"), @embedFile("block_v5_wide_public_windows_source_v1.zig"), @embedFile("../prover/block_v5_wide_public_windows_stage_v1.zig"), @embedFile("block_v5_global_public_fields_v1.zig"), @embedFile("../air/program/decode.zig"), @embedFile("../prover/block_v5_universal_channel_v1.zig"), @embedFile("../prover/block_v5_register_windows_v1.zig") }) |source| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(source, &digest, .{});
        channel.mixRoot(digest);
    }
    return channel.digestBytes();
}
