//! Independently trusted key/statement for a bounded local tail-link ancestor.
//! Version3 of the shared public-parent envelope separates this statement from
//! both old B5WM/v1 and consumer B5WM/v2; no old-key acceptance or H conversion.
const std = @import("std");
const core = @import("stwo_core");
const Recipe = struct {
    pub const VERSION: u32 = 3;
    pub const sourceAuthority = authority;
};
const Impl = @import("block_v5_reusable_wide_public_windows_protocol_impl_v1.zig").ForModules(@import("block_v5_input_tail_ancestor_bus_v1.zig"), Recipe);
pub const VERSION = Impl.VERSION;
pub const Profile = Impl.Profile;
pub const Context = Impl.Context;
pub const Key = Impl.Key;
pub const Admission = Impl.Admission;
pub const sourceAuthority = authority;
pub const complete_source_authority = false;
fn authority() [32]u8 {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42355441, VERSION });
    inline for (.{ @embedFile("block_v5_input_tail_ancestor_bus_v1.zig"), @embedFile("air/block_v5_input_tail_ancestor_graph_v1.zig"), @embedFile("block_v5_input_tail_ancestor_preparation_v1.zig"), @embedFile("block_v5_input_tail_ancestor_protocol_v1.zig"), @embedFile("block_v5_input_tail_ancestor_receiver_v1.zig"), @embedFile("../prover/block_v5_input_tail_ancestor_stage_v1.zig"), @embedFile("block_v5_reusable_wide_public_windows_protocol_impl_v1.zig"), @embedFile("block_v5_reusable_tail_linked_public_windows_protocol_v2.zig"), @embedFile("block_v5_input_tail_protocol_v1.zig"), @embedFile("air/block_v5_scoped_admitted_graph_attach_v1.zig"), @embedFile("air/block_v5_scoped_child_verifier_rows_v1.zig") }) |source| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(source, &digest, .{});
        channel.mixRoot(digest);
    }
    channel.mixRoot(@import("block_v5_reusable_tail_linked_public_windows_protocol_v2.zig").sourceAuthority());
    channel.mixRoot(@import("block_v5_input_tail_protocol_v1.zig").sourceAuthority());
    return channel.digestBytes();
}
