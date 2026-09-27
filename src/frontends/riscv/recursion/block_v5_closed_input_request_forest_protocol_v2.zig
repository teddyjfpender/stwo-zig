//! Genuine request-summary parent, separate version5 of the original shared
//! public-parent envelope. No old H/root grammar or received template accepted.
const std = @import("std");
const core = @import("stwo_core");
const Recipe = struct {
    pub const VERSION: u32 = 5;
    pub const sourceAuthority = authority;
};
const Impl = @import("block_v5_reusable_wide_public_windows_protocol_impl_v1.zig").ForModules(@import("block_v5_closed_input_request_forest_bus_v2.zig"), Recipe);
pub const VERSION = Impl.VERSION;
pub const Profile = Impl.Profile;
pub const Context = Impl.Context;
pub const Key = Impl.Key;
pub const Admission = Impl.Admission;
pub const sourceAuthority = authority;
pub const complete_source_authority = false;
fn authority() [32]u8 {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42354946, VERSION });
    inline for (.{ @embedFile("block_v5_closed_input_request_forest_bus_v2.zig"), @embedFile("block_v5_closed_input_request_forest_protocol_v2.zig"), @embedFile("block_v5_closed_input_request_forest_receiver_v2.zig"), @embedFile("block_v5_closed_input_request_forest_source_v2.zig"), @embedFile("block_v5_closed_input_request_forest_preparation_v2.zig"), @embedFile("air/block_v5_input_request_forest_graph_v1.zig"), @embedFile("air/block_v5_closed_public_supply_v1.zig"), @embedFile("block_v5_public_supply_session_v2.zig"), @embedFile("block_v5_public_supply_identity_v2.zig"), @embedFile("../prover/block_v5_closed_input_request_forest_stage_v2.zig"), @embedFile("block_v5_reusable_wide_public_windows_protocol_impl_v1.zig"), @embedFile("air/blake3_boundary.zig"), @embedFile("block_v5_input_request_forest_public_v1.zig"), @embedFile("block_v5_input_request_forest_plan_v1.zig"), @embedFile("../prover/block_v5_closed_input_request_forest_setup_v2.zig"), @embedFile("air/blake3_direct_cohort_columns_v1.zig"), @embedFile("air/stable_graph_arena_v1.zig"), @embedFile("air/block_v5_scoped_child_verifier_rows_v1.zig"), @embedFile("air/block_v5_scoped_admitted_graph_attach_v1.zig") }) |source| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(source, &digest, .{});
        channel.mixRoot(digest);
    }
    channel.mixRoot(@import("block_v5_reusable_tail_linked_public_windows_protocol_v2.zig").sourceAuthority());
    channel.mixRoot(@import("block_v5_input_tail_protocol_v1.zig").sourceAuthority());
    return channel.digestBytes();
}
