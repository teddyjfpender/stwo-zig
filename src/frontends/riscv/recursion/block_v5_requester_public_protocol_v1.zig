//! Direct public-closed requester statement. Memory/source transition remains
//! OPEN for the independently verified compact memory-root join.
const std = @import("std");
const core = @import("stwo_core");
const Bus = @import("block_v5_requester_public_bus_v1.zig");
const Recipe = struct {
    pub const VERSION = Bus.VERSION;
    pub const sourceAuthority = authority;
};
const Impl = @import("block_v5_reusable_wide_public_windows_protocol_impl_v1.zig").ForModules(Bus, Recipe);
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
    c.mixU32s(&.{ 0x52515041, VERSION });
    inline for (.{ @embedFile("block_v5_requester_public_compensation_v1.zig"), @embedFile("block_v5_requester_public_bus_v1.zig"), @embedFile("air/block_v5_requester_public_composition_v1.zig"), @embedFile("block_v5_requester_public_preparation_v1.zig"), @embedFile("block_v5_requester_public_assembly_ports_v1.zig"), @embedFile("air/block_v5_global_public_tuple_algebra_v1.zig"), @embedFile("air/block_v5_scoped_public_compensation_algebra_v1.zig"), @embedFile("air/block_v5_global_public_export_rows_v1.zig"), @embedFile("block_v5_requester_public_receiver_v1.zig"), @embedFile("block_v5_requester_public_source_v1.zig"), @embedFile("block_v5_global_public_fields_v1.zig"), @embedFile("block_v5_global_public_export_policy_v1.zig"), @embedFile("block_v5_heterogeneous_scoped_plan_v1.zig") }) |bytes| {
        var hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(bytes, &hash, .{});
        c.mixRoot(hash);
    }
    return c.digestBytes();
}
