//! Typed BLAKE3 roster projection shared by proving and independent verification.
pub fn Fixture(comptime with_private_input: bool) type {
    return WithBridge(if (with_private_input) @import("blake3_input_bridge.zig") else null);
}
pub fn WithBridge(comptime Bridge: ?type) type {
    return WithExtras(if (Bridge) |Air| .{Air} else .{});
}
pub fn WithExtras(comptime Extras: anytype) type {
    return @import("universal_component_roster.zig").ForAirs(
        .{ @import("blake3_g_call.zig"), @import("blake3_xor_call.zig"), @import("blake3_boundary.zig") } ++ Extras,
        &.{ "g", "xor", "boundary", "input", "auxiliary", "query", "arithmetic" },
    );
}
