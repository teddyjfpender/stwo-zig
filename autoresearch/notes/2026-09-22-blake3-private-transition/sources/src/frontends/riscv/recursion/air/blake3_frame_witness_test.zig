const std = @import("std");
const core = @import("stwo_core");
const frame = @import("blake3_frame_witness.zig");
const g = @import("blake3_g_call.zig");
const xor = @import("blake3_xor_call.zig");
const boundary = @import("blake3_boundary.zig");
const bindings = [_]frame.Binding{.{ .role = .state, .caller = .{ .circuit = 1, .first_wire = 40 } }};
const message = core.channel.blake3.Frame{ .integer = .{ .state = @splat(0xa7), .value = 42 } };
test "BLAKE3 routed frame witness hides digest bytes from fixed columns and owns allocations" {
    const a = std.testing.allocator;
    const digest = message.hash();
    var live = try frame.prepare(a, 2, message, &bindings, digest);
    defer live.deinit();
    const placeholder = core.channel.blake3.Frame{ .integer = .{ .state = @splat(0), .value = 42 } };
    var fixed = try frame.trusted(a, 2, placeholder, &bindings, digest);
    defer fixed.deinit();
    try std.testing.expectEqualSlices(u8, &digest, &live.digest.?);
    try std.testing.expect(fixed.digest == null);
    try std.testing.expectEqualDeep(live.source_uses, fixed.source_uses);
    inline for (.{ g, xor, boundary, frame.route }, .{ live.rows.g_rows, live.rows.xor_rows, live.rows.boundary_rows, live.route_rows }, .{ fixed.rows.g_rows, fixed.rows.xor_rows, fixed.rows.boundary_rows, fixed.route_rows }) |Air, actual, expected| {
        try std.testing.expectEqual(actual.len, expected.len);
        for (actual, expected) |row, trusted_row| try std.testing.expectEqualSlices(core.fields.m31.M31, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], trusted_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}
fn allocationCase(a: std.mem.Allocator) !void {
    var live = try frame.prepare(a, 2, message, &bindings, @splat(0));
    defer live.deinit();
    var fixed = try frame.trusted(a, 2, message, &bindings, @splat(0));
    defer fixed.deinit();
}
