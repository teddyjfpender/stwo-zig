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
    try payloadCases(a);
}
fn allocationCase(a: std.mem.Allocator) !void {
    var live = try frame.prepare(a, 2, message, &bindings, @splat(0));
    defer live.deinit();
    var fixed = try frame.trusted(a, 2, message, &bindings, @splat(0));
    defer fixed.deinit();
}

fn payloadCases(a: std.mem.Allocator) !void {
    const M31 = core.fields.m31.M31;
    const QM31 = core.fields.qm31.QM31;
    const values = [_]M31{ M31.one(), M31.fromCanonical(2147483646), M31.fromCanonical(256), M31.fromCanonical(19) };
    const fields = [_]QM31{QM31.fromM31Array(values)};
    const zeros = [_]M31{ M31.zero(), M31.zero(), M31.zero(), M31.zero() };
    const zero_fields = [_]QM31{QM31.zero()};
    const raw = [_]u32{ 0, 0xffffffff, 0x80000000, 19 };
    const zero_raw = [_]u32{ 0, 0, 0, 0 };
    const frames = [_]core.channel.blake3.Frame{ .{ .leaf = &values }, .{ .felts = .{ .state = @splat(0xa7), .values = &fields } }, .{ .words = .{ .state = @splat(0xa7), .values = &raw } } };
    const placeholders = [_]core.channel.blake3.Frame{ .{ .leaf = &zeros }, .{ .felts = .{ .state = @splat(0), .values = &zero_fields } }, .{ .words = .{ .state = @splat(0), .values = &zero_raw } } };
    const roles = [_]core.channel.blake3.framing.PayloadRole{ .leaf, .felts, .words };
    for (frames, placeholders, roles, 0..) |message_frame, placeholder, role, i| {
        const payload = frame.PayloadBinding{ .role = role, .caller = .{ .circuit = 2, .first_wire = 80 }, .word_count = 4 };
        const active = bindings[0..if (i == 0) @as(usize, 0) else 1];
        var live = try frame.preparePayload(a, 3, message_frame, active, payload, message_frame.hash());
        defer live.deinit();
        var fixed = try frame.trustedPayload(a, 3, placeholder, active, payload, message_frame.hash());
        defer fixed.deinit();
        try std.testing.expectEqualSlices(u32, live.payload_uses, fixed.payload_uses);
        for (live.payload_uses) |uses| try std.testing.expect(uses > 0 and uses <= 2);
        inline for (.{ g, xor, boundary, frame.route }, .{ live.rows.g_rows, live.rows.xor_rows, live.rows.boundary_rows, live.route_rows }, .{ fixed.rows.g_rows, fixed.rows.xor_rows, fixed.rows.boundary_rows, fixed.route_rows }) |Air, actual, expected| {
            try std.testing.expectEqual(actual.len, expected.len);
            for (actual, expected) |row, trusted_row| try std.testing.expectEqualSlices(M31, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], trusted_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
        }
        var bad = payload;
        bad.word_count += 1;
        try std.testing.expectError(error.InvalidBlake3FrameCaller, frame.trustedPayload(a, 3, placeholder, active, bad, message_frame.hash()));
        bad = payload;
        bad.role = if (role == .leaf) .words else .leaf;
        try std.testing.expectError(error.InvalidBlake3FrameCaller, frame.trustedPayload(a, 3, placeholder, active, bad, message_frame.hash()));
    }
    try std.testing.checkAllAllocationFailures(a, payloadAllocationCase, .{});
}
fn payloadAllocationCase(a: std.mem.Allocator) !void {
    const values = [_]core.fields.m31.M31{core.fields.m31.M31.one()};
    const payload = frame.PayloadBinding{ .role = .leaf, .caller = .{ .circuit = 1, .first_wire = 0 }, .word_count = 1 };
    var live = try frame.preparePayload(a, 2, .{ .leaf = &values }, &.{}, payload, @splat(0));
    defer live.deinit();
    var fixed = try frame.trustedPayload(a, 2, .{ .leaf = &values }, &.{}, payload, @splat(0));
    defer fixed.deinit();
}
