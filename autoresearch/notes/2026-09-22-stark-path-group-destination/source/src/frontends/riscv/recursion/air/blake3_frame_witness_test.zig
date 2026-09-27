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
    try destinationCase(a, true);
    try std.testing.checkAllAllocationFailures(a, destinationCase, .{false});
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
    try payloadCases(a);
    try groupDestinationAllocationCase(a, true);
    try std.testing.checkAllAllocationFailures(a, groupDestinationAllocationCase, .{false});
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

fn destinationCase(a: std.mem.Allocator, check_invalid: bool) !void {
    const M = core.fields.m31.M31;
    var expected = try frame.prepare(a, 2, message, &bindings, message.hash());
    defer expected.deinit();
    var trusted = try frame.trusted(a, 2, message, &bindings, message.hash());
    defer trusted.deinit();
    const gs = try a.alloc(g.Row, expected.rows.g_rows.len);
    defer a.free(gs);
    const xs = try a.alloc(xor.Row, expected.rows.xor_rows.len);
    defer a.free(xs);
    const destination = frame.HashDestination{ .g_rows = gs, .xor_rows = xs };
    {
        var result = try frame.prepareInto(a, 2, message, &bindings, null, message.hash(), destination);
        defer result.deinit();
        try std.testing.expectEqual(gs.ptr, result.rows.g_rows.ptr);
        try std.testing.expectEqual(xs.ptr, result.rows.xor_rows.ptr);
        try std.testing.expectEqualDeep(expected.rows, result.rows);
        try std.testing.expectEqualDeep(expected.route_rows, result.route_rows);
        try std.testing.expectEqualDeep(expected.source_uses, result.source_uses);
        try std.testing.expectEqualDeep(expected.digest, result.digest);
    }
    // Borrowed buffers survive receipt destruction and are reusable by fixed generation.
    try std.testing.expectEqualDeep(expected.rows.g_rows, gs);
    try std.testing.expectEqualDeep(expected.rows.xor_rows, xs);
    {
        var result = try frame.trustedInto(a, 2, message, &bindings, null, message.hash(), destination);
        defer result.deinit();
        try std.testing.expectEqualDeep(trusted.rows, result.rows);
        try std.testing.expectEqualDeep(trusted.route_rows, result.route_rows);
        try std.testing.expect(result.digest == null);
    }
    if (!check_invalid) return;
    @memset(gs, @splat(M.fromCanonical(123)));
    var invalid = destination;
    invalid.xor_rows = xs[1..];
    try std.testing.expectError(error.InvalidBlake3WitnessDestination, frame.prepareInto(a, 2, message, &bindings, null, message.hash(), invalid));
    try std.testing.expectError(error.InvalidBlake3WitnessDestination, frame.trustedInto(a, 2, message, &bindings, null, message.hash(), invalid));
    for (gs) |row| for (row) |value| try std.testing.expectEqual(@as(u32, 123), value.v);
}

fn groupDestinationAllocationCase(a: std.mem.Allocator, check_invalid: bool) !void {
    const group = @import("blake3_merkle_group_witness.zig");
    const directions = [_]group.select.Endpoint{.{ .circuit = 80, .wire = 0 }};
    const statement = group.Statement{ .namespace = 1000, .payload = .{ .circuit = 77, .first_wire = 0 }, .leaf_count = 2, .words_per_leaf = 1, .index = 1, .depth = 1, .root = @splat(0), .root_source = .{ .circuit = 78, .first_wire = 0 }, .directions = &directions };
    const values = [_]core.fields.m31.M31{ .one(), .fromCanonical(19) };
    const siblings = [_][32]u8{@splat(11)};
    var live = try group.prepare(a, statement, &values, &siblings);
    defer live.deinit();
    var fixed = try group.trusted(a, statement);
    defer fixed.deinit();
    try std.testing.expect(live.computed_root != null);
    try std.testing.expectEqualSlices(u32, live.payload_uses, fixed.payload_uses);
    inline for (.{ g, xor }, .{ live.g_rows, live.xor_rows }, .{ fixed.g_rows, fixed.xor_rows }) |Air, rows, trusted_rows| {
        try std.testing.expectEqual(rows.len, trusted_rows.len);
        for (rows, trusted_rows) |row, trusted_row| try std.testing.expectEqualSlices(core.fields.m31.M31, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], trusted_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
    const counts = try group.requiredHashRows(a, statement);
    const gs = try a.alloc(g.Row, counts.g);
    defer a.free(gs);
    const xs = try a.alloc(xor.Row, counts.xor);
    defer a.free(xs);
    const out = group.HashDestination{ .g_rows = gs, .xor_rows = xs };
    {
        var result = try group.prepareInto(a, statement, &values, &siblings, out);
        defer result.deinit();
        try std.testing.expectEqual(gs.ptr, result.g_rows.ptr);
        try std.testing.expectEqual(xs.ptr, result.xor_rows.ptr);
        try std.testing.expectEqualDeep(live.g_rows, result.g_rows);
        try std.testing.expectEqualDeep(live.xor_rows, result.xor_rows);
        try std.testing.expectEqualDeep(live.computed_root, result.computed_root);
        try std.testing.expectEqualDeep(live.route_rows, result.route_rows);
    }
    try std.testing.expectEqualDeep(live.g_rows, gs);
    {
        var result = try group.trustedInto(a, statement, out);
        defer result.deinit();
        try std.testing.expectEqualDeep(fixed.g_rows, result.g_rows);
        try std.testing.expectEqualDeep(fixed.xor_rows, result.xor_rows);
    }
    if (check_invalid) {
        @memset(gs, @splat(core.fields.m31.M31.fromCanonical(123)));
        var invalid = out;
        invalid.xor_rows = xs[1..];
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, group.prepareInto(a, statement, &values, &siblings, invalid));
        try std.testing.expectError(error.InvalidBlake3WitnessDestination, group.trustedInto(a, statement, invalid));
        for (gs) |row| for (row) |value| try std.testing.expectEqual(@as(u32, 123), value.v);
    }
}
