const std = @import("std");
const core = @import("stwo_core");
const route = @import("blake3_byte_route.zig");
const node = @import("blake3_node_route.zig");
const lang = @import("../../air/lang/mod.zig");
const M31 = core.fields.m31.M31;
test "BLAKE3 byte route pins typed semantics and rejects selected byte mutations" {
    const a = std.testing.allocator;
    const digest = try route.computeSemanticDigest(a);
    try std.testing.expectEqualSlices(u8, &route.SEMANTIC_DIGEST, &digest);
    var d = try route.build(a);
    defer d.deinit();
    const plan = try @import("universal_relation_binding.zig").Binding(route).authenticate(&d);
    const direct = try @import("direct_constraint_program.zig").authenticate(&d.arena, route.SEMANTIC_DIGEST, route.LOGICAL_INPUT_COUNT);
    var exported = try @import("framework_polynomial_export_v1.zig").exportLocalPrepared(route, a, &direct, &plan);
    defer exported.deinit();
    const schedule = route.Schedule{ .sources = .{ .{ .circuit = 1, .wire = 3 }, .{ .circuit = 2, .wire = 7 } }, .destination = .{ .circuit = 8, .wire = 9 }, .uses = 14, .bytes = .{ .{ .source = .{ .word = 0, .byte = 3 } }, .{ .source = .{ .word = 1, .byte = 0 } }, .{ .constant = 71 }, .{ .source = .{ .word = 0, .byte = 1 } } } };
    const row = try route.logicalRow(schedule, .{ 0x12345678, 0xaabbccdd });
    try std.testing.expect(try satisfied(&d, row));
    for ([_]usize{ 3, 4, 1, 8, 9, 10, 11, 21 + 2, 25 + 3 }) |column| {
        var changed = row;
        changed[column] = changed[column].add(M31.one());
        try std.testing.expect(!try satisfied(&d, changed));
    }
    try std.testing.expect(try satisfied(&d, @splat(M31.zero())));
}
fn satisfied(d: *const route.Definition, row: route.Row) !bool {
    const values = try @import("test_support.zig").evaluateArena(std.testing.allocator, &d.arena, &row);
    defer std.testing.allocator.free(values);
    for (d.arena.constraintsView()) |constraint| if (!values[lang.types.idIndex(constraint.root)].isZero()) return false;
    return true;
}
test "BLAKE3 symbolic Merkle routing matches canonical frame bytes" {
    const a = std.testing.allocator;
    const callers = [2]node.Caller{ .{ .circuit = 1, .first_wire = 40 }, .{ .circuit = 2, .first_wire = 80 } };
    const digests: [2][32]u8 = .{ @splat(0xff), @splat(0x81) };
    var plan = try node.build(a, 3, callers);
    defer plan.deinit();
    const bytes = try (core.channel.blake3.Frame{ .node = .{ .left = digests[0], .right = digests[1] } }).encode(a);
    defer a.free(bytes);
    const actual = try a.alloc(u8, plan.schedules.len * 4);
    defer a.free(actual);
    for (plan.schedules, 0..) |schedule, i| {
        const row = try node.witnessRow(schedule, callers, digests);
        for (row[8..12], 0..) |byte, j| actual[i * 4 + j] = @intCast(byte.toU32());
    }
    try std.testing.expectEqualSlices(u8, bytes, actual[0..bytes.len]);
    for (actual[bytes.len..]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (plan.child_uses) |counts| for (counts) |count| try std.testing.expect(count > 0 and count <= 2);
    try std.testing.expectError(error.InvalidBlake3NodeCaller, node.build(a, 1, callers));
}
