const std = @import("std");
const core = @import("stwo_core");
const route = @import("../blake3_byte_route.zig");
const node = @import("../blake3_node_route.zig");
const lang = @import("../../../air/lang/mod.zig");
const M31 = core.fields.m31.M31;
test "BLAKE3 byte route pins typed semantics and rejects selected byte mutations" {
    const a = std.testing.allocator;
    const digest = try route.computeSemanticDigest(a);
    try std.testing.expectEqualSlices(u8, &route.SEMANTIC_DIGEST, &digest);
    var d = try route.build(a);
    defer d.deinit();
    const plan = try @import("../universal_relation_binding.zig").Binding(route).authenticate(&d);
    const direct = try @import("../direct_constraint_program.zig").authenticate(&d.arena, route.SEMANTIC_DIGEST, route.LOGICAL_INPUT_COUNT);
    var exported = try @import("../framework_polynomial_export_v1.zig").exportLocalPrepared(route, a, &direct, &plan);
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
    const group = @import("../blake3_merkle_group_witness.zig");
    const equality = try group.rootEquality(.{ .circuit = 1, .first_wire = 40 }, .{ .circuit = 2, .first_wire = 80 }, 7);
    const equal = try route.logicalRow(equality, .{ 0xff01807f, 0 });
    const fixed = try route.fixedRow(equality);
    try std.testing.expectEqualSlices(M31, fixed[12..], equal[12..]);
    try std.testing.expect(try satisfied(&d, equal));
    const entries = plan.preparedEntries(equal);
    try std.testing.expectEqual(core.fields.m31.Modulus - 1, (try entries[0].numerator.tryIntoM31()).v);
    try std.testing.expect(entries[1].numerator.isZero());
    try std.testing.expectEqual(core.fields.m31.Modulus - 1, (try entries[2].numerator.tryIntoM31()).v);
    for (entries[0].values[2..6], entries[2].values[2..6]) |left, right| try std.testing.expect(left.eql(right));
    for (entries[2].values[0..6], [_]u32{ 2, 87, 127, 128, 1, 255 }) |actual, expected| try std.testing.expectEqual(expected, (try actual.tryIntoM31()).v);
    for (0..4) |i| {
        var changed = equal;
        changed[8 + i] = changed[8 + i].add(M31.one());
        try std.testing.expect(!try satisfied(&d, changed));
    }
    try privateRootSchedules();
}
fn satisfied(d: *const route.Definition, row: route.Row) !bool {
    const values = try @import("../test_support.zig").evaluateArena(std.testing.allocator, &d.arena, &row);
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

test "BLAKE3 transcript digest routing matches frames and rejects missing role bindings" {
    const routing = @import("../blake3_frame_route.zig");
    const a = std.testing.allocator;
    const state: [32]u8 = @splat(0xa7);
    const root: [32]u8 = @splat(0x91);
    const caller = routing.Caller{ .circuit = 1, .first_wire = 40 };
    const bindings = [_]routing.Binding{ .{ .role = .state, .caller = caller }, .{ .role = .root, .caller = .{ .circuit = 2, .first_wire = 80 } } };
    const frames = [_]core.channel.blake3.Frame{
        .{ .draw = .{ .state = state, .index = 0xf123456789abcdef } },
        .{ .integer = .{ .state = state, .value = 0x8123456789abcdef } },
        .{ .root = .{ .state = state, .value = root } },
        .{ .pow = .{ .state = state, .bits = 26, .nonce = 0x9876543210 } },
    };
    for (frames, 0..) |frame, frame_index| {
        const count: usize = if (frame_index == 2) 2 else 1;
        var plan = try routing.build(a, 3, frame, bindings[0..count]);
        defer plan.deinit();
        const encoded = try frame.encode(a);
        defer a.free(encoded);
        const actual = try a.alloc(u8, plan.schedules.len * 4);
        defer a.free(actual);
        const callers = [_]routing.Caller{ bindings[0].caller, bindings[1].caller };
        const digests = [_][32]u8{ state, root };
        for (plan.schedules, 0..) |schedule, i| {
            const row = try routing.witnessRow(schedule, callers[0..count], digests[0..count]);
            for (row[8..12], 0..) |byte, j| actual[4 * i + j] = @intCast(byte.toU32());
        }
        try std.testing.expectEqualSlices(u8, encoded, actual[0..encoded.len]);
        for (actual[encoded.len..]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
        for (plan.child_uses[0..count]) |counts| for (counts) |uses| try std.testing.expect(uses > 0 and uses <= 2);
        try std.testing.expectError(error.InvalidBlake3FrameCaller, routing.build(a, 3, frame, &.{}));
        try std.testing.checkAllAllocationFailures(a, frameAllocation, .{ frame, bindings[0..count] });
    }
    const adjacent = [_]routing.Binding{ .{ .role = .state, .caller = .{ .circuit = 1, .first_wire = 40 } }, .{ .role = .root, .caller = .{ .circuit = 1, .first_wire = 48 } } };
    var joined = try routing.build(a, 3, frames[2], &adjacent);
    defer joined.deinit();
    const encoded = try frames[2].encode(a);
    defer a.free(encoded);
    const output = try a.alloc(u8, joined.schedules.len * 4);
    defer a.free(output);
    for (joined.schedules, 0..) |schedule, i| {
        const row = try routing.witnessRow(schedule, &.{ adjacent[0].caller, adjacent[1].caller }, &.{ state, root });
        for (row[8..12], 0..) |byte, j| output[4 * i + j] = @intCast(byte.v);
    }
    try std.testing.expectEqualSlices(u8, encoded, output[0..encoded.len]);
    for ([_]u32{ 33, 40, 47 }) |overlap| {
        var bad = adjacent;
        bad[1].caller.first_wire = overlap;
        try std.testing.expectError(error.InvalidBlake3FrameCaller, routing.build(a, 3, frames[2], &bad));
    }
    try std.testing.expectError(error.InvalidBlake3FrameCaller, routing.build(a, 3, frames[0], &bindings));
    try std.testing.expectError(error.InvalidBlake3FrameCaller, routing.build(a, 3, frames[0], &.{bindings[1]}));
    try std.testing.expectError(error.InvalidBlake3FrameCaller, routing.build(a, 3, frames[2], &.{ bindings[0], bindings[0] }));
}
fn frameAllocation(a: std.mem.Allocator, frame: core.channel.blake3.Frame, bindings: []const @import("../blake3_frame_route.zig").Binding) !void {
    var plan = try @import("../blake3_frame_route.zig").build(a, 3, frame, bindings);
    defer plan.deinit();
}

fn privateRootSchedules() !void {
    const group = @import("../blake3_merkle_group_witness.zig");
    const a = std.testing.allocator;
    const values = [_]M31{ M31.one(), M31.fromCanonical(17), M31.fromCanonical(31), M31.fromCanonical(41) };
    for ([_]u32{ 1, 4 }) |leaves| {
        var s = group.Statement{ .namespace = 100, .payload = .{ .circuit = 10, .first_wire = 0 }, .leaf_count = leaves, .words_per_leaf = 1, .index = 0, .depth = 0, .root = @splat(0), .root_source = .{ .circuit = 20, .first_wire = 8 } };
        var live = try group.prepare(a, s, values[0..leaves], &.{});
        defer live.deinit();
        s.root = @splat(0xff);
        var fixed = try group.trusted(a, s);
        defer fixed.deinit();
        inline for (.{ group.g, group.xor, group.boundary, group.route, group.word }, .{ "g_rows", "xor_rows", "boundary_rows", "route_rows", "word_rows" }) |Air, name| {
            try std.testing.expectEqual(@field(live, name).len, @field(fixed, name).len);
            for (@field(live, name), @field(fixed, name)) |row, trusted| try std.testing.expectEqualSlices(M31, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], trusted[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
        }
        s.root_source = null;
        var public = try group.trusted(a, s);
        defer public.deinit();
        try std.testing.expectEqual(live.boundary_rows.len + 8, public.boundary_rows.len);
        try std.testing.expectEqual(public.route_rows.len + 8, live.route_rows.len);
        s.root_source = .{ .circuit = 100, .first_wire = 0 };
        try std.testing.expectError(error.InvalidBlake3MerkleGroup, group.trusted(a, s));
    }
}
