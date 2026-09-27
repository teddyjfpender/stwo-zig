const std = @import("std");
const core = @import("stwo_core");
const select = @import("blake3_path_select.zig");
const M31 = core.fields.m31.M31;
test "BLAKE3 path selector pins typed semantics and authenticates both directions" {
    const a = std.testing.allocator;
    const digest = try select.computeSemanticDigest(a);
    try std.testing.expectEqualSlices(u8, &select.SEMANTIC_DIGEST, &digest);
    var d = try select.build(a);
    defer d.deinit();
    const plan = try @import("universal_relation_binding.zig").Binding(select).authenticate(&d);
    const direct = try @import("direct_constraint_program.zig").authenticate(&d.arena, select.SEMANTIC_DIGEST, select.LOGICAL_INPUT_COUNT);
    var exported = try @import("framework_polynomial_export_v1.zig").exportLocalPrepared(select, a, &direct, &plan);
    defer exported.deinit();
    const schedule = select.Schedule{ .bit = .{ .circuit = 1, .wire = 7 }, .current = .{ .circuit = 2, .wire = 8 }, .sibling = .{ .circuit = 3, .wire = 9 }, .destination_circuit = 4, .left_wire = 10, .right_wire = 11, .left_uses = 2, .right_uses = 1 };
    const fixed = try select.fixedRow(schedule);
    for ([_]u1{ 0, 1 }) |bit| {
        const row = try select.logicalRow(schedule, bit, 0xff01807f, 0x271938ab);
        try std.testing.expectEqualSlices(M31, fixed[17..], row[17..]);
        try std.testing.expect(try satisfied(&d, row));
        const entries = plan.preparedEntries(row);
        try std.testing.expectEqual(@as(u32, bit), (try entries[0].values[2].tryIntoM31()).v);
        for (entries[3].values[2..6], entries[if (bit == 0) @as(usize, 1) else 2].values[2..6]) |left, right| try std.testing.expect(left.eql(right));
        for (entries[4].values[2..6], entries[if (bit == 0) @as(usize, 2) else 1].values[2..6]) |left, right| try std.testing.expect(left.eql(right));
        for (0..17) |i| {
            var bad = row;
            bad[i] = bad[i].add(M31.one());
            try std.testing.expect(!try satisfied(&d, bad));
        }
    }
    try std.testing.expect(try satisfied(&d, @splat(M31.zero())));
    try privateDirections(a);
}
fn satisfied(d: *const select.Definition, row: select.Row) !bool {
    const values = try @import("test_support.zig").evaluateArena(std.testing.allocator, &d.arena, &row);
    defer std.testing.allocator.free(values);
    for (d.arena.constraintsView()) |constraint| if (!values[@import("../../air/lang/mod.zig").types.idIndex(constraint.root)].isZero()) return false;
    return true;
}

fn privateDirections(a: std.mem.Allocator) !void {
    const group = @import("blake3_merkle_group_witness.zig");
    const direction = [_]select.Endpoint{.{ .circuit = 30, .wire = 7 }};
    const values = [_]M31{M31.one()};
    const siblings = [_][32]u8{@splat(0xff)};
    var statement = group.Statement{ .namespace = 100, .payload = .{ .circuit = 10, .first_wire = 0 }, .leaf_count = 1, .words_per_leaf = 1, .index = 0, .depth = 1, .root = @splat(0), .root_source = .{ .circuit = 20, .first_wire = 0 }, .directions = &direction };
    var left = try group.prepare(a, statement, &values, &siblings);
    defer left.deinit();
    statement.index = 1;
    var right = try group.prepare(a, statement, &values, &siblings);
    defer right.deinit();
    var fixed = try group.trusted(a, statement);
    defer fixed.deinit();
    try std.testing.expect(!std.mem.eql(u8, &left.computed_root.?, &right.computed_root.?));
    try std.testing.expectEqual(@as(usize, 8), left.select_rows.len);
    for (left.select_rows, right.select_rows) |l, r| {
        try std.testing.expectEqual(@as(u32, 0), l[0].v);
        try std.testing.expectEqual(@as(u32, 1), r[0].v);
    }
    inline for (.{ group.g, group.xor, group.boundary, group.route, group.word, select }, .{ "g_rows", "xor_rows", "boundary_rows", "route_rows", "word_rows", "select_rows" }) |Air, name| {
        try std.testing.expectEqual(@field(left, name).len, @field(right, name).len);
        try std.testing.expectEqual(@field(left, name).len, @field(fixed, name).len);
        for (@field(left, name), @field(right, name), @field(fixed, name)) |l, r, trusted| {
            try std.testing.expectEqualSlices(M31, l[Air.PHYSICAL_MAIN_COLUMN_COUNT..], r[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
            try std.testing.expectEqualSlices(M31, l[Air.PHYSICAL_MAIN_COLUMN_COUNT..], trusted[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
        }
    }
    statement.directions = &.{};
    try std.testing.expectError(error.InvalidBlake3MerkleGroup, group.trusted(a, statement));
    statement.directions = &.{.{ .circuit = 101, .wire = 0 }};
    try std.testing.expectError(error.InvalidBlake3MerkleGroup, group.trusted(a, statement));
}
