const std = @import("std");
const core = @import("stwo_core");
const encoding = @import("../blake3_field_bytes.zig");
const binding = @import("../universal_relation_binding.zig");
const schema = @import("../../../air/lookups/tables/schema.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const schedule = encoding.Schedule{ .source_circuit = 1, .source_wire = 8, .destination_circuit = 2, .destination_first = 40, .uses = @splat(1) };
test "BLAKE3 field byte encoding pins canonical coordinates and rejects modular aliases" {
    const a = std.testing.allocator;
    const digest = try encoding.computeSemanticDigest(a);
    if (!std.mem.eql(u8, &digest, &encoding.SEMANTIC_DIGEST)) std.debug.print("FIELD_BYTES_DIGEST={x}\n", .{digest});
    try std.testing.expectEqualSlices(u8, &encoding.SEMANTIC_DIGEST, &digest);
    var d = try encoding.build(a);
    defer d.deinit();
    const plan = try binding.Binding(encoding).authenticate(&d);
    const direct = try @import("../direct_constraint_program.zig").authenticate(&d.arena, encoding.SEMANTIC_DIGEST, encoding.LOGICAL_INPUT_COUNT);
    var exported = try @import("../framework_polynomial_export_v1.zig").exportLocalPrepared(encoding, a, &direct, &plan);
    defer exported.deinit();
    for ([_]u32{ 0, 1, 255, 256, 0x7fffff00, 0x7ffffffe }) |word| {
        const row = try encoding.logicalRow(schedule, QM31.fromM31Array(@splat(M31.fromCanonical(word))));
        try std.testing.expect(try satisfied(&d, row));
        const entries = plan.preparedEntries(row);
        for (0..4) |i| {
            _ = try schema.indexSecure(.range_check_8_8, entries[4 * i].values[0..2]);
            _ = try schema.indexSecure(.range_check_8_8, entries[4 * i + 1].values[0..2]);
            _ = try schema.indexSecure(.bitwise, entries[4 * i + 2].values[0..4]);
            var reconstructed: u32 = 0;
            for (row[4 + i * 4 ..][0..4], 0..) |byte, j| reconstructed |= byte.toU32() << @as(u5, @intCast(j * 8));
            try std.testing.expectEqual(word, reconstructed);
            for ([_]usize{ i, 20 + i, 4 + 4 * i }) |column| {
                var changed = row;
                changed[column] = changed[column].add(M31.one());
                try std.testing.expect(!try satisfied(&d, changed));
            }
        }
    }
    var alias = try encoding.logicalRow(schedule, QM31.zero());
    alias[4..8].* = .{ M31.fromCanonical(255), M31.fromCanonical(255), M31.fromCanonical(255), M31.fromCanonical(127) };
    try std.testing.expect(!try satisfied(&d, alias));
    var high = try encoding.logicalRow(schedule, QM31.fromM31Array(.{ M31.one(), M31.zero(), M31.zero(), M31.zero() }));
    high[4..8].* = .{ M31.zero(), M31.zero(), M31.zero(), M31.fromCanonical(128) };
    high[20] = try M31.fromCanonical(892 - 128).inv();
    try std.testing.expect(try satisfied(&d, high));
    const high_entries = plan.preparedEntries(high);
    try std.testing.expectError(error.InvalidTuple, schema.indexSecure(.bitwise, high_entries[2].values[0..4]));
    try std.testing.expect(try satisfied(&d, @splat(M31.zero())));
}
fn satisfied(d: *const encoding.Definition, row: encoding.Row) !bool {
    const lang = @import("../../../air/lang/mod.zig");
    const values = try @import("../test_support.zig").evaluateArena(std.testing.allocator, &d.arena, &row);
    defer std.testing.allocator.free(values);
    for (d.arena.constraintsView()) |constraint| if (!values[lang.types.idIndex(constraint.root)].isZero()) return false;
    return true;
}
