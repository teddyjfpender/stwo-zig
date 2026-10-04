const std = @import("std");
const core = @import("stwo_core");
const mask = @import("../blake3_query_mask.zig");
const binding = @import("../universal_relation_binding.zig");
const schema = @import("../../../air/lookups/tables/schema.zig");
test "BLAKE3 raw query masking pins semantics and preserves native u32 boundaries" {
    const a = std.testing.allocator;
    const digest = try mask.computeSemanticDigest(a);
    if (!std.mem.eql(u8, &digest, &mask.SEMANTIC_DIGEST)) std.debug.print("QUERY_MASK_DIGEST={x}\n", .{digest});
    try std.testing.expectEqualSlices(u8, &mask.SEMANTIC_DIGEST, &digest);
    var d = try mask.build(a);
    defer d.deinit();
    const plan = try binding.Binding(mask).authenticate(&d);
    const direct = try @import("../direct_constraint_program.zig").authenticate(&d.arena, mask.SEMANTIC_DIGEST, mask.LOGICAL_INPUT_COUNT);
    var exported = try @import("../framework_polynomial_export_v1.zig").exportLocalPrepared(mask, a, &direct, &plan);
    defer exported.deinit();
    const words = [_]u32{ 0, 1, 0x7ffffffe, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff, 0x12345678 };
    for (0..32) |log| for (words) |word| {
        const schedule = mask.Schedule{ .source_circuit = 1, .source_wire = 30, .destination_circuit = 2, .destination_wire = 50, .uses = 1, .log_domain_size = @intCast(log) };
        const row = try mask.logicalRow(schedule, word);
        const expected = word & ((@as(u32, 1) << @as(u5, @intCast(log))) - 1);
        var actual: u32 = 0;
        for (row[4..8], 0..) |byte, i| actual |= byte.toU32() << @as(u5, @intCast(i * 8));
        try std.testing.expectEqual(expected, actual);
        const entries = plan.preparedEntries(row);
        for (entries[0..4]) |entry| _ = try schema.indexSecure(.bitwise, entry.values[0..4]);
        for (0..4) |i| {
            var changed = row;
            changed[4 + i] = changed[4 + i].add(core.fields.m31.M31.one());
            const bad = plan.preparedEntries(changed);
            try std.testing.expectError(if (row[4 + i].toU32() == 255) error.ValueOutOfRange else error.InvalidTuple, schema.indexSecure(.bitwise, bad[i].values[0..4]));
        }
    };
    var schedule = mask.Schedule{ .source_circuit = 1, .source_wire = 30, .destination_circuit = 2, .destination_wire = 50, .uses = 1, .log_domain_size = 32 };
    try std.testing.expectError(error.InvalidBlake3QueryMask, mask.fixedRow(schedule));
    const full = try mask.logicalLowBitsRow(schedule, 0xffffffff);
    for (full[4..8]) |byte| try std.testing.expectEqual(@as(u32, 255), byte.toU32());
    const full_entries = plan.preparedEntries(full);
    for (full_entries[0..4]) |entry| _ = try schema.indexSecure(.bitwise, entry.values[0..4]);
    const zero = try mask.logicalLowBitsRow(schedule, 0);
    for (zero[4..8]) |byte| try std.testing.expect(byte.isZero());
    schedule.log_domain_size = 33;
    try std.testing.expectError(error.InvalidBlake3QueryMask, mask.fixedLowBitsRow(schedule));
    schedule.log_domain_size = 31;
    schedule.destination_circuit = 1;
    try std.testing.expectError(error.InvalidBlake3QueryMask, mask.fixedRow(schedule));
}
