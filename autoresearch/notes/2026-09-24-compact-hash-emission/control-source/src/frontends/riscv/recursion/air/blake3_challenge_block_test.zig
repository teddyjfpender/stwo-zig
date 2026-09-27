const std = @import("std");
const core = @import("stwo_core");
const block = @import("blake3_challenge_block.zig");
const binding = @import("universal_relation_binding.zig");
const lang = @import("../../air/lang/mod.zig");
const M31 = core.fields.m31.M31;
const schedule = block.Schedule{ .source_circuit = 17, .source_first = 100, .destination_circuit = 19, .destination_first = 200, .uses = .{ 1, 1, 1, 1, 0, 0, 0, 0 }, .status_wire = 220, .status_uses = 1 };
test "BLAKE3 challenge block pins typed reduction rejection and framework export" {
    const a = std.testing.allocator;
    const digest = try block.computeSemanticDigest(a);
    if (!std.mem.eql(u8, &digest, &block.SEMANTIC_DIGEST)) std.debug.print("CHALLENGE_DIGEST={x}\n", .{digest});
    try std.testing.expectEqualSlices(u8, &block.SEMANTIC_DIGEST, &digest);
    var d = try block.build(a);
    defer d.deinit();
    const plan = try binding.Binding(block).authenticate(&d);
    const direct = try @import("direct_constraint_program.zig").authenticate(&d.arena, block.SEMANTIC_DIGEST, block.LOGICAL_INPUT_COUNT);
    var exported = try @import("framework_polynomial_export_v1.zig").exportLocalPrepared(block, a, &direct, &plan);
    defer exported.deinit();
    var degrees = try lang.degree.analyze(a, &d.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(u32, 2), degrees.maximumConstraintDegree());
    try std.testing.expect(try satisfied(&d, @splat(M31.zero())));
}
test "BLAKE3 challenge block matches native boundaries and rejects unused half" {
    const a = std.testing.allocator;
    var d = try block.build(a);
    defer d.deinit();
    const plan = try binding.Binding(block).authenticate(&d);
    const p = core.fields.m31.Modulus;
    const cases = [_]u32{ 0, 1, p - 1, p, p + 1, 2 * p - 2, 2 * p - 1, 2 * p, 0xffffffff };
    for (cases) |word| for (0..8) |position| {
        var words: [8]u32 = @splat(17);
        words[position] = word;
        const row = try block.logicalRow(schedule, words);
        try std.testing.expect(try satisfied(&d, row));
        const accepted = core.channel.blake3.sampleWord(word) != null;
        try std.testing.expectEqual(accepted, row[70].eql(M31.one()));
        for (words, 0..) |value, i| try std.testing.expect(row[i * 8 + 7].eql(core.channel.blake3.sampleWord(value) orelse M31.zero()));
        const entries = plan.preparedEntries(row);
        for (0..8) |i| {
            try std.testing.expect((try entries[4 * i + 3].numerator.tryIntoM31()).eql(if (accepted) M31.fromCanonical(schedule.uses[i]) else M31.zero()));
            inline for (.{ @as(usize, 1), 2 }) |offset| _ = try @import("../../air/lookups/tables/schema.zig").indexSecure(.range_check_8_8, entries[4 * i + offset].values[0..2]);
        }
    };
    // Fixed preprocessing must not depend on draw bytes or rejection outcome.
    const fixed = try block.fixedRow(schedule);
    const rejected = try block.logicalRow(schedule, @splat(0xffffffff));
    try std.testing.expectEqualSlices(M31, fixed[71..], rejected[71..]);
    var invalid_byte = try block.logicalRow(schedule, @splat(17));
    invalid_byte[0] = M31.fromCanonical(256);
    const invalid_entries = plan.preparedEntries(invalid_byte);
    if (@import("../../air/lookups/tables/schema.zig").indexSecure(.range_check_8_8, invalid_entries[1].values[0..2])) |_| {
        return error.AcceptedOutOfRangeByte;
    } else |_| {}
    var random = std.Random.DefaultPrng.init(0x42334348);
    for (0..64) |_| {
        var words: [8]u32 = undefined;
        for (&words) |*word| word.* = random.random().int(u32);
        const row = try block.logicalRow(schedule, words);
        try std.testing.expect(try satisfied(&d, row));
    }
}
test "BLAKE3 challenge block rejects validity reduction and acceptance mutations" {
    var d = try block.build(std.testing.allocator);
    defer d.deinit();
    const row = try block.logicalRow(schedule, .{ 0, 2147483646, 2147483647, 2147483648, 4294967292, 4294967293, 123, 456 });
    for (0..8) |i| for ([_]usize{ 4, 5, 6, 7 }) |coordinate| {
        var changed = row;
        changed[i * 8 + coordinate] = changed[i * 8 + coordinate].add(M31.one());
        try std.testing.expect(!try satisfied(&d, changed));
    };
    for ([_]u32{ 0xfffffffe, 0xffffffff }) |word| for (0..8) |position| {
        var words: [8]u32 = @splat(17);
        words[position] = word;
        const rejected = try block.logicalRow(schedule, words);
        for ([_]usize{ position * 8 + 6, position * 8 + 7, 70 }) |coordinate| {
            var changed = rejected;
            changed[coordinate] = M31.one();
            try std.testing.expect(!try satisfied(&d, changed));
        }
    };
    for (64..71) |i| {
        var changed = row;
        changed[i] = changed[i].add(M31.one());
        try std.testing.expect(!try satisfied(&d, changed));
    }
}
fn satisfied(d: *const block.Definition, row: block.Row) !bool {
    const a = std.testing.allocator;
    const values = try @import("test_support.zig").evaluateArena(a, &d.arena, &row);
    defer a.free(values);
    for (d.arena.constraintsView()) |constraint| if (!values[lang.types.idIndex(constraint.root)].isZero()) return false;
    return true;
}
