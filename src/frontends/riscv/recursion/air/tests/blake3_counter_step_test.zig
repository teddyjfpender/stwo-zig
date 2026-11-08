const std = @import("std");
const core = @import("stwo_core");
const counter = @import("../blake3_counter_step.zig");
const M = core.fields.m31.M31;
test "BLAKE3 counter step pins checked u64 byte carries" {
    const a = std.testing.allocator;
    const digest = try counter.computeSemanticDigest(a);
    try std.testing.expectEqualSlices(u8, &counter.SEMANTIC_DIGEST, &digest);
    var d = try counter.build(a);
    defer d.deinit();
    const binding = try @import("../universal_relation_binding.zig").Binding(counter).authenticate(&d);
    const direct = try @import("../direct_constraint_program.zig").authenticate(&d.arena, counter.SEMANTIC_DIGEST, counter.LOGICAL_INPUT_COUNT);
    var exported = try @import("../framework_polynomial_export_v1.zig").exportLocalPrepared(counter, a, &direct, &binding);
    defer exported.deinit();
    const s = counter.Schedule{ .source = .{ .circuit = 1, .first_wire = 0 }, .increment = .{ .circuit = 2, .wire = 0 }, .destination = .{ .circuit = 1, .first_wire = 2 }, .uses = .{ 2, 3 } };
    const fixed = try counter.fixedRow(s);
    const cases = [_]u64{ 0, 1, 255, 65535, 16777215, 4294967295, 1099511627775, 281474976710655, 72057594037927935, 0xfffffffffffffffe, 0xffffffffffffffff };
    for (cases) |value| for ([_]u1{ 0, 1 }) |increment| {
        if (value == std.math.maxInt(u64) and increment == 1) {
            try std.testing.expectError(error.Blake3CounterExhausted, counter.logicalRow(s, value, increment));
            continue;
        }
        const row = try counter.logicalRow(s, value, increment);
        try std.testing.expectEqualSlices(M, fixed[24..], row[24..]);
        try std.testing.expect(try satisfied(&d, row));
        var reconstructed: u64 = 0;
        for (row[9..17], 0..) |byte, i| reconstructed |= @as(u64, byte.v) << @intCast(8 * i);
        try std.testing.expectEqual(value + increment, reconstructed);
        const entries = binding.preparedEntries(row);
        for (entries[0..8]) |entry| for (entry.values[0..2]) |byte| try std.testing.expect((try byte.tryIntoM31()).v <= 255);
        for (0..24) |i| {
            var changed = row;
            changed[i] = changed[i].add(M.one());
            try std.testing.expect(!try satisfied(&d, changed));
        }
    };
    // Direct addition alone is modular; byte lookups forbid this alias.
    var alias = try counter.logicalRow(s, 0, 0);
    alias[1] = M.fromCanonical(256);
    alias[9] = M.fromCanonical(256);
    try std.testing.expect(try satisfied(&d, alias));
    const alias_entries = binding.preparedEntries(alias);
    try std.testing.expect((try alias_entries[0].values[0].tryIntoM31()).v > 255);
    try std.testing.expect((try alias_entries[4].values[0].tryIntoM31()).v > 255);
    try std.testing.expect(try satisfied(&d, @splat(M.zero())));
}
fn satisfied(d: *const counter.Definition, row: counter.Row) !bool {
    const values = try @import("../test_support.zig").evaluateArena(std.testing.allocator, &d.arena, &row);
    defer std.testing.allocator.free(values);
    for (d.arena.constraintsView()) |constraint| if (!values[@import("../../../air/lang/mod.zig").types.idIndex(constraint.root)].isZero()) return false;
    return true;
}
