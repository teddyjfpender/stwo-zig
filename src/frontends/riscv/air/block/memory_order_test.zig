const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const order = @import("memory_order.zig");
const support = @import("../../recursion/air/test_support.zig");
const lang = @import("../lang/definition.zig");
const tables = @import("../lookups/tables/schema.zig");
fn satisfied(definition: *const order.Definition, row: *const order.Row) !bool {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, row);
    defer std.testing.allocator.free(values);
    for (definition.arena.constraintsView()) |constraint| if (!values[lang.types.idIndex(constraint.root)].isZero()) return false;
    for (definition.arena.effectsView(), 0..) |effect, i| {
        if (values[lang.types.idIndex(effect.liveness.?)].isZero()) continue;
        const ids = definition.arena.effectValues(@enumFromInt(i)).?;
        const tuple = [2]M{ values[lang.types.idIndex(ids[0])], values[lang.types.idIndex(ids[1])] };
        _ = tables.indexBase(.range_check_8_8, &tuple) catch return false;
    }
    return true;
}
test "block memory ordering proves wide clocks values and address transitions" {
    var definition = try order.build(std.testing.allocator);
    defer definition.deinit();
    const clocks = [_]u64{ 0, 1, 255, 256, 65535, 65536, (1 << 31) - 1, 1 << 32, 1 << 48, std.math.maxInt(u64) - 1, std.math.maxInt(u64) };
    for (clocks, 0..) |first, i| for (clocks[i + 1 ..]) |second| {
        const row = try order.witness(.{ .space = 1, .address = 4096, .clock = first, .value = 0xfedcba98 }, .{ .space = 1, .address = 4096, .clock = second, .value = 0xfedcba98 });
        try std.testing.expect(try satisfied(&definition, &row));
    };
    // Address order dominates clocks. Register and RW address spaces cannot alias.
    const changed = try order.witness(.{ .space = 0, .address = std.math.maxInt(u32), .clock = std.math.maxInt(u64), .value = 9 }, .{ .space = 1, .address = 0, .clock = 0, .value = 17 });
    try std.testing.expect(try satisfied(&definition, &changed));
    const padding: order.Row = @splat(M.zero());
    try std.testing.expect(try satisfied(&definition, &padding));
    const digest = try lang.digest.computeIdentity(&definition.arena);
    std.debug.print("BLOCK_MEMORY_ORDER identity={x} constraints={d} range_events={d}\n", .{ digest.bytes, definition.arena.constraintsView().len, definition.arena.effectsView().len });
}
test "block memory ordering rejects value bypass clocks carries and unbounded bytes" {
    var definition = try order.build(std.testing.allocator);
    defer definition.deinit();
    const previous = order.Point{ .space = 1, .address = 4096, .clock = 255, .value = 0x12345678 };
    var current = order.Point{ .space = 1, .address = 4096, .clock = 256, .value = 0x12345678 };
    const honest = try order.witness(previous, current);
    const l = order.Layout;
    for ([_]usize{ l.same, l.previous_key, l.current_key, l.previous_clock, l.current_clock, l.previous_value, l.current_value, l.clock_gap, l.clock_carry, l.clock_carry + 7 }) |index| {
        var bad = honest;
        bad[index] = bad[index].add(M.one());
        try std.testing.expect(!try satisfied(&definition, &bad));
    }
    var bypass = honest;
    bypass[l.same] = M.zero();
    bypass[l.current_value] = M.zero();
    try std.testing.expect(!try satisfied(&definition, &bypass));
    // Compensating field equations do not make a non-byte into a valid limb.
    var nonbyte = honest;
    nonbyte[l.previous_value] = M.fromCanonical(256);
    nonbyte[l.current_value] = M.fromCanonical(256);
    try std.testing.expect(!try satisfied(&definition, &nonbyte));
    current.clock = previous.clock;
    try std.testing.expectError(error.MemoryClockOrder, order.witness(previous, current));
    current.clock = 1;
    try std.testing.expectError(error.MemoryClockOrder, order.witness(previous, current));
    current.clock = 256;
    current.value ^= 1;
    try std.testing.expectError(error.MemoryValueDiscontinuity, order.witness(previous, current));
    current.address = 4095;
    try std.testing.expectError(error.MemoryAddressOrder, order.witness(previous, current));
}

test "block memory ordering rejects 64-bit wrap even with consistent lower limbs" {
    var definition = try order.build(std.testing.allocator);
    defer definition.deinit();
    const l = order.Layout;
    var row = try order.witness(.{ .space = 1, .address = 0, .clock = 0, .value = 0 }, .{ .space = 1, .address = 0, .clock = 1, .value = 0 });
    // UINT64_MAX + 0 + 1 = 0 modulo 2^64. Every byte equation holds,
    // but the final carry must reject this fabricated increasing transition.
    for (row[l.previous_clock..][0..8]) |*value| value.* = M.fromCanonical(255);
    for (row[l.current_clock..][0..8]) |*value| value.* = M.zero();
    for (row[l.clock_carry..][0..8]) |*value| value.* = M.one();
    try std.testing.expect(!try satisfied(&definition, &row));
    row[l.clock_carry + 7] = M.zero();
    try std.testing.expect(!try satisfied(&definition, &row));
}
