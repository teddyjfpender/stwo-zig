const std = @import("std");
const air = @import("blake3_memory_boundary.zig");
test "BLAKE3 Span memory boundary pins exact word clock and word source" {
    const a = std.testing.allocator;
    const digest = try air.computeSemanticDigest(a);
    if (!std.mem.eql(u8, &digest, &air.SEMANTIC_DIGEST)) std.debug.print("MEMORY_BOUNDARY_DIGEST={s}\n", .{std.fmt.bytesToHex(digest, .lower)});
    var d = try air.build(a);
    defer d.deinit();
    const Binder = @import("universal_relation_binding.zig").Binding(air);
    const runtime = @import("relation_interaction.zig");
    try std.testing.expectError(error.InvalidInputGeometry, runtime.Runtime(11, 4, 2).authenticate(&d.arena, air.SEMANTIC_DIGEST, d.events));
    try std.testing.expectError(error.InvalidInputGeometry, runtime.RuntimeWithFixedAddresses(11, 4, 2, 6, &.{5}).authenticate(&d.arena, air.SEMANTIC_DIGEST, d.events));
    try std.testing.expectError(error.InvalidInputGeometry, runtime.RuntimeWithFixedAddresses(11, 4, 2, 4, &.{ 5, 5 }).authenticate(&d.arena, air.SEMANTIC_DIGEST, d.events));
    const binding = try Binder.authenticate(&d);
    try binding.validateAgainst(&d.arena, air.SEMANTIC_DIGEST, d.events);
    var invalid = air.Schedule{ .address = 1 << 30, .clock = 123, .direction = .initial, .circuit = 99, .first_wire = 8, .uses = 1 };
    try std.testing.expectError(error.InvalidMemoryBoundarySchedule, air.fixedRow(invalid));
    invalid.address = 13;
    try std.testing.expectError(error.InvalidMemoryBoundarySchedule, air.fixedRow(invalid));
    const M = @import("stwo_core").fields.m31.M31;
    for ([_]air.Direction{ .initial, .final }) |direction| {
        const row = try air.logicalRow(.{ .address = 12, .clock = 123, .direction = direction, .circuit = 99, .first_wire = 8, .uses = 1 }, .{ 0, 127, 128, 255 });
        const entries = binding.preparedEntries(row);
        const legacy = @import("../../air/memory_commitment/boundary.zig").Row{ .addr = 12, .clock = 123, .value = .{ 0, 127, 128, 255 }, .multiplicity = if (direction == .initial) M.one() else M.one().neg(), .root = 0 };
        for (entries[0].values[0..7], legacy.memoryTuple()) |actual, expected| try std.testing.expectEqual(expected, try actual.tryIntoM31());
        try std.testing.expectEqual(legacy.multiplicity, try entries[0].numerator.tryIntoM31());
        const entry = entries[3];
        try std.testing.expectEqual(@as(u32, 8), (try entry.values[1].tryIntoM31()).toU32());
        for (entry.values[2..6], row[0..4]) |coordinate, byte| try std.testing.expectEqual(byte, try coordinate.tryIntoM31());
    }
}
