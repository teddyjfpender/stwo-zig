const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const support = @import("typed_addi_witness_test_support.zig");
const typed_addi = @import("typed_addi.zig");
const witness = @import("typed_addi_witness.zig");

test "typed ADDI witness binding is exact source-independent and self-contained" {
    var generated = try typed_addi.build(std.testing.allocator, .generated);
    var generated_owned = true;
    defer if (generated_owned) generated.deinit();
    var moved = try typed_addi.build(std.testing.allocator, .{ .file = .{
        .path = "moved/addi.air",
        .start = .{ .byte_offset = 91, .line = 11, .column = 3 },
        .end = .{ .byte_offset = 95, .line = 11, .column = 7 },
    } });
    defer moved.deinit();

    var binding = try witness.WitnessBinding.canonical(&generated);
    const digest = binding.identityDigest();
    try std.testing.expectEqual(witness.WITNESS_BINDING_DIGEST, digest);
    const executor = try witness.Executor.init(&generated, &binding);
    const moved_binding = try witness.WitnessBinding.canonical(&moved);
    const moved_executor = try witness.Executor.init(&moved, &moved_binding);
    try std.testing.expectEqual(executor.identityDigest(), moved_executor.identityDigest());
    try std.testing.expect(std.meta.eql(binding, executor.identitySnapshot()));
    for (binding.slots, witness.CANONICAL_RECIPE, 0..) |slot, source, column| {
        try std.testing.expectEqual(column, slot.column);
        try std.testing.expectEqual(column, @intFromEnum(slot.value));
        try std.testing.expectEqual(source, slot.source);
    }
    for (binding.events, 0..) |event, index| {
        try std.testing.expectEqual(index, @intFromEnum(event.effect));
        for (event.values[event.arity..]) |unused|
            try std.testing.expectEqual(std.math.maxInt(u32), @intFromEnum(unused));
    }

    // The executor owns fixed-size identity, not this binding or its arena.
    binding.arithmetic.result_limb_count = 3;
    generated.deinit();
    generated_owned = false;
    const row = support.makeRow(7, 5, 0xff, 1, 8, 0x1040, 9, 7, 11);
    var storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    try executor.generateMainInto(&columns, &.{row}, 0);
    try std.testing.expectEqual(M31.one(), columns[25][0]);
    try std.testing.expect(columns[29][0].isZero());
    try std.testing.expectEqual(M31.one(), columns[30][0]);
    _ = try executor.generateRelationRow(row);
}

test "typed ADDI witness is all-column exact at x0 alias signed and carry boundaries" {
    const rows = [_]witness.TraceRow{
        support.makeRow(0, 0, 0, 0, 1, 0x1000, 0, 0, 0),
        support.makeRow(0, 7, 0x1234_5678, -2048, 2, 0x1004, 0, 0, 0),
        support.makeRow(7, 7, 41, 1, 3, 0x1008, 0, 0, 0),
        support.makeRow(31, 31, 0xffff_ffff, 1, 4, 0x100c, 0, 0, 0),
        support.makeRow(3, 5, 0, -2048, 5, 0x1010, 0xabcd, 0, 0),
        support.makeRow(3, 5, 0, 2047, 6, 0x1014, 0xabcd, 0, 0),
        support.makeRow(9, 4, 0x0000_00ff, 1, 7, 0x1018, 1, 0, 0),
        support.makeRow(9, 4, 0x0000_ffff, 1, 8, 0x101c, 2, 0, 0),
        support.makeRow(9, 4, 0x00ff_ffff, 1, 9, 0x1020, 3, 0, 0),
        support.makeRow(9, 4, 0xffff_ffff, 1, 10, 0x1024, 4, 0, 0),
        support.makeRow(9, 4, 0x8000_0000, -1, 11, 0x1028, 5, 0, 0),
        support.makeRow(9, 4, 0x7fff_ffff, 1, 12, 0x102c, 6, 0, 0),
    };
    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    const sentinel = M31.fromCanonical(0x5151);
    var actual = try support.OwnedColumns.init(std.testing.allocator, 16, sentinel);
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, &rows, 4);
    try support.expectProductionColumns(&rows, 4, &actual.views);
    for (rows, 0..) |row, index|
        try support.expectRelationParity(&executor, &actual.views, index, row);
    for (actual.views) |column| {
        for (column[rows.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}

test "typed ADDI witness is exact for a deterministic broad corpus" {
    var prng = std.Random.DefaultPrng.init(0x4530_3037_2d41_4444);
    const random = prng.random();
    var rows: [512]witness.TraceRow = undefined;
    for (&rows, 0..) |*row, index| {
        const clock: u32 = @intCast(index + 1);
        const rd = random.int(u5);
        const rs1 = if (index % 7 == 0) rd else random.int(u5);
        const immediate = random.intRangeAtMost(i32, -2048, 2047);
        row.* = support.makeRow(
            rd,
            rs1,
            random.int(u32),
            immediate,
            clock,
            @as(u32, 0x4000) +% @as(u32, @intCast(index * 4)),
            random.int(u32),
            0,
            0,
        );
    }

    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    var actual = try support.OwnedColumns.init(
        std.testing.allocator,
        512,
        M31.fromCanonical(0x6262),
    );
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, &rows, 9);
    try support.expectProductionColumns(&rows, 9, &actual.views);
    for (0..64) |sample| {
        const index = (sample * 73) % rows.len;
        try support.expectRelationParity(&executor, &actual.views, index, rows[index]);
    }
}

test "typed ADDI witness preserves exterior guards and zeroes only final padding" {
    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    const guard = M31.fromCanonical(0x3c3c);
    const interior = M31.fromCanonical(0x4d4d);
    var guarded: [witness.MAIN_COLUMN_COUNT][10]M31 = undefined;
    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&guarded, &columns) |*storage, *column| {
        @memset(storage, guard);
        @memset(storage[1..9], interior);
        column.* = storage[1..9];
    }
    const rows = [_]witness.TraceRow{
        support.makeRow(0, 0, 0, 0, 1, 0x1000, 0, 0, 0),
        support.makeRow(1, 2, 0xdead_beef, -1, 2, 0x1004, 7, 0, 0),
        support.makeRow(31, 31, 0x0123_4567, 2047, 3, 0x1008, 0, 0, 0),
    };
    try executor.generateMainInto(&columns, &rows, 3);
    try support.expectProductionColumns(&rows, 3, &columns);
    for (guarded, columns) |storage, column| {
        try std.testing.expectEqual(guard, storage[0]);
        try std.testing.expectEqual(guard, storage[9]);
        for (column[rows.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}
