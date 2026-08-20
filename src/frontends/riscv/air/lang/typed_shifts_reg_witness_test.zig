const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Opcode = @import("../../isa/decode.zig").Opcode;
const support = @import("typed_shifts_reg_witness_test_support.zig");
const typed = @import("typed_shifts_reg.zig");
const witness = @import("typed_shifts_reg_witness.zig");

const operations = [_]Opcode{ .SLL, .SRL, .SRA };

test "typed SHIFTS_REG binding is complete source-independent and retained" {
    var generated = try typed.build(std.testing.allocator, .generated);
    var moved = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "moved/shifts_reg.air",
        .start = .{ .byte_offset = 12, .line = 3, .column = 1 },
        .end = .{ .byte_offset = 28, .line = 3, .column = 17 },
    } });
    defer moved.deinit();
    var binding = try witness.WitnessBinding.canonical(&generated);
    const executor = try witness.Executor.init(&generated, &binding);
    const moved_binding = try witness.WitnessBinding.canonical(&moved);
    const moved_executor = try witness.Executor.init(&moved, &moved_binding);
    try std.testing.expectEqual(witness.WITNESS_BINDING_DIGEST, binding.identityDigest());
    try std.testing.expectEqual(executor.identityDigest(), moved_executor.identityDigest());
    try std.testing.expect(std.meta.eql(binding, executor.identitySnapshot()));
    for (binding.slots, witness.CANONICAL_RECIPE, 0..) |slot, recipe, column| {
        try std.testing.expectEqual(column, slot.column);
        try std.testing.expectEqual(column, @intFromEnum(slot.value));
        try std.testing.expectEqual(recipe, slot.source);
    }
    for (binding.operations, witness.CANONICAL_OPERATIONS) |actual, expected|
        try std.testing.expectEqualDeep(expected, actual);

    binding.operations[0].opcode_id = 99;
    generated.deinit();
    var storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    const rows = [_]witness.TraceRow{support.makeRow(
        .SRA,
        3,
        3,
        3,
        0x9234_5678,
        0,
        10,
        0x1000,
        0,
        0,
        0,
        0,
    )};
    try executor.generateMainInto(&columns, &rows, 0);
    try support.expectLegacyColumns(&rows, 0, &columns);
}

test "typed SHIFTS_REG is exact for every opcode amount and register alias boundary" {
    const Case = struct {
        rd: u5,
        rs1: u5,
        rs2: u5,
        value: u32,
        raw_amount: u32,
    };
    const cases = [_]Case{
        .{ .rd = 0, .rs1 = 0, .rs2 = 0, .value = 0, .raw_amount = 0 },
        .{ .rd = 7, .rs1 = 7, .rs2 = 9, .value = 0xffff_ffff, .raw_amount = 1 },
        .{ .rd = 5, .rs1 = 5, .rs2 = 9, .value = 0x8000_0001, .raw_amount = 0xffff_ffe7 },
        .{ .rd = 9, .rs1 = 5, .rs2 = 9, .value = 0x7fff_ffff, .raw_amount = 0x100 },
        .{ .rd = 31, .rs1 = 3, .rs2 = 4, .value = 0x0102_0304, .raw_amount = 47 },
        .{ .rd = 1, .rs1 = 2, .rs2 = 3, .value = 0xffff_00ff, .raw_amount = 0xffff_fff0 },
        .{ .rd = 11, .rs1 = 12, .rs2 = 13, .value = 0x8080_8080, .raw_amount = 55 },
        .{ .rd = 13, .rs1 = 14, .rs2 = 15, .value = 0x1020_4080, .raw_amount = 88 },
        .{ .rd = 15, .rs1 = 16, .rs2 = 17, .value = 0x8000_0000, .raw_amount = 0xffff_ffff },
        .{ .rd = 18, .rs1 = 19, .rs2 = 19, .value = 0x1234_5678, .raw_amount = 0 },
    };
    var rows: [operations.len * cases.len]witness.TraceRow = undefined;
    var count: usize = 0;
    for (operations) |opcode| for (cases) |case| {
        rows[count] = support.makeRow(
            opcode,
            case.rd,
            case.rs1,
            case.rs2,
            case.value,
            case.raw_amount,
            @intCast(count + 100),
            @intCast(0x2000 + count * 4),
            0x1020_3040 +% @as(u32, @intCast(count)),
            @intCast(count),
            @intCast(count + 1),
            @intCast(count + 2),
        );
        count += 1;
    };

    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var actual = try support.OwnedColumns.init(std.testing.allocator, 32, M31.zero());
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, &rows, 5);
    try support.expectLegacyColumns(&rows, 5, &actual.views);
    for (rows, 0..) |row, index| try support.expectRelationParity(
        &executor,
        &actual.views,
        index,
        row,
    );
}

test "typed SHIFTS_REG matches legacy and relation authority on seeded corpus" {
    var prng = std.Random.DefaultPrng.init(0x4530_3134_2d53_5247);
    const random = prng.random();
    var rows: [256]witness.TraceRow = undefined;
    for (&rows, 0..) |*row, index| row.* = support.makeRow(
        operations[random.uintLessThan(usize, operations.len)],
        random.int(u5),
        random.int(u5),
        random.int(u5),
        random.int(u32),
        random.int(u32),
        @intCast(index + 1000),
        @intCast(0x4000 + index * 4),
        random.int(u32),
        random.uintLessThan(u32, 100),
        random.uintLessThan(u32, 100),
        random.uintLessThan(u32, 100),
    );
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var actual = try support.OwnedColumns.init(std.testing.allocator, rows.len, M31.zero());
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, &rows, 8);
    try support.expectLegacyColumns(&rows, 8, &actual.views);
    for (rows, 0..) |row, index| try support.expectRelationParity(
        &executor,
        &actual.views,
        index,
        row,
    );
}

test "typed SHIFTS_REG exhausts low-five amounts and all byte quotient classes" {
    var rows: [operations.len * 32 * 8]witness.TraceRow = undefined;
    var count: usize = 0;
    for (operations) |opcode| for (0..8) |quotient| for (0..32) |amount| {
        const value: u32 = switch (amount & 3) {
            0 => 0,
            1 => 0x7fff_ffff,
            2 => 0x8000_0000,
            else => 0xffff_ffff,
        };
        const raw_amount: u32 = @intCast(quotient * 32 + amount);
        rows[count] = support.makeRow(
            opcode,
            10,
            5,
            6,
            value,
            raw_amount,
            @intCast(count + 100),
            @intCast(0xc000 + count * 4),
            @truncate(0x5566_7788 +% count),
            @intCast(count % 32),
            @intCast((count + 1) % 32),
            @intCast((count + 2) % 32),
        );
        count += 1;
    };

    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var actual = try support.OwnedColumns.init(std.testing.allocator, 1024, M31.zero());
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, &rows, 10);
    try support.expectLegacyColumns(&rows, 10, &actual.views);
    for (rows, 0..) |row, index| try support.expectRelationParity(
        &executor,
        &actual.views,
        index,
        row,
    );
}

test "typed SHIFTS_REG preserves guards and zeroes final padding" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const guard = M31.fromCanonical(0x3c3c);
    const interior = M31.fromCanonical(0x4d4d);
    var storage: [witness.MAIN_COLUMN_COUNT][10]M31 = undefined;
    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| {
        @memset(owned, guard);
        @memset(owned[1..9], interior);
        view.* = owned[1..9];
    }
    const rows = [_]witness.TraceRow{
        support.makeRow(.SLL, 0, 0, 0, 0, 0, 10, 0x1000, 0, 0, 0, 0),
        support.makeRow(.SRL, 7, 7, 8, 0xffff_ffff, 31, 11, 0x1004, 0, 0, 0, 0),
        support.makeRow(.SRA, 9, 5, 9, 0x8000_0000, 8, 12, 0x1008, 0, 0, 0, 0),
        support.makeRow(.SLL, 1, 2, 3, 0x0102_0304, 7, 13, 0x100c, 8, 0, 0, 0),
    };
    try executor.generateMainInto(&columns, &rows, 3);
    try support.expectLegacyColumns(&rows, 3, &columns);
    for (storage, columns) |owned, column| {
        try std.testing.expectEqual(guard, owned[0]);
        try std.testing.expectEqual(guard, owned[9]);
        for (column[rows.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}
