const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Opcode = @import("../../isa/decode.zig").Opcode;
const support = @import("typed_shifts_imm_witness_test_support.zig");
const typed = @import("typed_shifts_imm.zig");
const witness = @import("typed_shifts_imm_witness.zig");

const operations = [_]Opcode{ .SLLI, .SRLI, .SRAI };

test "typed SHIFTS_IMM binding is complete source-independent and retained" {
    var generated = try typed.build(std.testing.allocator, .generated);
    var moved = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "moved/shifts_imm.air",
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
        .SRAI,
        3,
        3,
        0x9234_5678,
        31,
        10,
        0x1000,
        0,
        0,
        0,
    )};
    try executor.generateMainInto(&columns, &rows, 0);
    try support.expectLegacyColumns(&rows, 0, &columns);
}

test "typed SHIFTS_IMM is exact for every opcode amount and register alias boundary" {
    const Case = struct {
        rd: u5,
        rs1: u5,
        value: u32,
        amount: u5,
    };
    const cases = [_]Case{
        .{ .rd = 0, .rs1 = 0, .value = 0, .amount = 0 },
        .{ .rd = 7, .rs1 = 7, .value = 0xffff_ffff, .amount = 1 },
        .{ .rd = 5, .rs1 = 5, .value = 0x8000_0001, .amount = 7 },
        .{ .rd = 9, .rs1 = 5, .value = 0x7fff_ffff, .amount = 8 },
        .{ .rd = 31, .rs1 = 3, .value = 0x0102_0304, .amount = 15 },
        .{ .rd = 1, .rs1 = 2, .value = 0xffff_00ff, .amount = 16 },
        .{ .rd = 11, .rs1 = 12, .value = 0x8080_8080, .amount = 23 },
        .{ .rd = 13, .rs1 = 14, .value = 0x1020_4080, .amount = 24 },
        .{ .rd = 15, .rs1 = 16, .value = 0x8000_0000, .amount = 31 },
    };
    var rows: [operations.len * cases.len]witness.TraceRow = undefined;
    var count: usize = 0;
    for (operations) |opcode| for (cases) |case| {
        rows[count] = support.makeRow(
            opcode,
            case.rd,
            case.rs1,
            case.value,
            case.amount,
            @intCast(count + 100),
            @intCast(0x2000 + count * 4),
            0x1020_3040 +% @as(u32, @intCast(count)),
            @intCast(count),
            @intCast(count + 1),
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

test "typed SHIFTS_IMM matches legacy and relation authority on seeded corpus" {
    var prng = std.Random.DefaultPrng.init(0x4530_3134_2d53_494d);
    const random = prng.random();
    var rows: [256]witness.TraceRow = undefined;
    for (&rows, 0..) |*row, index| row.* = support.makeRow(
        operations[random.uintLessThan(usize, operations.len)],
        random.int(u5),
        random.int(u5),
        random.int(u32),
        random.int(u5),
        @intCast(index + 1000),
        @intCast(0x4000 + index * 4),
        random.int(u32),
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

test "typed SHIFTS_IMM exhausts every amount direction and sign boundary" {
    const values = [_]u32{
        0,
        1,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x0102_0304,
    };
    var rows: [operations.len * 32 * values.len]witness.TraceRow = undefined;
    var count: usize = 0;
    for (operations) |opcode| for (0..32) |amount| for (values) |value| {
        rows[count] = support.makeRow(
            opcode,
            @intCast(1 + (count % 30)),
            @intCast(1 + ((count * 7 + 3) % 30)),
            value,
            @intCast(amount),
            @intCast(count + 100),
            @intCast(0x8000 + count * 4),
            @truncate(0x1122_3344 +% count),
            @intCast(count % 32),
            @intCast((count + 1) % 32),
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

test "typed SHIFTS_IMM preserves guards and zeroes final padding" {
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
        support.makeRow(.SLLI, 0, 0, 0, 0, 10, 0x1000, 0, 0, 0),
        support.makeRow(.SRLI, 7, 7, 0xffff_ffff, 31, 11, 0x1004, 0, 0, 0),
        support.makeRow(.SRAI, 9, 5, 0x8000_0000, 8, 12, 0x1008, 0, 0, 0),
        support.makeRow(.SLLI, 1, 2, 0x0102_0304, 7, 13, 0x100c, 8, 0, 0),
    };
    try executor.generateMainInto(&columns, &rows, 3);
    try support.expectLegacyColumns(&rows, 3, &columns);
    for (storage, columns) |owned, column| {
        try std.testing.expectEqual(guard, owned[0]);
        try std.testing.expectEqual(guard, owned[9]);
        for (column[rows.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}
