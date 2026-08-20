const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Opcode = @import("../../isa/decode.zig").Opcode;
const support = @import("typed_base_alu_reg_witness_test_support.zig");
const typed = @import("typed_base_alu_reg.zig");
const witness = @import("typed_base_alu_reg_witness.zig");

const operations = [_]Opcode{ .ADD, .SUB, .XOR, .OR, .AND };

test "typed BASE_ALU_REG binding is complete source-independent and retained" {
    var generated = try typed.build(std.testing.allocator, .generated);
    var moved = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "moved/base_alu_reg.air",
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
        .XOR,
        3,
        3,
        3,
        0x1234_5678,
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

test "typed BASE_ALU_REG is exact for every opcode and register alias boundary" {
    const Case = struct {
        rd: u5,
        rs1: u5,
        rs2: u5,
        lhs: u32,
        rhs: u32,
    };
    const cases = [_]Case{
        .{ .rd = 0, .rs1 = 0, .rs2 = 0, .lhs = 0, .rhs = 0 },
        .{ .rd = 7, .rs1 = 7, .rs2 = 7, .lhs = 0xffff_ffff, .rhs = 0 },
        .{ .rd = 5, .rs1 = 5, .rs2 = 9, .lhs = 0x7fff_ffff, .rhs = 1 },
        .{ .rd = 9, .rs1 = 5, .rs2 = 9, .lhs = 0x8000_0000, .rhs = 0xffff_ffff },
        .{ .rd = 31, .rs1 = 3, .rs2 = 3, .lhs = 0x0102_0304, .rhs = 0 },
        .{ .rd = 1, .rs1 = 2, .rs2 = 3, .lhs = 0xffff_00ff, .rhs = 0x00ff_ffff },
    };
    var rows: [operations.len * cases.len]witness.TraceRow = undefined;
    var count: usize = 0;
    for (operations) |opcode| for (cases) |case| {
        rows[count] = support.makeRow(
            opcode,
            case.rd,
            case.rs1,
            case.rs2,
            case.lhs,
            case.rhs,
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

test "typed BASE_ALU_REG matches legacy and relation authority on seeded corpus" {
    var prng = std.Random.DefaultPrng.init(0x4530_3134_2d52_4547);
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

test "typed BASE_ALU_REG preserves guards and zeroes final padding" {
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
        support.makeRow(.ADD, 0, 0, 0, 0, 0, 10, 0x1000, 0, 0, 0, 0),
        support.makeRow(.SUB, 7, 7, 7, 1, 0, 11, 0x1004, 0, 0, 0, 0),
        support.makeRow(.XOR, 9, 5, 9, 0x8000_0000, 1, 12, 0x1008, 0, 0, 0, 0),
        support.makeRow(.AND, 1, 2, 3, 0xffff_ffff, 0, 13, 0x100c, 8, 0, 0, 0),
    };
    try executor.generateMainInto(&columns, &rows, 3);
    try support.expectLegacyColumns(&rows, 3, &columns);
    for (storage, columns) |owned, column| {
        try std.testing.expectEqual(guard, owned[0]);
        try std.testing.expectEqual(guard, owned[9]);
        for (column[rows.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}
