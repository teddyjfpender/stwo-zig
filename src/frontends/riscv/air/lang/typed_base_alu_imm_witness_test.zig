const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Opcode = @import("../../isa/decode.zig").Opcode;
const support = @import("typed_base_alu_imm_witness_test_support.zig");
const typed_addi = @import("typed_addi.zig");
const witness = @import("typed_base_alu_imm_witness.zig");

const operations = [_]Opcode{ .ADDI, .XORI, .ORI, .ANDI };

test "typed BASE_ALU_IMM binding is complete source-independent and retained" {
    var generated = try typed_addi.build(std.testing.allocator, .generated);
    var moved = try typed_addi.build(std.testing.allocator, .{ .file = .{
        .path = "moved/base_alu_imm.air",
        .start = .{ .byte_offset = 12, .line = 3, .column = 1 },
        .end = .{ .byte_offset = 28, .line = 3, .column = 17 },
    } });
    defer moved.deinit();
    var binding = try witness.WitnessBinding.canonical(&generated);
    const executor = try witness.Executor.init(&generated, &binding);
    const moved_binding = try witness.WitnessBinding.canonical(&moved);
    const moved_executor = try witness.Executor.init(&moved, &moved_binding);

    try std.testing.expectEqual(
        witness.WITNESS_BINDING_FORMAT_VERSION,
        binding.format_version,
    );
    try std.testing.expectEqual(typed_addi.SEMANTIC_DIGEST, binding.semantic_digest);
    try std.testing.expectEqual(
        witness.WITNESS_BINDING_DIGEST,
        binding.identityDigest(),
    );
    try std.testing.expectEqual(executor.identityDigest(), moved_executor.identityDigest());
    try std.testing.expect(std.meta.eql(binding, executor.identitySnapshot()));
    for (binding.slots, witness.CANONICAL_RECIPE, 0..) |slot, recipe, column| {
        try std.testing.expectEqual(column, slot.column);
        try std.testing.expectEqual(column, @intFromEnum(slot.value));
        try std.testing.expectEqual(recipe, slot.source);
    }
    for (binding.operations, witness.CANONICAL_OPERATIONS) |actual, expected|
        try std.testing.expectEqualDeep(expected, actual);

    // The executor owns its fixed identity and remains usable after arena and
    // caller-side binding mutation.
    binding.operations[0].opcode_id = 0;
    generated.deinit();
    var storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    const rows = [_]witness.TraceRow{support.makeRow(
        .XORI,
        3,
        3,
        0x1234_5678,
        -1,
        10,
        0x1000,
        0,
        0,
        0,
    )};
    try executor.generateMainInto(&columns, &rows, 0);
    try support.expectLegacyColumns(&rows, 0, &columns);
}

test "typed BASE_ALU_IMM is exact for every opcode immediate and alias boundary" {
    const immediates = [_]i32{ -2048, -257, -1, 0, 1, 255, 2047 };
    const Case = struct { rd: u5, rs1: u5, source: u32 };
    const cases = [_]Case{
        .{ .rd = 0, .rs1 = 0, .source = 0 },
        .{ .rd = 1, .rs1 = 0, .source = 0xffff_ffff },
        .{ .rd = 5, .rs1 = 5, .source = 0x7fff_ffff },
        .{ .rd = 31, .rs1 = 7, .source = 0x8000_0000 },
    };
    var rows: [operations.len * immediates.len * cases.len]witness.TraceRow = undefined;
    var count: usize = 0;
    for (operations) |opcode| {
        for (immediates) |immediate| {
            for (cases) |case| {
                rows[count] = support.makeRow(
                    opcode,
                    case.rd,
                    case.rs1,
                    case.source,
                    immediate,
                    @intCast(count + 100),
                    @intCast(0x2000 + count * 4),
                    0x1020_3040 +% @as(u32, @intCast(count)),
                    @intCast(count),
                    @intCast(count + 1),
                );
                count += 1;
            }
        }
    }

    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    var actual = try support.OwnedColumns.init(
        std.testing.allocator,
        128,
        M31.fromCanonical(0x5151),
    );
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, &rows, 7);
    try support.expectLegacyColumns(&rows, 7, &actual.views);
    for (rows, 0..) |row, index| {
        try support.expectRelationParity(&executor, &actual.views, index, row);
        const expected_flag: usize = switch (row.opcode) {
            .ADDI => 25,
            .XORI => 26,
            .ORI => 27,
            .ANDI => 28,
            else => unreachable,
        };
        for (25..29) |column| try std.testing.expectEqual(
            column == expected_flag,
            actual.views[column][index].eql(M31.one()),
        );
    }
}

test "typed BASE_ALU_IMM matches the legacy oracle on a broad seeded corpus" {
    var prng = std.Random.DefaultPrng.init(0x4530_3134_2d49_4d4d);
    const random = prng.random();
    var rows: [256]witness.TraceRow = undefined;
    for (&rows, 0..) |*row, index| {
        const opcode = operations[random.uintLessThan(usize, operations.len)];
        const immediate = @as(i32, random.int(u12)) - 2048;
        row.* = support.makeRow(
            opcode,
            random.int(u5),
            random.int(u5),
            random.int(u32),
            immediate,
            @intCast(index + 1000),
            @intCast(0x4000 + index * 4),
            random.int(u32),
            random.uintLessThan(u32, 100),
            random.uintLessThan(u32, 100),
        );
    }
    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    var actual = try support.OwnedColumns.init(
        std.testing.allocator,
        rows.len,
        M31.zero(),
    );
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, &rows, 8);
    try support.expectLegacyColumns(&rows, 8, &actual.views);
    for (rows, 0..) |row, index|
        try support.expectRelationParity(&executor, &actual.views, index, row);
}

test "typed BASE_ALU_IMM preserves exterior guards and zeroes final padding" {
    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
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
        support.makeRow(.ADDI, 0, 0, 0, -2048, 10, 0x1000, 0, 0, 0),
        support.makeRow(.XORI, 7, 7, 0x1234_5678, -1, 11, 0x1004, 0, 0, 0),
        support.makeRow(.ORI, 31, 5, 0x8000_0000, 2047, 12, 0x1008, 9, 0, 0),
        support.makeRow(.ANDI, 1, 2, 0xffff_ffff, 0, 13, 0x100c, 8, 0, 0),
    };
    try executor.generateMainInto(&columns, &rows, 3);
    try support.expectLegacyColumns(&rows, 3, &columns);
    for (storage, columns) |owned, column| {
        try std.testing.expectEqual(guard, owned[0]);
        try std.testing.expectEqual(guard, owned[9]);
        for (column[rows.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}
