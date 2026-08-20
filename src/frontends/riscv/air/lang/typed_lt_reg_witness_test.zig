const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Opcode = @import("../../isa/decode.zig").Opcode;
const legacy = @import("../../runner/witness/lt_reg_legacy_test_oracle.zig");
const support = @import("typed_lt_reg_witness_test_support.zig");
const typed = @import("typed_lt_reg.zig");
const witness = @import("typed_lt_reg_witness.zig");

const operations = [_]Opcode{ .SLT, .SLTU };

test "typed LT_REG binding is complete source-independent and retained" {
    var generated = try typed.build(std.testing.allocator, .generated);
    var moved = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "moved/compare/lt_reg.air",
        .start = .{ .byte_offset = 144, .line = 17, .column = 3 },
        .end = .{ .byte_offset = 148, .line = 17, .column = 7 },
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
        .SLT,
        3,
        3,
        3,
        0x8000_0000,
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

test "typed LT_REG exhaustively matches legacy across signed top limbs" {
    var actual_storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var expected_storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var actual: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    var expected: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&actual, &actual_storage) |*view, *storage| view.* = storage;
    for (&expected, &expected_storage) |*view, *storage| view.* = storage;

    var visited: usize = 0;
    for (operations) |opcode| {
        for (0..256) |lhs_most_significant| {
            for (0..256) |rhs_most_significant| {
                const lhs = @as(u32, @intCast(lhs_most_significant)) << 24 |
                    0x005a_a55a;
                const rhs = @as(u32, @intCast(rhs_most_significant)) << 24 |
                    0x005a_a55a;
                const row = support.makeRow(
                    opcode,
                    5,
                    3,
                    4,
                    lhs,
                    rhs,
                    @intCast(1 + visited % 1_000_000),
                    @truncate(0x1000 +% visited *% 4),
                    @truncate(visited *% 0x1020_3041),
                    0,
                    0,
                    0,
                );
                witness.writeActiveRow(&actual, 0, row);
                legacy.writeRow(&expected, 0, row);
                inline for (0..witness.MAIN_COLUMN_COUNT) |column| {
                    if (!actual[column][0].eql(expected[column][0])) {
                        std.log.err(
                            "LT_REG top-limb mismatch opcode={s} lhs_msl={d} " ++
                                "rhs_msl={d} column={d}",
                            .{
                                @tagName(opcode),
                                lhs_most_significant,
                                rhs_most_significant,
                                column,
                            },
                        );
                        return error.WitnessCellMismatch;
                    }
                }
                visited += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 2 * 256 * 256), visited);
}

test "typed LT_REG is exact at every first-difference and alias boundary" {
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
        .{ .rd = 5, .rs1 = 5, .rs2 = 9, .lhs = 0x7fff_ffff, .rhs = 0x8000_0000 },
        .{ .rd = 9, .rs1 = 5, .rs2 = 9, .lhs = 0x8000_0000, .rhs = 0x7fff_ffff },
        .{ .rd = 31, .rs1 = 3, .rs2 = 4, .lhs = 0x0102_0304, .rhs = 0x0102_0305 },
        .{ .rd = 1, .rs1 = 2, .rs2 = 3, .lhs = 0x0102_0304, .rhs = 0x0102_0404 },
        .{ .rd = 2, .rs1 = 3, .rs2 = 4, .lhs = 0x0102_0304, .rhs = 0x0103_0304 },
        .{ .rd = 3, .rs1 = 4, .rs2 = 5, .lhs = 0x0102_0304, .rhs = 0x0202_0304 },
        .{ .rd = 4, .rs1 = 5, .rs2 = 6, .lhs = 0x8080_8080, .rhs = 0x8080_8080 },
        .{ .rd = 6, .rs1 = 0, .rs2 = 6, .lhs = 0xffff_ffff, .rhs = 1 },
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

test "typed LT_REG matches legacy and ordered relation authority on seeded corpus" {
    var prng = std.Random.DefaultPrng.init(0x4530_3134_2d4c_5452);
    const random = prng.random();
    var rows: [256]witness.TraceRow = undefined;
    for (&rows, 0..) |*row, index| row.* = support.makeRow(
        operations[index & 1],
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

test "typed LT_REG preserves guards and zeroes final padding" {
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
        support.makeRow(.SLT, 0, 0, 0, 0, 0, 10, 0x1000, 0, 0, 0, 0),
        support.makeRow(.SLTU, 7, 7, 7, 1, 0, 11, 0x1004, 0, 0, 0, 0),
        support.makeRow(.SLT, 9, 5, 9, 0x8000_0000, 1, 12, 0x1008, 0, 0, 0, 0),
        support.makeRow(.SLTU, 1, 2, 3, 0xffff_ffff, 0, 13, 0x100c, 8, 0, 0, 0),
    };
    try executor.generateMainInto(&columns, &rows, 3);
    try support.expectLegacyColumns(&rows, 3, &columns);
    for (storage, columns) |owned, column| {
        try std.testing.expectEqual(guard, owned[0]);
        try std.testing.expectEqual(guard, owned[9]);
        for (column[rows.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}
