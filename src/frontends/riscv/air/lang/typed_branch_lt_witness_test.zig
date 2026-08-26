const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Opcode = @import("../../isa/decode.zig").Opcode;
const legacy = @import("../../runner/witness/branch_lt_legacy_test_oracle.zig");
const support = @import("typed_branch_lt_witness_test_support.zig");
const typed = @import("typed_branch_lt.zig");
const witness = @import("typed_branch_lt_witness.zig");

const operations = [_]Opcode{ .BLT, .BLTU, .BGE, .BGEU };

test "typed BRANCH_LT binding is complete source-independent and retained" {
    var generated = try typed.build(std.testing.allocator, .generated);
    var moved = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "moved/control/branch_lt.air",
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
        .BLT,
        3,
        4,
        0x8000_0000,
        0,
        8,
        10,
        0x1000,
        0,
        0,
    )};
    try executor.generateMainInto(&columns, &rows, 0);
    try support.expectLegacyColumns(&rows, 0, &columns);
}

test "typed BRANCH_LT exhaustively matches every opcode across top limbs" {
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
                    3,
                    4,
                    lhs,
                    rhs,
                    8,
                    @intCast(1 + visited % 200_000),
                    0x0010_0000,
                    0,
                    0,
                );
                witness.writeActiveRow(&actual, 0, row);
                legacy.writeRow(&expected, 0, row);
                inline for (0..witness.MAIN_COLUMN_COUNT) |column| {
                    if (!actual[column][0].eql(expected[column][0])) {
                        std.log.err(
                            "BRANCH_LT top-limb mismatch opcode={s} lhs_msl={d} " ++
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
    try std.testing.expectEqual(@as(usize, 4 * 256 * 256), visited);
}

test "typed BRANCH_LT is exact at comparison target and alias boundaries" {
    const Case = struct {
        opcode: Opcode,
        rs1: u5,
        rs2: u5,
        lhs: u32,
        rhs: u32,
        immediate: i32,
    };
    const cases = [_]Case{
        .{ .opcode = .BLT, .rs1 = 0, .rs2 = 0, .lhs = 0, .rhs = 0, .immediate = 0 },
        .{ .opcode = .BGE, .rs1 = 7, .rs2 = 7, .lhs = 0xffff_ffff, .rhs = 0, .immediate = 4 },
        .{ .opcode = .BLT, .rs1 = 5, .rs2 = 9, .lhs = 0x8000_0000, .rhs = 0, .immediate = -4096 },
        .{ .opcode = .BGE, .rs1 = 5, .rs2 = 9, .lhs = 0x7fff_ffff, .rhs = 0x8000_0000, .immediate = 4092 },
        .{ .opcode = .BLTU, .rs1 = 3, .rs2 = 4, .lhs = 1, .rhs = 2, .immediate = 8 },
        .{ .opcode = .BGEU, .rs1 = 3, .rs2 = 4, .lhs = 1, .rhs = 2, .immediate = -8 },
        .{ .opcode = .BLTU, .rs1 = 2, .rs2 = 3, .lhs = 0x0102_0304, .rhs = 0x0102_0305, .immediate = 12 },
        .{ .opcode = .BLTU, .rs1 = 2, .rs2 = 3, .lhs = 0x0102_0304, .rhs = 0x0102_0404, .immediate = 16 },
        .{ .opcode = .BLTU, .rs1 = 2, .rs2 = 3, .lhs = 0x0102_0304, .rhs = 0x0103_0304, .immediate = 20 },
        .{ .opcode = .BLTU, .rs1 = 2, .rs2 = 3, .lhs = 0x0102_0304, .rhs = 0x0202_0304, .immediate = 24 },
        .{ .opcode = .BGEU, .rs1 = 4, .rs2 = 5, .lhs = 0x8080_8080, .rhs = 0x8080_8080, .immediate = 28 },
        .{ .opcode = .BLT, .rs1 = 0, .rs2 = 6, .lhs = 0xffff_ffff, .rhs = 1, .immediate = -4 },
    };
    var rows: [cases.len]witness.TraceRow = undefined;
    for (&rows, cases, 0..) |*row, case, index| row.* = support.makeRow(
        case.opcode,
        case.rs1,
        case.rs2,
        case.lhs,
        case.rhs,
        case.immediate,
        @intCast(index + 100),
        0x0010_0000,
        @intCast(index),
        @intCast(index + 1),
    );

    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var actual = try support.OwnedColumns.init(std.testing.allocator, 16, M31.zero());
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, &rows, 4);
    try support.expectLegacyColumns(&rows, 4, &actual.views);
    for (rows, 0..) |row, index| try support.expectRelationParity(
        &executor,
        &actual.views,
        index,
        row,
    );
}

test "typed BRANCH_LT matches legacy and ordered relation authority on seeded corpus" {
    var prng = std.Random.DefaultPrng.init(0x4530_3134_2d42_4c54);
    const random = prng.random();
    var rows: [256]witness.TraceRow = undefined;
    for (&rows, 0..) |*row, index| {
        const immediate = random.intRangeAtMost(i32, -1024, 1023) * 4;
        row.* = support.makeRow(
            operations[index & 3],
            random.int(u5),
            random.int(u5),
            random.int(u32),
            random.int(u32),
            immediate,
            @intCast(index + 1000),
            @intCast(0x0010_0000 + index * 4),
            random.uintLessThan(u32, 100),
            random.uintLessThan(u32, 100),
        );
    }
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

test "typed BRANCH_LT production source is singular pinned and allocator-free" {
    const witness_source = @embedFile("typed_branch_lt_witness.zig");
    const trace_source = @embedFile("../../runner/trace.zig");
    const execute_source = @embedFile("../../runner/execute.zig");
    const retirement_source = @embedFile("../../runner/generated_retirement.zig");
    const constraint_source = @embedFile("../constraint_program_constructors.zig");
    const semantics_registry = @embedFile("../semantics/mod.zig");

    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".branch_lt => BRANCH_LT_AUTHORITY.writeActiveRow",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".branch_lt => typed_branch_lt_witness.writeActiveRow",
    ) == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        execute_source,
        ".BLT, .BLTU, .BGE, .BGEU => return error.GeneratedRetirementRequired",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        retirement_source,
        ".blt, .bltu, .bge, .bgeu => try branch_lt.retireAtomic",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        constraint_source,
        ".branch_lt => constructBranchLt(section, columns, is_active)",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        constraint_source,
        ".branch_lt => constructFamily(section, .branch_lt",
    ) == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        semantics_registry,
        "pub const branch_lt =",
    ) == null);
    try std.testing.expect(std.mem.indexOf(u8, trace_source, "compare_witness") == null);
    try std.testing.expect(std.mem.indexOf(u8, witness_source, "legacy_test_oracle") == null);
    try std.testing.expect(std.mem.indexOf(u8, witness_source, "allocator.alloc") == null);
    try std.testing.expect(std.mem.indexOf(u8, witness_source, "ArrayList") == null);
}

test "typed BRANCH_LT preserves guards and zeroes final padding" {
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
        support.makeRow(.BLT, 0, 0, 0, 0, 0, 10, 0x1000, 0, 0),
        support.makeRow(.BLTU, 7, 7, 1, 0, 4, 11, 0x1004, 0, 0),
        support.makeRow(.BGE, 5, 9, 0x8000_0000, 1, 8, 12, 0x1008, 0, 0),
        support.makeRow(.BGEU, 2, 3, 0xffff_ffff, 0, -4, 13, 0x100c, 0, 0),
    };
    try executor.generateMainInto(&columns, &rows, 3);
    try support.expectLegacyColumns(&rows, 3, &columns);
    for (storage, columns) |owned, column| {
        try std.testing.expectEqual(guard, owned[0]);
        try std.testing.expectEqual(guard, owned[9]);
        for (column[rows.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}
