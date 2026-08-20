const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Opcode = @import("../../isa/decode.zig").Opcode;
const legacy = @import("../../runner/witness/branch_eq_legacy_test_oracle.zig");
const support = @import("typed_branch_eq_witness_test_support.zig");
const typed = @import("typed_branch_eq.zig");
const witness = @import("typed_branch_eq_witness.zig");

const operations = [_]Opcode{ .BEQ, .BNE };

test "typed BRANCH_EQ binding is complete source-independent and retained" {
    var generated = try typed.build(std.testing.allocator, .generated);
    var moved = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "moved/control/branch_eq.air",
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
    try std.testing.expectEqualDeep(witness.CANONICAL_OPERATIONS, binding.operations);
    try std.testing.expectEqual(witness.CANONICAL_INVERSE_ALGORITHM, binding.inverse_algorithm);
    try std.testing.expectEqualDeep(witness.EVENT_SPECS, binding.events);

    binding.operations[0].opcode_id = 99;
    generated.deinit();
    var storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    const rows = [_]witness.TraceRow{support.makeRow(
        .BNE,
        3,
        4,
        0x0102_0304,
        0x0102_0305,
        8,
        10,
        0x1000,
        0,
        0,
    )};
    try executor.generateMainInto(&columns, &rows, 0);
    try support.expectLegacyColumns(&rows, 0, &columns);
}

test "typed BRANCH_EQ exhaustively matches first inverse marker for every byte pair" {
    var actual_storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var expected_storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var actual: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    var expected: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&actual, &actual_storage) |*view, *storage| view.* = storage;
    for (&expected, &expected_storage) |*view, *storage| view.* = storage;

    var visited: usize = 0;
    for (operations) |opcode| {
        for (0..4) |limb| {
            const shift: u5 = @intCast(limb * 8);
            const mask = ~(@as(u32, 0xff) << shift);
            for (0..256) |lhs_byte| {
                for (0..256) |rhs_byte| {
                    const lhs = (0x5a5a_5a5a & mask) |
                        (@as(u32, @intCast(lhs_byte)) << shift);
                    const rhs = (0x5a5a_5a5a & mask) |
                        (@as(u32, @intCast(rhs_byte)) << shift);
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
                                "BRANCH_EQ inverse mismatch opcode={s} limb={d} " ++
                                    "lhs={d} rhs={d} column={d}",
                                .{ @tagName(opcode), limb, lhs_byte, rhs_byte, column },
                            );
                            return error.WitnessCellMismatch;
                        }
                    }
                    visited += 1;
                }
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 2 * 4 * 256 * 256), visited);
}

test "typed BRANCH_EQ is exact at decision inverse target and alias boundaries" {
    const Case = struct {
        opcode: Opcode,
        rs1: u5,
        rs2: u5,
        lhs: u32,
        rhs: u32,
        immediate: i32,
    };
    const cases = [_]Case{
        .{ .opcode = .BEQ, .rs1 = 0, .rs2 = 0, .lhs = 0, .rhs = 0, .immediate = 0 },
        .{ .opcode = .BNE, .rs1 = 7, .rs2 = 7, .lhs = 1, .rhs = 2, .immediate = 4 },
        .{ .opcode = .BEQ, .rs1 = 5, .rs2 = 9, .lhs = 0, .rhs = 1, .immediate = -4096 },
        .{ .opcode = .BNE, .rs1 = 5, .rs2 = 9, .lhs = 0, .rhs = 1, .immediate = 4092 },
        .{ .opcode = .BEQ, .rs1 = 2, .rs2 = 3, .lhs = 0x0102_0304, .rhs = 0x0102_0305, .immediate = 8 },
        .{ .opcode = .BNE, .rs1 = 2, .rs2 = 3, .lhs = 0x0102_0304, .rhs = 0x0102_0404, .immediate = -8 },
        .{ .opcode = .BEQ, .rs1 = 2, .rs2 = 3, .lhs = 0x0102_0304, .rhs = 0x0103_0304, .immediate = 12 },
        .{ .opcode = .BNE, .rs1 = 2, .rs2 = 3, .lhs = 0x0102_0304, .rhs = 0x0202_0304, .immediate = 16 },
        .{ .opcode = .BEQ, .rs1 = 31, .rs2 = 30, .lhs = 0xffff_ffff, .rhs = 0xffff_ffff, .immediate = 20 },
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
    // B-type bits 11:7 are decoder metadata, not a destination register.
    rows[1].rd = 31;
    rows[1].rd_prev_val = 0x1234_5678;
    rows[1].rd_prev_clk = 0x8765_4321;
    rows[1].rd_val = 0x89ab_cdef;

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

test "typed BRANCH_EQ matches legacy and ordered relation authority on seeded corpus" {
    var prng = std.Random.DefaultPrng.init(0x4530_3134_2d42_4551);
    const random = prng.random();
    var rows: [256]witness.TraceRow = undefined;
    for (&rows, 0..) |*row, index| {
        row.* = support.makeRow(
            operations[index & 1],
            random.int(u5),
            random.int(u5),
            random.int(u32),
            random.int(u32),
            random.intRangeAtMost(i32, -1024, 1023) * 4,
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

test "typed BRANCH_EQ production source is authority-pinned allocator-free and independent" {
    const source_text = @embedFile("typed_branch_eq_witness.zig");
    const trace_source = @embedFile("../../runner/trace.zig");
    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".branch_eq => BRANCH_EQ_AUTHORITY.writeActiveRow",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".branch_eq => typed_branch_eq_witness.writeActiveRow",
    ) == null);
    try std.testing.expect(std.mem.indexOf(u8, trace_source, "compare_witness") == null);
    try std.testing.expect(std.mem.indexOf(u8, trace_source, "witness/compare.zig") == null);
    try std.testing.expect(std.mem.indexOf(u8, source_text, "legacy_test_oracle") == null);
    try std.testing.expect(std.mem.indexOf(u8, source_text, "pub inline fn writeActiveRow") != null);
    try std.testing.expect(std.mem.indexOf(u8, source_text, "inline for (CANONICAL_RECIPE") != null);
    try std.testing.expect(std.mem.indexOf(u8, source_text, "allocator.alloc") == null);
    try std.testing.expect(std.mem.indexOf(u8, source_text, "ArrayList") == null);
}

test "typed BRANCH_EQ preserves guards and zeroes final padding" {
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
        support.makeRow(.BEQ, 0, 0, 0, 0, 0, 10, 0x1000, 0, 0),
        support.makeRow(.BNE, 7, 7, 1, 0, 4, 11, 0x1004, 0, 0),
        support.makeRow(.BEQ, 5, 9, 1, 2, 8, 12, 0x1008, 0, 0),
        support.makeRow(.BNE, 2, 3, 0xffff_ffff, 0, -4, 13, 0x100c, 0, 0),
    };
    try executor.generateMainInto(&columns, &rows, 3);
    try support.expectLegacyColumns(&rows, 3, &columns);
    for (storage, columns) |owned, column| {
        try std.testing.expectEqual(guard, owned[0]);
        try std.testing.expectEqual(guard, owned[9]);
        for (column[rows.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}
