const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const support = @import("typed_mulh_witness_test_support.zig");
const typed = @import("typed_mulh.zig");
const witness = @import("typed_mulh_witness.zig");

test "typed MULH witness binding is exact portable and policy-authenticated" {
    var generated = try typed.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var moved = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "moved/mulh.air",
        .start = .{ .byte_offset = 80, .line = 11, .column = 3 },
        .end = .{ .byte_offset = 84, .line = 11, .column = 7 },
    } });
    defer moved.deinit();

    const binding = try witness.WitnessBinding.canonical(&generated);
    const moved_binding = try witness.WitnessBinding.canonical(&moved);
    const executor = try witness.Executor.init(&generated, &binding);
    const moved_executor = try witness.Executor.init(&moved, &moved_binding);
    try std.testing.expectEqual(binding.identityDigest(), executor.identityDigest());
    try std.testing.expectEqual(binding.identityDigest(), moved_executor.identityDigest());
    try std.testing.expect(std.meta.eql(binding, executor.identitySnapshot()));
    for (binding.slots, witness.CANONICAL_RECIPE, 0..) |slot, recipe, column| {
        try std.testing.expectEqual(column, slot.column);
        try std.testing.expectEqual(column, @intFromEnum(slot.value));
        try std.testing.expectEqual(recipe, slot.source);
    }
    for (binding.operations, witness.CANONICAL_OPERATIONS) |actual, expected|
        try std.testing.expectEqualDeep(expected, actual);

    // The prepared executor owns a value snapshot, not a borrowed binding.
    var mutable_binding = binding;
    mutable_binding.operations[0].opcode_id = 99;
    var storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    const rows = [_]witness.TraceRow{support.makeRow(
        .MULH,
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

test "typed MULH matches legacy semantics and all effects over 768 boundary rows" {
    const corpus_count = support.operations.len *
        support.boundary_operands.len * support.boundary_operands.len;
    comptime if (corpus_count != 768)
        @compileError("typed MULH boundary corpus cardinality is migration evidence");
    var rows: [corpus_count]witness.TraceRow = undefined;
    for (&rows, 0..) |*row, index| row.* = support.corpusRow(index);

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

test "typed MULH seeded corpus preserves arbitrary products aliases and effects" {
    var prng = std.Random.DefaultPrng.init(0x4530_3134_2d4d_4849);
    const random = prng.random();
    var rows: [256]witness.TraceRow = undefined;
    for (&rows, 0..) |*row, index| row.* = support.makeRow(
        support.operations[random.uintLessThan(usize, support.operations.len)],
        random.int(u5),
        random.int(u5),
        random.int(u5),
        random.int(u32),
        random.int(u32),
        @intCast(index + 1000),
        @intCast(0x8000 + index * 4),
        random.int(u32),
        random.int(u32),
        random.int(u32),
        random.int(u32),
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

test "typed MULH operation policy covers signedness discontinuities exactly" {
    const Case = struct { lhs: u32, rhs: u32 };
    const cases = [_]Case{
        .{ .lhs = 0, .rhs = 0 },
        .{ .lhs = 1, .rhs = 0xffff_ffff },
        .{ .lhs = 0x7fff_ffff, .rhs = 0x8000_0000 },
        .{ .lhs = 0x8000_0000, .rhs = 1 },
        .{ .lhs = 0x8000_0000, .rhs = 0xffff_ffff },
        .{ .lhs = 0xffff_ffff, .rhs = 0xffff_ffff },
    };
    var rows: [support.operations.len * cases.len]witness.TraceRow = undefined;
    var count: usize = 0;
    for (support.operations) |opcode| for (cases) |case| {
        rows[count] = support.makeRow(
            opcode,
            @intCast((count % 31) + 1),
            5,
            6,
            case.lhs,
            case.rhs,
            @intCast(count + 50),
            @intCast(0xc000 + count * 4),
            @truncate(0x5566_7788 +% count),
            0,
            0,
            0,
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

test "typed MULH preserves guards and zeroes final padding" {
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
        support.makeRow(.MULH, 0, 0, 0, 0, 0, 10, 0x1000, 0, 0, 0, 0),
        support.makeRow(.MULHSU, 7, 7, 8, 0xffff_ffff, 0xffff_ffff, 11, 0x1004, 0, 0, 0, 0),
        support.makeRow(.MULHU, 9, 5, 9, 0x8000_0000, 0x8000_0000, 12, 0x1008, 0, 0, 0, 0),
        support.makeRow(.MULH, 1, 2, 3, 0x0102_0304, 0xff00_ff00, 13, 0x100c, 8, 0, 0, 0),
    };
    try executor.generateMainInto(&columns, &rows, 3);
    try support.expectLegacyColumns(&rows, 3, &columns);
    for (storage, columns) |owned, column| {
        try std.testing.expectEqual(guard, owned[0]);
        try std.testing.expectEqual(guard, owned[9]);
        for (column[rows.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}

test "typed MULH witness-binding digest is pinned" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    try std.testing.expectEqual(witness.WITNESS_BINDING_DIGEST, binding.identityDigest());
}

test "typed MULH helper result agrees with independently authored policy" {
    for (support.operations) |opcode| for (support.boundary_operands) |lhs| {
        const rhs = lhs ^ 0xa5a5_5a5a;
        const row = support.makeRow(opcode, 1, 2, 3, lhs, rhs, 10, 0x1000, 0, 0, 0, 0);
        try std.testing.expectEqual(support.result(opcode, lhs, rhs), witness.highProduct(row));
    };
}
