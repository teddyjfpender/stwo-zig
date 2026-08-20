const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const support = @import("typed_fence_witness_test_support.zig");
const typed_fence = @import("typed_fence.zig");
const witness = @import("typed_fence_witness.zig");

test "typed FENCE witness rejects every binding mutation" {
    var authored = try typed_fence.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const canonical = try witness.WitnessBinding.canonical(&authored);
    var malformed = canonical;
    malformed.format_version +%= 1;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.semantic_format_version +%= 1;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.opcode_id +%= 1;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.semantic_digest[0] ^= 1;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.slots[4].column = 3;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.slots[4].value = malformed.slots[3].value;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.slots[4].source = .trace_encoding_rd;
    try expectInvalidBinding(&authored, &malformed);
}

test "typed FENCE witness rejects malformed semantic authority before binding trust" {
    var malformed = try typed_fence.build(std.testing.allocator, .generated);
    defer malformed.deinit();
    const binding = try witness.WitnessBinding.canonical(&malformed);
    malformed.arena.nodes.items[0].key.ty = .byte;
    try std.testing.expectError(
        error.InvalidInternTable,
        witness.Executor.init(&malformed, &binding),
    );
}

test "typed FENCE witness rejects hidden side effects and malformed rows atomically" {
    var authored = try typed_fence.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    const sentinel = M31.fromCanonical(0x1ace);
    var columns = try support.OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    const honest = support.makeRow(3, 5, -173, 2, 0x1000, 7);

    var forged = honest;
    forged.opcode = .ADDI;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest;
    forged.imm = -2049;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest;
    forged.imm = 2048;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest;
    forged.next_pc +%= 4;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest;
    forged.branch_taken = true;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest;
    forged.is_load = true;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest;
    forged.is_store = true;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest;
    forged.rd_val +%= 1;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest;
    forged.rs1_prev_clk = 1;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest;
    forged.rd_prev_clk = 1;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest;
    forged.mem_prev_word = 1;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
}

test "typed FENCE witness shape and alias failures are deterministic and atomic" {
    var authored = try typed_fence.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    const sentinel = M31.fromCanonical(0x2bad);
    var columns = try support.OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    const rows = [_]witness.TraceRow{support.makeRow(3, 5, -173, 1, 0x1000, 7)};

    const original_last = columns.views[witness.MAIN_COLUMN_COUNT - 1];
    columns.views[witness.MAIN_COLUMN_COUNT - 1] = original_last[0..3];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, &rows, 2),
    );
    try columns.expectStorageValue(sentinel);
    columns.views[witness.MAIN_COLUMN_COUNT - 1] = original_last;

    const original_second = columns.views[1];
    columns.views[1] = columns.views[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&columns.views, &rows, 2),
    );
    try columns.expectStorageValue(sentinel);
    columns.views[1] = original_second;

    var overlap = [_]M31{sentinel} ** 5;
    const original_first = columns.views[0];
    columns.views[0] = overlap[0..4];
    columns.views[1] = overlap[1..5];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&columns.views, &rows, 2),
    );
    try std.testing.expectEqualSlices(M31, &([_]M31{sentinel} ** 5), &overlap);
    try columns.expectStorageValue(sentinel);
    columns.views[0] = original_first;
    columns.views[1] = original_second;

    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, &rows, @bitSizeOf(usize)),
    );
    try columns.expectStorageValue(sentinel);

    var aliased = try support.OwnedColumns.init(std.testing.allocator, 64, sentinel);
    defer aliased.deinit();
    comptime {
        if (@sizeOf(witness.TraceRow) > 64 * @sizeOf(M31))
            @compileError("input-alias fixture is too small");
    }
    const row_pointer: *witness.TraceRow = @ptrCast(@alignCast(aliased.storage[0].ptr));
    row_pointer.* = rows[0];
    var before: [64]M31 = undefined;
    @memcpy(&before, aliased.storage[0]);
    const overlapping_rows = @as([*]const witness.TraceRow, @ptrCast(row_pointer))[0..1];
    try std.testing.expectError(
        error.AliasedInput,
        executor.generateMainInto(&aliased.views, overlapping_rows, 6),
    );
    try std.testing.expectEqualSlices(M31, &before, aliased.storage[0]);
    for (aliased.storage[1..]) |column| {
        for (column) |value| try std.testing.expectEqual(sentinel, value);
    }
}

test "typed FENCE witness preserves guards and zeroes final padding only" {
    var authored = try typed_fence.build(std.testing.allocator, .generated);
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
        support.makeRow(0, 0, -2048, 1, 0x1000, 0),
        support.makeRow(17, 31, -1, 2, 0x1004, 7),
        support.makeRow(31, 17, 2047, 3, 0x1008, 9),
    };
    try executor.generateMainInto(&columns, &rows, 3);
    try support.expectLegacyColumns(&rows, 3, &columns);
    for (guarded, columns) |storage, column| {
        try std.testing.expectEqual(guard, storage[0]);
        try std.testing.expectEqual(guard, storage[9]);
        for (column[rows.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}

test "typed FENCE witness construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn expectInvalidBinding(
    definition: *const typed_fence.Definition,
    binding: *const witness.WitnessBinding,
) !void {
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(definition, binding),
    );
}

fn expectInvalidRowAtomic(
    executor: *const witness.Executor,
    columns: *support.OwnedColumns,
    row: witness.TraceRow,
    sentinel: M31,
) !void {
    try std.testing.expectError(
        error.InvalidTraceRow,
        executor.generateMainInto(&columns.views, &.{row}, 2),
    );
    try columns.expectStorageValue(sentinel);
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var authored = try typed_fence.build(allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    _ = try witness.Executor.init(&authored, &binding);
}
