const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const hint_recipe = @import("hint_recipe.zig");
const support = @import("typed_auipc_witness_test_support.zig");
const typed_auipc = @import("typed_auipc.zig");
const witness = @import("typed_auipc_witness.zig");

test "typed AUIPC witness rejects every binding arithmetic and hint mutation" {
    var authored = try typed_auipc.build(std.testing.allocator, .generated);
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
    malformed.slots[13].column = 14;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.slots[13].value = malformed.slots[14].value;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.slots[13].source = .trace_pc;
    try expectInvalidBinding(&authored, &malformed);

    malformed = canonical;
    malformed.arithmetic.pc_column = 3;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.arithmetic.immediate_column = 12;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.arithmetic.first_result_column = 13;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.arithmetic.result_limb_count = 3;
    try expectInvalidBinding(&authored, &malformed);

    malformed = canonical;
    malformed.destination_hint.recipe = hint_recipe.id(.identity_felt);
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.destination_hint.recipe_version +%= 1;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.destination_hint.algorithm = .identity_felt;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.destination_hint.exceptional_cases = .none;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.destination_hint.input_column = 2;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.destination_hint.inverse_output_column = 18;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.destination_hint.nonzero_output_column = 19;
    try expectInvalidBinding(&authored, &malformed);
}

test "typed AUIPC witness rejects malformed semantic authority before binding trust" {
    var malformed = try typed_auipc.build(std.testing.allocator, .generated);
    defer malformed.deinit();
    const binding = try witness.WitnessBinding.canonical(&malformed);
    malformed.arena.nodes.items[0].key.ty = .byte;
    try std.testing.expectError(
        error.InvalidInternTable,
        witness.Executor.init(&malformed, &binding),
    );
}

test "typed AUIPC witness rejects forged architectural rows atomically" {
    var authored = try typed_auipc.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    const sentinel = M31.fromCanonical(0x1ace);
    var columns = try support.OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    const honest = support.makeRow(3, 0x1000, 2, 0x1000, 7, 1);

    var forged = honest;
    forged.opcode = .LUI;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest;
    forged.imm = 1;
    forged.rd_val = forged.pc +% 1;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest;
    forged.pc = @as(u32, 1) << 30;
    forged.rd_val = forged.pc +% @as(u32, @bitCast(forged.imm));
    forged.next_pc = forged.pc +% 4;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest;
    forged.next_pc +%= 4;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest;
    forged.rd_val +%= 1;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = support.makeRow(0, 0, 2, 0x1000, 0, 0);
    forged.rd_prev_val = 1;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = support.makeRow(0, 0, 2, 0x1000, 0, 0);
    forged.rd_prev_clk = 1;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
}

test "typed AUIPC witness shape destination and input alias failures are atomic" {
    var authored = try typed_auipc.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    const sentinel = M31.fromCanonical(0x2bad);
    var columns = try support.OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    const rows = [_]witness.TraceRow{support.makeRow(3, 0x1000, 1, 0x1000, 0, 0)};

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

test "typed AUIPC witness preserves outer guards and zeroes final padding only" {
    var authored = try typed_auipc.build(std.testing.allocator, .generated);
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
        support.makeRow(0, 0, 1, 0x1000, 0, 0),
        support.makeRow(1, @bitCast(@as(u32, 0x8000_0000)), 2, 0x1004, 7, 1),
        support.makeRow(31, @bitCast(@as(u32, 0xffff_f000)), 3, 0x1008, 9, 5),
    };
    try executor.generateMainInto(&columns, &rows, 3);
    try support.expectLegacyColumns(&rows, 3, &columns);
    for (guarded, columns) |storage, column| {
        try std.testing.expectEqual(guard, storage[0]);
        try std.testing.expectEqual(guard, storage[9]);
        for (column[rows.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}

test "typed AUIPC witness construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn expectInvalidBinding(
    definition: *const typed_auipc.Definition,
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
    var authored = try typed_auipc.build(allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    _ = try witness.Executor.init(&authored, &binding);
}
