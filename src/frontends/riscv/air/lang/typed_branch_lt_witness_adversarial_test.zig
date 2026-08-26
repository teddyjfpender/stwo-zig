const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const support = @import("typed_branch_lt_witness_test_support.zig");
const typed = @import("typed_branch_lt.zig");
const witness = @import("typed_branch_lt_witness.zig");

test "typed BRANCH_LT rejects every binding identity mutation" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const canonical = try witness.WitnessBinding.canonical(&definition);
    var malformed = canonical;
    malformed.format_version +%= 1;
    try expectInvalidBinding(&definition, &malformed);
    malformed = canonical;
    malformed.semantic_format_version +%= 1;
    try expectInvalidBinding(&definition, &malformed);
    malformed = canonical;
    malformed.semantic_digest[0] ^= 1;
    try expectInvalidBinding(&definition, &malformed);
    malformed = canonical;
    malformed.slots[0].column = 1;
    try expectInvalidBinding(&definition, &malformed);
    malformed = canonical;
    malformed.slots[0].value = malformed.slots[1].value;
    try expectInvalidBinding(&definition, &malformed);
    malformed = canonical;
    malformed.slots[0].source = .trace_pc;
    try expectInvalidBinding(&definition, &malformed);
    malformed = canonical;
    malformed.operations[0].opcode_id = typed.BLTU_OPCODE_ID;
    try expectInvalidBinding(&definition, &malformed);
    malformed = canonical;
    malformed.operations[0].flag_column = 34;
    try expectInvalidBinding(&definition, &malformed);
    malformed = canonical;
    malformed.operations[0].comparison = .unsigned_u32;
    try expectInvalidBinding(&definition, &malformed);
    malformed = canonical;
    malformed.operations[0].decision = .greater_or_equal;
    try expectInvalidBinding(&definition, &malformed);
}

test "typed BRANCH_LT authenticates definition before row recipe" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    definition.arena.nodes.items[0].key.ty = .byte;
    try std.testing.expectError(
        error.InvalidInternTable,
        witness.Executor.init(&definition, &binding),
    );
}

test "typed BRANCH_LT row forgeries reject atomically" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const sentinel = M31.fromCanonical(0x1ace);
    var columns = try support.OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    const valid = support.makeRow(
        .BLT,
        5,
        6,
        0x8000_0000,
        0x7fff_ffff,
        8,
        20,
        0x1000,
        0,
        0,
    );
    var forged = valid;
    forged.opcode = .ADD;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.imm = 3;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.imm = 4096;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.clk = 0;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.clk = std.math.maxInt(u32);
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.pc += 2;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.pc = @as(u32, 1) << 30;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.next_pc +%= 4;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.branch_taken = !forged.branch_taken;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.is_load = true;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.is_store = true;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.mem_addr = 4;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rs1 = 0;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rs2 = 0;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rs2 = forged.rs1;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rs2 = forged.rs1;
    forged.rs2_val = forged.rs1_val;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rs1_prev_clk = (valid.clk - 1) * 4 + 1;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rs2_prev_clk = (valid.clk - 1) * 4 + 2;
    try expectRowRejected(&executor, &columns, forged, sentinel);

    forged = valid;
    forged.imm = 2;
    forged.next_pc = forged.pc + 2;
    forged.branch_taken = true;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.pc = (@as(u32, 1) << 30) - 4;
    forged.imm = 4;
    forged.next_pc = @as(u32, 1) << 30;
    forged.branch_taken = false;
    try expectRowRejected(&executor, &columns, forged, sentinel);
}

test "typed BRANCH_LT ignores B-immediate bits decoded through destination metadata" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const valid = support.makeRow(
        .BGEU,
        2,
        3,
        4,
        5,
        4092,
        10,
        0x10_000,
        0,
        0,
    );
    var decoded = valid;
    // The generic decoder exposes instruction bits 11:7 as `rd` even though
    // a B-type instruction has no destination. Runner snapshots of that
    // pseudo-register are likewise not part of the BRANCH_LT witness recipe.
    decoded.rd = 31;
    decoded.rd_prev_val = 0x1234_5678;
    decoded.rd_prev_clk = 0x7654_3210;
    decoded.rd_val = 0x89ab_cdef;

    var baseline = try support.OwnedColumns.init(std.testing.allocator, 1, M31.zero());
    defer baseline.deinit();
    var actual = try support.OwnedColumns.init(std.testing.allocator, 1, M31.zero());
    defer actual.deinit();
    try executor.generateMainInto(&baseline.views, &.{valid}, 0);
    try executor.generateMainInto(&actual.views, &.{decoded}, 0);
    for (baseline.views, actual.views) |expected, observed|
        try std.testing.expectEqualSlices(M31, expected, observed);
}

test "typed BRANCH_LT rejects shapes aliases input overlap and address overflow atomically" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const sentinel = M31.fromCanonical(0x2bad);
    var columns = try support.OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    const rows = [_]witness.TraceRow{support.makeRow(
        .BGEU,
        2,
        3,
        4,
        5,
        8,
        10,
        0x1000,
        0,
        0,
    )};
    const last = columns.views[witness.MAIN_COLUMN_COUNT - 1];
    columns.views[witness.MAIN_COLUMN_COUNT - 1] = last[0..3];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, &rows, 2),
    );
    try columns.expectStorageValue(sentinel);
    columns.views[witness.MAIN_COLUMN_COUNT - 1] = last;

    const second = columns.views[1];
    columns.views[1] = columns.views[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&columns.views, &rows, 2),
    );
    try columns.expectStorageValue(sentinel);
    columns.views[1] = second;

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

    const maximum_aligned = std.math.maxInt(usize) &
        ~(@as(usize, @alignOf(M31)) - 1);
    const invalid: [*]M31 = @ptrFromInt(maximum_aligned);
    columns.views[witness.MAIN_COLUMN_COUNT - 1] = invalid[0..4];
    try std.testing.expectError(
        error.AddressOverflow,
        executor.generateMainInto(&columns.views, &rows, 2),
    );
    try columns.expectStorageValue(sentinel);
}

test "typed BRANCH_LT construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn expectInvalidBinding(
    definition: *const typed.Definition,
    binding: *const witness.WitnessBinding,
) !void {
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(definition, binding),
    );
}

fn expectRowRejected(
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
    var definition = try typed.build(allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    _ = try witness.Executor.init(&definition, &binding);
}
