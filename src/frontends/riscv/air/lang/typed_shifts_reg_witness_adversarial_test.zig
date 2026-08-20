const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const support = @import("typed_shifts_reg_witness_test_support.zig");
const typed = @import("typed_shifts_reg.zig");
const witness = @import("typed_shifts_reg_witness.zig");

test "typed SHIFTS_REG rejects every binding identity mutation" {
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
    malformed.operations[0].opcode_id = 99;
    try expectInvalidBinding(&definition, &malformed);
    malformed = canonical;
    malformed.operations[1].flag_column = 35;
    try expectInvalidBinding(&definition, &malformed);
    malformed = canonical;
    malformed.operations[2].algorithm = .rv32_logical_left_low_five;
    try expectInvalidBinding(&definition, &malformed);
}

test "typed SHIFTS_REG authenticates definition before row recipe" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    definition.arena.nodes.items[0].key.ty = .byte;
    try std.testing.expectError(
        error.InvalidInternTable,
        witness.Executor.init(&definition, &binding),
    );
}

test "typed SHIFTS_REG row forgeries reject atomically" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const sentinel = M31.fromCanonical(0x1ace);
    var columns = try support.OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    const valid = support.makeRow(
        .SRA,
        7,
        7,
        7,
        0x9234_5678,
        0,
        20,
        0x1000,
        0,
        0,
        0,
        0,
    );
    var forged = valid;
    forged.opcode = .SLT;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.imm = 1;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.clk = 0;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.next_pc +%= 4;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.is_store = true;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.branch_taken = true;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rd_val ^= 1;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rs1_val ^= 1;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rs2_val ^= 1;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rd_prev_val ^= 1;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rs2_prev_clk -%= 1;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rs1_prev_clk = (valid.clk - 1) * 4 + 1;
    try expectRowRejected(&executor, &columns, forged, sentinel);
}

test "typed SHIFTS_REG validates the complete batch before the first write" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const sentinel = M31.fromCanonical(0x35a1);
    var columns = try support.OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    var rows = [_]witness.TraceRow{
        support.makeRow(.SLL, 3, 4, 5, 0x1020_3040, 7, 20, 0x1000, 0, 0, 0, 0),
        support.makeRow(.SRL, 6, 7, 8, 0x8000_0000, 8, 21, 0x1004, 0, 0, 0, 0),
        support.makeRow(.SRA, 9, 10, 11, 0xffff_ffff, 31, 22, 0x1008, 0, 0, 0, 0),
    };
    rows[1].rd_val ^= 1;
    try std.testing.expectError(
        error.InvalidTraceRow,
        executor.generateMainInto(&columns.views, &rows, 2),
    );
    try columns.expectStorageValue(sentinel);
}

test "typed SHIFTS_REG rejects shapes aliases and address overflow atomically" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const sentinel = M31.fromCanonical(0x2bad);
    var columns = try support.OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    const rows = [_]witness.TraceRow{support.makeRow(
        .SLL,
        1,
        2,
        3,
        4,
        5,
        10,
        0x1000,
        0,
        0,
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

test "typed SHIFTS_REG construction releases every allocation failure" {
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
