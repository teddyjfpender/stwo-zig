const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const support = @import("typed_base_alu_imm_witness_test_support.zig");
const typed_addi = @import("typed_addi.zig");
const witness = @import("typed_base_alu_imm_witness.zig");

test "typed BASE_ALU_IMM rejects every family binding identity mutation" {
    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const canonical = try witness.WitnessBinding.canonical(&authored);
    var malformed = canonical;

    malformed.format_version +%= 1;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.semantic_format_version +%= 1;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.semantic_digest[0] ^= 1;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.typed_definition_binding_digest[0] ^= 1;
    try expectInvalidBinding(&authored, &malformed);

    malformed = canonical;
    malformed.slots[0].column = 1;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.slots[0].value = malformed.slots[1].value;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.slots[0].source = .trace_pc;
    try expectInvalidBinding(&authored, &malformed);

    malformed = canonical;
    malformed.operations[0].opcode_id = 11;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.operations[1].flag_column = 27;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.operations[2].result = .rv32_bitwise_and_signed_imm12;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.operations[3].bitwise_active = false;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.operations[1].bitwise_operation_id = 1;
    try expectInvalidBinding(&authored, &malformed);
}

test "typed BASE_ALU_IMM authenticates the typed definition before its recipe" {
    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    authored.arena.nodes.items[0].key.ty = .byte;
    try std.testing.expectError(
        error.InvalidInternTable,
        witness.Executor.init(&authored, &binding),
    );
}

test "typed BASE_ALU_IMM row forgeries reject atomically before any write" {
    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    const sentinel = M31.fromCanonical(0x1ace);
    var columns = try support.OwnedColumns.init(
        std.testing.allocator,
        4,
        sentinel,
    );
    defer columns.deinit();
    const valid = support.makeRow(
        .XORI,
        7,
        7,
        0x1234_5678,
        -1,
        20,
        0x1000,
        0,
        0,
        0,
    );

    var forged = valid;
    forged.opcode = .SLTI;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.imm = 2048;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.clk = 0;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.next_pc +%= 4;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.is_load = true;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.branch_taken = true;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rd_val ^= 1;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rs1 = 0;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rd_prev_val ^= 1;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rd_prev_clk -%= 1;
    try expectRowRejected(&executor, &columns, forged, sentinel);
    forged = valid;
    forged.rs1_prev_clk = (valid.clk - 1) * 4 + 1;
    try expectRowRejected(&executor, &columns, forged, sentinel);
}

test "typed BASE_ALU_IMM rejects shapes aliases and address overflow atomically" {
    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    const sentinel = M31.fromCanonical(0x2bad);
    var columns = try support.OwnedColumns.init(
        std.testing.allocator,
        4,
        sentinel,
    );
    defer columns.deinit();
    const rows = [_]witness.TraceRow{
        support.makeRow(.ADDI, 1, 2, 3, 4, 10, 0x1000, 0, 0, 0),
    };

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

test "typed BASE_ALU_IMM construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn expectInvalidBinding(
    definition: *const typed_addi.Definition,
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
    var authored = try typed_addi.build(allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    _ = try witness.Executor.init(&authored, &binding);
}
