const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const hint_recipe = @import("hint_recipe.zig");
const relation = @import("relation.zig");
const support = @import("typed_addi_witness_test_support.zig");
const typed_addi = @import("typed_addi.zig");
const witness = @import("typed_addi_witness.zig");

test "typed ADDI witness rejects every binding carry hint source and event mutation" {
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
    malformed.slots[13].source = .trace_rs1_value_previous_byte_1;
    try expectInvalidBinding(&authored, &malformed);

    malformed = canonical;
    malformed.arithmetic.lhs = .trace_signed_immediate;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.arithmetic.first_result_column = 28;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.arithmetic.result_limb_count = 3;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.arithmetic.carry_policy = .external_committed_carries;
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
    malformed.destination_hint.output_count = 1;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.destination_hint.input_column = 12;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.destination_hint.inverse_output_column = 33;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.destination_hint.nonzero_output_column = 34;
    try expectInvalidBinding(&authored, &malformed);

    malformed = canonical;
    malformed.events[4].effect = malformed.events[5].effect;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.events[4].kind = .register_write;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.events[4].schema = relation.id(.program_access);
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.events[4].role = .emit;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.events[4].liveness = malformed.events[7].liveness;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.events[4].values[3] = malformed.events[4].values[4];
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.events[4].access_ordinal = 2;
    try expectInvalidBinding(&authored, &malformed);
    malformed = canonical;
    malformed.events[4].values[6] = @enumFromInt(std.math.maxInt(u32));
    try expectInvalidBinding(&authored, &malformed);
}

test "typed ADDI witness rejects forged carries and source rows before mutation" {
    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    const sentinel = M31.fromCanonical(0x1ace);
    var columns = try support.OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();

    const honest_carry = support.makeRow(3, 5, 0x0000_00ff, 1, 2, 0x1000, 7, 0, 0);
    var forged = honest_carry;
    forged.rd_val = 0;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);

    forged = honest_carry;
    forged.imm = 2048;
    forged.rd_val = forged.rs1_val +% @as(u32, @bitCast(forged.imm));
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);

    forged = support.makeRow(3, 0, 0, 1, 2, 0x1000, 7, 0, 0);
    forged.rs1_val = 1;
    forged.rd_val = 2;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);

    forged = support.makeRow(5, 5, 41, 1, 2, 0x1000, 0, 0, 0);
    forged.rd_prev_val = 42;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = support.makeRow(5, 5, 41, 1, 2, 0x1000, 0, 0, 0);
    forged.rd_prev_clk = 0;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);

    forged = honest_carry;
    forged.rs1_prev_clk = 5;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
    forged = honest_carry;
    forged.next_pc +%= 4;
    try expectInvalidRowAtomic(&executor, &columns, forged, sentinel);
}

test "typed ADDI witness shape and alias failures are deterministic and atomic" {
    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    const sentinel = M31.fromCanonical(0x2bad);
    var columns = try support.OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    const row = support.makeRow(3, 5, 41, 1, 1, 0x1000, 0, 0, 0);

    const original_last = columns.views[34];
    columns.views[34] = original_last[0..3];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, &.{row}, 2),
    );
    try columns.expectStorageValue(sentinel);
    columns.views[34] = original_last;

    const original_second = columns.views[1];
    columns.views[1] = columns.views[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&columns.views, &.{row}, 2),
    );
    try columns.expectStorageValue(sentinel);
    columns.views[1] = original_second;

    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, &.{row}, @bitSizeOf(usize)),
    );
    try columns.expectStorageValue(sentinel);
}

test "typed ADDI witness construction releases every allocation failure" {
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
    try std.testing.expectError(error.InvalidTraceRow, executor.generateRelationRow(row));
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var authored = try typed_addi.build(allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    _ = try witness.Executor.init(&authored, &binding);
}
