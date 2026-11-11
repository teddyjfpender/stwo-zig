const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const corpus = @import("../typed_div_corpus.zig");
const legacy = @import("../../../runner/witness/div_legacy_test_oracle.zig");
const typed_div = @import("../typed_div.zig");
const witness = @import("../typed_div_witness.zig");

test "typed DIV witness binding is exact portable and recipe-authenticated" {
    var generated = try typed_div.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var moved = try typed_div.build(std.testing.allocator, .{ .file = .{
        .path = "moved/div.air",
        .start = .{ .byte_offset = 80, .line = 11, .column = 3 },
        .end = .{ .byte_offset = 84, .line = 11, .column = 7 },
    } });
    defer moved.deinit();

    const binding = witness.WitnessBinding.canonical(&generated);
    const moved_binding = witness.WitnessBinding.canonical(&moved);
    const identity = binding.identityDigest();
    try std.testing.expectEqual(witness.WITNESS_BINDING_DIGEST, identity);
    const executor = try witness.Executor.init(&generated, &binding);
    const moved_executor = try witness.Executor.init(&moved, &moved_binding);
    try std.testing.expectEqual(identity, executor.identityDigest());
    try std.testing.expectEqual(identity, moved_executor.identityDigest());
    try std.testing.expect(std.meta.eql(binding, executor.identitySnapshot()));
    for (binding.slots, witness.CANONICAL_RECIPE, 0..) |slot, source, column| {
        try std.testing.expectEqual(column, slot.column);
        try std.testing.expectEqual(column, @intFromEnum(slot.value));
        try std.testing.expectEqual(source, slot.source);
    }
}

test "typed DIV witness rejects every authenticated binding dimension" {
    var definition = try typed_div.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const canonical = witness.WitnessBinding.canonical(&definition);

    var malformed = canonical;
    malformed.format_version +%= 1;
    try expectInvalid(&definition, &malformed);
    malformed = canonical;
    malformed.semantic_format_version +%= 1;
    try expectInvalid(&definition, &malformed);
    malformed = canonical;
    malformed.opcode_ids[2] +%= 1;
    try expectInvalid(&definition, &malformed);
    malformed = canonical;
    malformed.semantic_digest[0] ^= 1;
    try expectInvalid(&definition, &malformed);
    malformed = canonical;
    malformed.hint_recipe_id = @enumFromInt(0);
    try expectInvalid(&definition, &malformed);
    malformed = canonical;
    malformed.hint_recipe_version +%= 1;
    try expectInvalid(&definition, &malformed);
    malformed = canonical;
    malformed.slots[34].column = 35;
    try expectInvalid(&definition, &malformed);
    malformed = canonical;
    malformed.slots[34].value = malformed.slots[35].value;
    try expectInvalid(&definition, &malformed);
    malformed = canonical;
    malformed.slots[34].source = .q_1;
    try expectInvalid(&definition, &malformed);
}

test "typed DIV direct writer is exact over the full pinned 292-row corpus" {
    var actual_storage: [witness.MAIN_COLUMN_COUNT][1]M31 =
        .{.{M31.zero()}} ** witness.MAIN_COLUMN_COUNT;
    var actual: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&actual, &actual_storage) |*column, *storage| column.* = storage;

    for (0..corpus.OPERAND_CLASS_COUNT) |class_index| {
        const operands = corpus.operandClass(class_index);
        for (0..4) |opcode_index| {
            const op = corpus.opcode(opcode_index);
            const case_index = class_index * 4 + opcode_index;
            const row = try corpus.traceRow(op, operands, case_index);
            const expected = try corpus.honestRow(op, operands, case_index);
            witness.writeActiveRow(&actual, 0, row);
            for (actual, expected[0..witness.MAIN_COLUMN_COUNT], 0..) |
                column,
                expected_value,
                column_index,
            | {
                errdefer std.debug.print(
                    "DIV corpus mismatch case={d} column={d}\n",
                    .{ case_index, column_index },
                );
                try std.testing.expectEqual(expected_value, column[0]);
            }
        }
    }
}

test "typed DIV prepared executor validates before mutation and zeroes padding" {
    var definition = try typed_div.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const first = try corpus.traceRow(.DIV, corpus.operandClass(0), 0);
    const second = try corpus.traceRow(.REMU, corpus.operandClass(72), 291);

    var storage: [witness.MAIN_COLUMN_COUNT][4]M31 = undefined;
    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*values, *column| {
        values.* = .{M31.fromCanonical(91)} ** 4;
        column.* = values;
    }
    try executor.generateMainInto(&columns, &.{ first, second }, 2);
    for (columns) |column| {
        try std.testing.expect(column[2].isZero());
        try std.testing.expect(column[3].isZero());
    }

    var invalid = first;
    invalid.opcode = .LUI;
    const snapshot = storage;
    try std.testing.expectError(
        error.InvalidTraceRow,
        executor.generateMainInto(&columns, &.{ first, invalid }, 2),
    );
    try std.testing.expectEqualDeep(snapshot, storage);
}

test "typed DIV writer is the singular production trace authority" {
    const trace_source = @embedFile("../../../runner/trace.zig");
    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".div => DIV_AUTHORITY.writeActiveRow",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".div => typed_div_witness.writeActiveRow",
    ) == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".div => m_extension_witness.div",
    ) == null);
}

fn expectInvalid(
    definition: *const typed_div.Definition,
    binding: *const witness.WitnessBinding,
) !void {
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(definition, binding),
    );
}

pub const OwnedColumns = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    views: [witness.MAIN_COLUMN_COUNT][]M31,

    pub fn init(allocator: std.mem.Allocator, rows: usize) !OwnedColumns {
        const storage = try allocator.alloc(M31, witness.MAIN_COLUMN_COUNT * rows);
        var result = OwnedColumns{
            .allocator = allocator,
            .storage = storage,
            .views = undefined,
        };
        for (&result.views, 0..) |*view, column| {
            view.* = storage[column * rows ..][0..rows];
        }
        return result;
    }

    pub fn deinit(self: *OwnedColumns) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};
