const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const corpus = @import("typed_div_corpus.zig");
const legacy = @import("../../runner/witness/div_legacy_test_oracle.zig");
const typed_div = @import("typed_div.zig");
const witness = @import("typed_div_witness.zig");

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
    const trace_source = @embedFile("../../runner/trace.zig");
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

test "typed DIV hot rows retain paired legacy throughput and scaling" {
    if (builtin.mode != .ReleaseFast) return;

    const allocator = std.testing.allocator;
    const log_rows = [_]u32{ 10, 14, 18 };
    const max_rows = @as(usize, 1) << log_rows[log_rows.len - 1];
    const rows = try allocator.alloc(witness.TraceRow, max_rows);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| {
        const case_index = index % corpus.CORPUS_ROW_COUNT;
        row.* = try corpus.traceRow(
            corpus.opcode(case_index & 3),
            corpus.operandClass(case_index / 4),
            case_index,
        );
    }
    var columns = try OwnedColumns.init(allocator, max_rows);
    defer columns.deinit();

    for (rows, 0..) |row, index| witness.writeActiveRow(&columns.views, index, row);
    consumeColumns(&columns.views, rows.len);
    for (rows, 0..) |row, index| legacy.writeRow(&columns.views, index, row);
    consumeColumns(&columns.views, rows.len);

    var generated_medians: [log_rows.len]u64 = undefined;
    for (log_rows, 0..) |log_size, case_index| {
        const active = rows[0..(@as(usize, 1) << @intCast(log_size))];
        var generated_times: [9]u64 = undefined;
        var legacy_times: [9]u64 = undefined;
        for (0..9) |sample| {
            if ((sample & 1) == 0) {
                generated_times[sample] = try measureGenerated(&columns.views, active);
                legacy_times[sample] = try measureLegacy(&columns.views, active);
            } else {
                legacy_times[sample] = try measureLegacy(&columns.views, active);
                generated_times[sample] = try measureGenerated(&columns.views, active);
            }
        }
        std.mem.sort(u64, &generated_times, {}, std.sort.asc(u64));
        std.mem.sort(u64, &legacy_times, {}, std.sort.asc(u64));
        const generated_median = generated_times[4];
        const legacy_median = legacy_times[4];
        generated_medians[case_index] = generated_median;
        std.debug.print(
            "\n  typed DIV log_rows={d}: generated={d} ns legacy={d} ns " ++
                "median_speed={d:.4}x\n",
            .{
                log_size,
                generated_median,
                legacy_median,
                @as(f64, @floatFromInt(legacy_median)) /
                    @as(f64, @floatFromInt(generated_median)),
            },
        );
        try std.testing.expect(generated_median * 97 <= legacy_median * 100);
    }
    for (1..generated_medians.len) |index| try std.testing.expect(
        generated_medians[index] * 10 <= generated_medians[index - 1] * 176,
    );
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

const OwnedColumns = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    views: [witness.MAIN_COLUMN_COUNT][]M31,

    fn init(allocator: std.mem.Allocator, rows: usize) !OwnedColumns {
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

    fn deinit(self: *OwnedColumns) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};

fn measureGenerated(
    columns: *[witness.MAIN_COLUMN_COUNT][]M31,
    rows: []const witness.TraceRow,
) !u64 {
    var timer = try std.time.Timer.start();
    for (rows, 0..) |row, index| witness.writeActiveRow(columns, index, row);
    const elapsed = timer.read();
    consumeColumns(columns, rows.len);
    return elapsed;
}

fn measureLegacy(
    columns: *[witness.MAIN_COLUMN_COUNT][]M31,
    rows: []const witness.TraceRow,
) !u64 {
    var timer = try std.time.Timer.start();
    for (rows, 0..) |row, index| legacy.writeRow(columns, index, row);
    const elapsed = timer.read();
    consumeColumns(columns, rows.len);
    return elapsed;
}

fn consumeColumns(
    columns: *const [witness.MAIN_COLUMN_COUNT][]M31,
    active_rows: usize,
) void {
    var checksum: u64 = 0;
    for (columns) |column| {
        for (column[0..active_rows]) |value| checksum +%= value.v;
    }
    std.mem.doNotOptimizeAway(&checksum);
}
