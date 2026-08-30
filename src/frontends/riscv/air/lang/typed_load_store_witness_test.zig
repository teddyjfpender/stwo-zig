const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const Opcode = @import("../../runner/decode.zig").Opcode;
const legacy = @import("../../runner/witness/load_store_legacy_test_oracle.zig");
const typed = @import("typed_load_store.zig");
const witness = @import("typed_load_store_witness.zig");

const opcodes = [_]Opcode{ .LB, .LH, .LBU, .LHU, .LW, .SB, .SH, .SW };
const values = [_]u32{
    0,           1,           0x7f,        0x80,        0xff, 0x7fff, 0x8000, 0xffff,
    0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 0x1122_3344,
};

test "typed load/store witness binding is exact and source-independent" {
    var generated = try typed.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var moved = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "moved/load_store.air",
        .start = .{ .byte_offset = 12, .line = 3, .column = 2 },
        .end = .{ .byte_offset = 18, .line = 3, .column = 8 },
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
    for (binding.slots, witness.CANONICAL_RECIPE, 0..) |slot, source, column| {
        try std.testing.expectEqual(column, slot.column);
        try std.testing.expectEqual(column, @intFromEnum(slot.value));
        try std.testing.expectEqual(source, slot.source);
    }
}

test "typed load/store witness rejects every binding dimension" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const canonical = witness.WitnessBinding.canonical(&definition);
    var malformed = canonical;
    malformed.format_version +%= 1;
    try expectInvalid(&definition, &malformed);
    malformed = canonical;
    malformed.semantic_format_version +%= 1;
    try expectInvalid(&definition, &malformed);
    malformed = canonical;
    malformed.opcode_ids[7] +%= 1;
    try expectInvalid(&definition, &malformed);
    malformed = canonical;
    malformed.semantic_digest[0] ^= 1;
    try expectInvalid(&definition, &malformed);
    malformed = canonical;
    malformed.slots[18].column = 19;
    try expectInvalid(&definition, &malformed);
    malformed = canonical;
    malformed.slots[18].value = malformed.slots[19].value;
    try expectInvalid(&definition, &malformed);
    malformed = canonical;
    malformed.slots[18].source = .src_prev_0;
    try expectInvalid(&definition, &malformed);
}

test "typed load/store direct writer matches every legacy cell over boundary corpus" {
    var typed_storage: [witness.MAIN_COLUMN_COUNT][1]M31 =
        .{.{M31.zero()}} ** witness.MAIN_COLUMN_COUNT;
    var legacy_storage: [witness.MAIN_COLUMN_COUNT][1]M31 =
        .{.{M31.zero()}} ** witness.MAIN_COLUMN_COUNT;
    var typed_columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    var legacy_columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&typed_columns, &typed_storage) |*column, *storage| column.* = storage;
    for (&legacy_columns, &legacy_storage) |*column, *storage| column.* = storage;

    var case_index: usize = 0;
    for (opcodes) |opcode| {
        for (0..4) |offset| {
            for (values) |value| {
                const row = makeRow(opcode, @intCast(offset), value, case_index);
                witness.writeActiveRow(&typed_columns, 0, row);
                legacy.writeRow(&legacy_columns, 0, row);
                for (
                    typed_columns[0..48],
                    legacy_columns[0..48],
                    0..,
                ) |actual, expected, column| {
                    errdefer std.debug.print(
                        "load/store mismatch case={d} opcode={s} column={d}\n",
                        .{ case_index, @tagName(opcode), column },
                    );
                    try std.testing.expectEqual(expected[0], actual[0]);
                }
                const word_index = (row.mem_addr & ~@as(u32, 3)) >> 2;
                try std.testing.expectEqual(
                    M31.fromCanonical(word_index),
                    typed_columns[48][0],
                );
                try std.testing.expectEqual(
                    M31.fromCanonical(word_index & ((1 << 20) - 1)),
                    typed_columns[49][0],
                );
                case_index += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 384), case_index);
}

test "typed load/store executor validates role flags before mutation and clears padding" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const first = makeRow(.LB, 3, 0x80, 0);
    const second = makeRow(.SW, 0, 0xdead_beef, 1);
    var storage: [witness.MAIN_COLUMN_COUNT][4]M31 = undefined;
    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*values_out, *column| {
        values_out.* = .{M31.fromCanonical(77)} ** 4;
        column.* = values_out;
    }
    try executor.generateMainInto(&columns, &.{ first, second }, 2);
    for (columns) |column| {
        try std.testing.expect(column[2].isZero());
        try std.testing.expect(column[3].isZero());
    }
    var invalid = first;
    invalid.is_store = true;
    const before = storage;
    try std.testing.expectError(
        error.InvalidTraceRow,
        executor.generateMainInto(&columns, &.{ first, invalid }, 2),
    );
    try std.testing.expectEqualDeep(before, storage);
}

test "typed load/store writer is the singular production trace authority" {
    const trace_source = @embedFile("../../runner/trace.zig");
    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".load_store => LOAD_STORE_AUTHORITY.writeActiveRow",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".load_store => typed_load_store_witness.writeActiveRow",
    ) == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        "load_store_witness.fill",
    ) == null);
}

test "typed load/store hot rows retain paired legacy throughput and scaling" {
    if (builtin.mode != .ReleaseFast) return;

    const allocator = std.testing.allocator;
    const log_rows = [_]u32{ 10, 14, 18 };
    const max_rows = @as(usize, 1) << log_rows[log_rows.len - 1];
    const rows = try allocator.alloc(witness.TraceRow, max_rows);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| {
        row.* = makeRow(
            opcodes[index % opcodes.len],
            @intCast(index & 3),
            @truncate(index *% 0x9e37_79b9),
            index,
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
            "\n  typed load/store log_rows={d}: generated={d} ns legacy={d} ns " ++
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

fn makeRow(opcode: Opcode, offset: u2, value: u32, index: usize) witness.TraceRow {
    const is_load = switch (opcode) {
        .LB, .LH, .LBU, .LHU, .LW => true,
        else => false,
    };
    const rd: u5 = if (index % 11 == 0) 0 else if (index % 7 == 0) 5 else 10;
    const rs1: u5 = 5;
    const rs2: u5 = if (index % 13 == 0) rd else 6;
    const result = switch (opcode) {
        .LB => @as(u32, @bitCast(@as(i32, @as(i8, @bitCast(@as(u8, @truncate(value))))))),
        .LH => @as(u32, @bitCast(@as(i32, @as(i16, @bitCast(@as(u16, @truncate(value))))))),
        .LBU, .LHU, .LW => value,
        else => 0,
    };
    return .{
        .clk = @intCast(index + 9),
        .pc = @intCast(0x1000 + index * 4),
        .opcode = opcode,
        .rd = rd,
        .rs1 = rs1,
        .rs2 = rs2,
        .imm = switch (index % 4) {
            0 => -2048,
            1 => -1,
            2 => 0,
            else => 2047,
        },
        .rs1_val = 0x2000,
        .rs2_val = value,
        .rs1_prev_clk = 2,
        .rs2_prev_clk = 3,
        .rd_prev_val = if (rd == rs1) 0x2000 else 0x5566_7788,
        .rd_prev_clk = 4,
        .rd_val = if (is_load and rd != 0) result else 0,
        .mem_addr = 0x3000 + @as(u32, offset),
        .mem_val = value,
        .mem_prev_word = 0xa1b2_c3d4,
        .mem_next_word = if (is_load) 0xa1b2_c3d4 else value,
        .mem_prev_clk = 5,
        .is_load = is_load,
        .is_store = !is_load,
        .branch_taken = false,
        .next_pc = @intCast(0x1004 + index * 4),
    };
}

fn expectInvalid(
    definition: *const typed.Definition,
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
