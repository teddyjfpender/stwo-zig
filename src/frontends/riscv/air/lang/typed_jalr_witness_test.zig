const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const opcode_entries = @import("../lookups/opcode_entries.zig");
const legacy_oracle = @import("../../runner/witness/jalr_legacy_test_oracle.zig");
const trace_mod = @import("../../runner/trace.zig");
const typed_jalr = @import("typed_jalr.zig");
const witness = @import("typed_jalr_witness.zig");

test "typed JALR witness binding is semantic exact source independent and self-contained" {
    var generated = try typed_jalr.build(std.testing.allocator, .generated);
    var moved = try typed_jalr.build(std.testing.allocator, .{ .file = .{
        .path = "moved/control/jalr.air",
        .start = .{ .byte_offset = 144, .line = 17, .column = 3 },
        .end = .{ .byte_offset = 148, .line = 17, .column = 7 },
    } });
    defer moved.deinit();

    var binding = witness.WitnessBinding.canonical(&generated);
    const executor = try witness.Executor.init(&generated, &binding);
    const moved_binding = witness.WitnessBinding.canonical(&moved);
    const moved_executor = try witness.Executor.init(&moved, &moved_binding);
    try std.testing.expectEqual(
        witness.WITNESS_BINDING_FORMAT_VERSION,
        binding.format_version,
    );
    try std.testing.expectEqual(typed_jalr.OPCODE_ID, binding.opcode_id);
    try std.testing.expectEqual(binding.identityDigest(), executor.identityDigest());
    try std.testing.expectEqual(witness.WITNESS_BINDING_DIGEST, executor.identityDigest());
    try std.testing.expectEqual(executor.identityDigest(), moved_executor.identityDigest());
    try std.testing.expect(std.meta.eql(binding, executor.identitySnapshot()));
    for (binding.slots, witness.CANONICAL_RECIPE, 0..) |slot, recipe, column| {
        try std.testing.expectEqual(column, slot.column);
        try std.testing.expectEqual(column, @intFromEnum(slot.value));
        try std.testing.expectEqual(recipe, slot.source);
    }

    // The executor owns its pointer-free recipe and remains usable after the
    // source binding and the authored arena are gone.
    binding.slots[0].source = .trace_clock;
    generated.deinit();
    var storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*column_storage, *column| column.* = column_storage;
    const row = makeRow(.{
        .rd = 7,
        .rs1 = 5,
        .source = 0x0010_4001,
        .immediate = -1,
        .clock = 9,
        .pc = 0x8abc,
    });
    try executor.generateMainInto(&columns, &.{row}, 0);
    try std.testing.expectEqual(M31.one(), columns[0][0]);
    try std.testing.expectEqual(M31.fromCanonical(7), columns[3][0]);
    try std.testing.expectEqual(M31.fromCanonical(5), columns[13][0]);
    try std.testing.expectEqual(M31.fromCanonical(0x0010_4000 / 2), columns[23][0]);
}

test "typed JALR witness rejects every binding field and slot dimension" {
    var authored = try typed_jalr.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const canonical = witness.WitnessBinding.canonical(&authored);

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

    for (0..witness.MAIN_COLUMN_COUNT) |index| {
        malformed = canonical;
        malformed.slots[index].column = @intCast((index + 1) % witness.MAIN_COLUMN_COUNT);
        try expectInvalidBinding(&authored, &malformed);

        malformed = canonical;
        malformed.slots[index].value = canonical.slots[(index + 1) % witness.MAIN_COLUMN_COUNT].value;
        try expectInvalidBinding(&authored, &malformed);

        malformed = canonical;
        malformed.slots[index].source = @enumFromInt((index + 1) % witness.MAIN_COLUMN_COUNT);
        try expectInvalidBinding(&authored, &malformed);
    }

    // Semantic validation precedes trust in the separately supplied binding.
    var malformed_definition = try typed_jalr.build(std.testing.allocator, .generated);
    defer malformed_definition.deinit();
    const definition_binding = witness.WitnessBinding.canonical(&malformed_definition);
    malformed_definition.arena.nodes.items[0].key.ty = .byte;
    try std.testing.expectError(
        error.InvalidInternTable,
        witness.Executor.init(&malformed_definition, &definition_binding),
    );
}

test "typed JALR witness is exact for every imm12 value and both unaligned low bits" {
    const row_count = 4096 * 2;
    const rows = try std.testing.allocator.alloc(witness.TraceRow, row_count);
    defer std.testing.allocator.free(rows);
    var index: usize = 0;
    for (0..4096) |immediate_index| {
        const immediate: i32 = @as(i32, @intCast(immediate_index)) - 2048;
        const immediate_bits: u32 = @bitCast(immediate);
        for (0..2) |low_bit| {
            const desired_unaligned = @as(u32, 0x0020_0000) + @as(u32, @intCast(low_bit));
            const source = desired_unaligned -% immediate_bits;
            rows[index] = makeRow(.{
                .rd = @intCast(index % 32),
                .rs1 = @intCast(1 + (index % 31)),
                .source = source,
                .immediate = immediate,
                .clock = @intCast(index + 1),
                .pc = @intCast(0x1000 + index * 4),
                .rd_previous = @truncate(index *% 0x9e37_79b9),
                .source_previous_clock = @intCast(index % 3),
                .destination_previous_clock = @intCast(index % 5),
            });
            index += 1;
        }
    }
    try std.testing.expectEqual(row_count, index);

    var authored = try typed_jalr.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    var actual = try OwnedColumns.init(std.testing.allocator, row_count, M31.fromCanonical(0x5151));
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, rows, 13);
    try expectLegacyColumns(rows, 13, &actual.views);

    for (rows, 0..) |row, row_index| {
        const unaligned = row.rs1_val +% @as(u32, @bitCast(row.imm));
        try std.testing.expectEqual(M31.fromU64(unaligned & 1), actual.views[24][row_index]);
        try std.testing.expectEqual(M31.fromU64(@as(u32, @bitCast(row.imm)) & 0xff), actual.views[38][row_index]);
        try std.testing.expectEqual(M31.fromU64((@as(u32, @bitCast(row.imm)) >> 8) & 0xf), actual.views[39][row_index]);
    }
}

test "typed JALR witness is exact at wrap x0 and register-alias boundaries" {
    const cases = [_]RowConfig{
        .{ .rd = 0, .rs1 = 0, .source = 0, .immediate = -2048, .clock = 1, .pc = 0xffff_fffc },
        .{ .rd = 31, .rs1 = 1, .source = 0, .immediate = -1, .clock = 2, .pc = 0xffff_ffff },
        .{ .rd = 1, .rs1 = 1, .source = 0xffff_ffff, .immediate = 1, .clock = 3, .pc = 0xffff_fffe },
        .{ .rd = 7, .rs1 = 7, .source = 0x3fff_fffc, .immediate = 3, .clock = 0x100, .pc = 0x7fff_fffc },
        .{ .rd = 8, .rs1 = 7, .source = 0x3fff_ffff, .immediate = -3, .clock = 0x101, .pc = 0x7fff_ffff },
        .{ .rd = 9, .rs1 = 10, .source = 0x7fff_fffc, .immediate = 2047, .clock = 0xffff, .pc = 0 },
        .{ .rd = 10, .rs1 = 11, .source = 0x8000_0000, .immediate = -2048, .clock = 0x1_0000, .pc = 4 },
    };
    var rows: [cases.len]witness.TraceRow = undefined;
    for (&rows, cases) |*row, config| row.* = makeRow(config);

    var authored = try typed_jalr.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    var actual = try OwnedColumns.init(std.testing.allocator, 8, M31.fromCanonical(0x6161));
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, &rows, 3);
    try expectLegacyColumns(&rows, 3, &actual.views);

    try std.testing.expect(actual.views[30][0].isZero());
    try std.testing.expect(actual.views[31][0].isZero());
    for (4..8) |column| try std.testing.expect(actual.views[column][0].isZero());
    for (9..13) |column| try std.testing.expect(actual.views[column][0].isZero());
    // rd == rs1 consumes the source at phase one, then carries that state into
    // the destination's previous value and clock exactly.
    for ([_]usize{ 2, 3 }) |row_index| {
        for (0..4) |limb| {
            try std.testing.expectEqual(
                actual.views[19 + limb][row_index],
                actual.views[4 + limb][row_index],
            );
        }
        const expected_clock = (rows[row_index].clk - 1) * 4 + 1;
        try std.testing.expectEqual(M31.fromU64(expected_clock), actual.views[8][row_index]);
    }
    for (actual.views) |column| try std.testing.expect(column[rows.len].isZero());
}

test "typed JALR witness rows and ordered lookup effects match the legacy authority" {
    var prng = std.Random.DefaultPrng.init(0x4a41_4c52_2d45_4646);
    const random = prng.random();
    var rows: [96]witness.TraceRow = undefined;
    for (&rows, 0..) |*row, index| {
        const immediate = @as(i32, random.intRangeAtMost(i16, -2048, 2047));
        row.* = makeRow(.{
            .rd = random.int(u5),
            .rs1 = @intCast(1 + random.uintLessThan(u5, 31)),
            .source = random.int(u32),
            .immediate = immediate,
            .clock = @intCast(index + 1),
            .pc = random.int(u32),
            .rd_previous = random.int(u32),
            .source_previous_clock = random.int(u16),
            .destination_previous_clock = random.int(u16),
        });
    }

    var authored = try typed_jalr.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    var actual = try OwnedColumns.init(std.testing.allocator, 128, M31.fromCanonical(0x6262));
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, &rows, 7);
    try expectLegacyColumns(&rows, 7, &actual.views);

    var legacy = try OwnedColumns.init(std.testing.allocator, 128, M31.zero());
    defer legacy.deinit();
    for (rows, 0..) |row, row_index| legacy_oracle.writeRow(&legacy.views, row_index, row);
    for (0..rows.len) |row_index| {
        var actual_main: [witness.MAIN_COLUMN_COUNT]QM31 = undefined;
        var legacy_main: [witness.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&actual_main, &legacy_main, actual.views, legacy.views) |
            *actual_value,
            *legacy_value,
            actual_column,
            legacy_column,
        | {
            actual_value.* = QM31.fromBase(actual_column[row_index]);
            legacy_value.* = QM31.fromBase(legacy_column[row_index]);
        }
        const actual_effects = try opcode_entries.fromMain(.jalr, &actual_main);
        const legacy_effects = try opcode_entries.fromMain(.jalr, &legacy_main);
        try expectExactEntries(&legacy_effects, &actual_effects);
    }
}

test "typed JALR production authority is singular and allocation-free by construction" {
    const trace_source = @embedFile("../../runner/trace.zig");
    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".jalr => JALR_AUTHORITY.writeActiveRow",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".jalr => typed_jalr_witness.writeActiveRow",
    ) == null);
    try std.testing.expect(std.mem.indexOf(u8, trace_source, "control_witness.jalr") == null);

    var production_storage: [trace_mod.MAX_FAMILY_COLUMNS][16]M31 = undefined;
    var production: [trace_mod.MAX_FAMILY_COLUMNS][]M31 = undefined;
    for (&production, &production_storage) |*column, *storage| column.* = storage;
    var legacy_storage: [witness.MAIN_COLUMN_COUNT][16]M31 = undefined;
    var legacy: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&legacy, &legacy_storage) |*column, *storage| column.* = storage;
    for (0..16) |index| {
        const pc: u32 = @intCast(0x1000 + index * 4);
        const immediate: i32 = @intCast(@as(i32, @intCast(index)) - 8);
        const source = pc +% 4 -% @as(u32, @bitCast(immediate));
        const row = makeRow(.{
            .rd = @intCast(index),
            .rs1 = @intCast(1 + index),
            .source = source,
            .immediate = immediate,
            .clock = @intCast(index + 1),
            .pc = pc,
            .rd_previous = @truncate(index *% 0x1122_3344),
        });
        trace_mod.fillFamilyColumns(&production, index, row, .jalr);
        legacy_oracle.writeRow(&legacy, index, row);
    }
    for (production[0..witness.MAIN_COLUMN_COUNT], legacy) |actual, expected| {
        try std.testing.expectEqualSlices(M31, expected, actual);
    }
}

test "typed JALR authority hot rows retain paired legacy throughput and scaling" {
    if (builtin.mode != .ReleaseFast) return;

    const allocator = std.testing.allocator;
    const log_rows = [_]u32{ 10, 14, 18 };
    const row_count: usize = @as(usize, 1) << log_rows[log_rows.len - 1];
    const rows = try allocator.alloc(witness.TraceRow, row_count);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| {
        row.* = makeRow(.{
            .rd = @intCast(index % 32),
            .rs1 = @intCast(1 + (index % 31)),
            .source = @truncate(index *% 0x9e37_79b9),
            .immediate = @as(i32, @intCast(index & 0xfff)) - 2048,
            .clock = @intCast(index + 1),
            .pc = @truncate(0x1000 +% index *% 4),
            .rd_previous = @truncate(index *% 0x0101_0101),
            .source_previous_clock = @intCast(index % 3),
            .destination_previous_clock = @intCast(index % 5),
        });
    }
    var columns = try OwnedColumns.init(allocator, row_count, M31.zero());
    defer columns.deinit();

    for (rows, 0..) |row, index| witness.writeActiveRow(&columns.views, index, row);
    consumeColumns(&columns.views, rows.len);
    for (rows, 0..) |row, index| legacy_oracle.writeRow(&columns.views, index, row);
    consumeColumns(&columns.views, rows.len);

    var generated_medians: [log_rows.len]u64 = undefined;
    for (log_rows, 0..) |log_size, case_index| {
        const active = rows[0..(@as(usize, 1) << @intCast(log_size))];
        var generated_times: [nine_samples]u64 = undefined;
        var legacy_times: [nine_samples]u64 = undefined;
        for (0..nine_samples) |sample| {
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
        const generated_median = generated_times[nine_samples / 2];
        const legacy_median = legacy_times[nine_samples / 2];
        generated_medians[case_index] = generated_median;
        std.debug.print(
            "\n  typed JALR authority log_rows={d}: generated={d} ns " ++
                "legacy={d} ns median_speed={d:.4}x\n",
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
    for (1..generated_medians.len) |index| {
        try std.testing.expect(
            generated_medians[index] * 10 <= generated_medians[index - 1] * 176,
        );
    }
}

test "typed JALR witness rejects shapes opcodes and overflow before mutation" {
    var authored = try typed_jalr.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    const sentinel = M31.fromCanonical(0x1ace);
    var columns = try OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    var rows = [_]witness.TraceRow{
        makeRow(.{ .rd = 1, .rs1 = 2, .source = 4, .immediate = 0, .clock = 1 }),
        makeRow(.{ .rd = 2, .rs1 = 3, .source = 8, .immediate = 1, .clock = 2 }),
        makeRow(.{ .rd = 3, .rs1 = 4, .source = 12, .immediate = -1, .clock = 3 }),
        makeRow(.{ .rd = 4, .rs1 = 5, .source = 16, .immediate = 2, .clock = 4 }),
        makeRow(.{ .rd = 5, .rs1 = 6, .source = 20, .immediate = -2, .clock = 5 }),
    };

    const original_last = columns.views[witness.MAIN_COLUMN_COUNT - 1];
    columns.views[witness.MAIN_COLUMN_COUNT - 1] = original_last[0..3];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, rows[0..1], 2),
    );
    try columns.expectStorageValue(sentinel);
    columns.views[witness.MAIN_COLUMN_COUNT - 1] = original_last;

    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, &rows, 2),
    );
    try columns.expectStorageValue(sentinel);
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, rows[0..1], @bitSizeOf(usize)),
    );
    try columns.expectStorageValue(sentinel);

    rows[0].opcode = .JAL;
    try std.testing.expectError(
        error.InvalidTraceRow,
        executor.generateMainInto(&columns.views, rows[0..1], 2),
    );
    try columns.expectStorageValue(sentinel);
    rows[0].opcode = .JALR;

    const maximum_aligned = std.math.maxInt(usize) &
        ~(@as(usize, @alignOf(M31)) - 1);
    const invalid: [*]M31 = @ptrFromInt(maximum_aligned);
    columns.views[witness.MAIN_COLUMN_COUNT - 1] = invalid[0..4];
    try std.testing.expectError(
        error.AddressOverflow,
        executor.generateMainInto(&columns.views, rows[0..1], 2),
    );
    try columns.expectStorageValue(sentinel);
}

test "typed JALR witness rejects destination and input aliases before mutation" {
    var authored = try typed_jalr.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    const sentinel = M31.fromCanonical(0x2bad);
    var columns = try OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    const rows = [_]witness.TraceRow{makeRow(.{
        .rd = 3,
        .rs1 = 2,
        .source = 0x1234,
        .immediate = -4,
        .clock = 1,
    })};

    const original_second = columns.views[1];
    columns.views[1] = columns.views[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&columns.views, &rows, 2),
    );
    try columns.expectStorageValue(sentinel);
    columns.views[1] = original_second;

    var overlapping = [_]M31{sentinel} ** 5;
    const original_first = columns.views[0];
    columns.views[0] = overlapping[0..4];
    columns.views[1] = overlapping[1..5];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&columns.views, &rows, 2),
    );
    try std.testing.expectEqualSlices(M31, &([_]M31{sentinel} ** 5), &overlapping);
    try columns.expectStorageValue(sentinel);
    columns.views[0] = original_first;
    columns.views[1] = original_second;

    var aliased = try OwnedColumns.init(std.testing.allocator, 64, sentinel);
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

test "typed JALR witness preserves guards and zeroes only final padding" {
    var authored = try typed_jalr.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = witness.WitnessBinding.canonical(&authored);
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
        makeRow(.{ .rd = 0, .rs1 = 0, .source = 0, .immediate = 0, .clock = 1 }),
        makeRow(.{ .rd = 1, .rs1 = 1, .source = 0x3fff_fffc, .immediate = 3, .clock = 2 }),
        makeRow(.{ .rd = 31, .rs1 = 30, .source = 0x0123_4567, .immediate = -7, .clock = 3 }),
    };
    try executor.generateMainInto(&columns, &rows, 3);
    try expectLegacyColumns(&rows, 3, &columns);
    for (guarded, columns) |storage, column| {
        try std.testing.expectEqual(guard, storage[0]);
        try std.testing.expectEqual(guard, storage[9]);
        for (column[rows.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}

test "typed JALR witness construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

const nine_samples: usize = 9;

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
    for (rows, 0..) |row, index| legacy_oracle.writeRow(columns, index, row);
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

fn expectInvalidBinding(
    definition: *const typed_jalr.Definition,
    binding: *const witness.WitnessBinding,
) !void {
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(definition, binding),
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var authored = try typed_jalr.build(allocator, .generated);
    defer authored.deinit();
    const binding = witness.WitnessBinding.canonical(&authored);
    _ = try witness.Executor.init(&authored, &binding);
}

fn expectLegacyColumns(
    rows: []const witness.TraceRow,
    log_size: u32,
    actual: *const [witness.MAIN_COLUMN_COUNT][]M31,
) !void {
    const domain_size = @as(usize, 1) << @intCast(log_size);
    try std.testing.expect(rows.len <= domain_size);
    var expected = try OwnedColumns.init(std.testing.allocator, domain_size, M31.zero());
    defer expected.deinit();
    for (rows, 0..) |row, logical_row| {
        legacy_oracle.writeRow(&expected.views, logical_row, row);
    }
    for (actual, expected.views) |actual_column, expected_column| {
        try std.testing.expectEqualSlices(
            u8,
            std.mem.sliceAsBytes(expected_column),
            std.mem.sliceAsBytes(actual_column),
        );
    }
}

fn expectExactEntries(expected: *const opcode_entries.List, actual: *const opcode_entries.List) !void {
    try std.testing.expectEqual(@as(usize, typed_jalr.LOOKUP_COUNT), actual.len);
    try std.testing.expectEqual(expected.len, actual.len);
    try std.testing.expectEqual(expected.batch_size, actual.batch_size);
    for (expected.entries[0..expected.len], actual.entries[0..actual.len]) |want, got| {
        try std.testing.expectEqual(want.domain, got.domain);
        try std.testing.expect(want.numerator.eql(got.numerator));
        try std.testing.expectEqual(want.arity, got.arity);
        try std.testing.expectEqual(want.role, got.role);
        try std.testing.expectEqual(want.access_ordinal, got.access_ordinal);
        for (want.values[0..want.arity], got.values[0..got.arity]) |want_value, got_value| {
            try std.testing.expect(want_value.eql(got_value));
        }
    }
}

const RowConfig = struct {
    rd: u5,
    rs1: u5,
    source: u32,
    immediate: i32,
    clock: u32,
    pc: u32 = 0x1000,
    rd_previous: u32 = 0x1122_3344,
    source_previous_clock: u32 = 0,
    destination_previous_clock: u32 = 0,
};

fn makeRow(config: RowConfig) witness.TraceRow {
    std.debug.assert(config.immediate >= -2048 and config.immediate <= 2047);
    std.debug.assert(config.clock != 0);
    const source = if (config.rs1 == 0) 0 else config.source;
    const source_access_clock = (config.clock - 1) *% 4 +% 1;
    const link = config.pc +% 4;
    const target = (source +% @as(u32, @bitCast(config.immediate))) & ~@as(u32, 1);
    return .{
        .clk = config.clock,
        .pc = config.pc,
        .opcode = .JALR,
        .rd = config.rd,
        .rs1 = config.rs1,
        .rs2 = 0,
        .imm = config.immediate,
        .rs1_val = source,
        .rs2_val = 0,
        .rs1_prev_clk = config.source_previous_clock,
        .rs2_prev_clk = 0,
        .rd_prev_val = if (config.rd == 0)
            0
        else if (config.rd == config.rs1)
            source
        else
            config.rd_previous,
        .rd_prev_clk = if (config.rd == config.rs1)
            source_access_clock
        else
            config.destination_previous_clock,
        .rd_val = if (config.rd == 0) 0 else link,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = target != link,
        .next_pc = target,
        .inst_word = 0,
    };
}

const OwnedColumns = struct {
    allocator: std.mem.Allocator,
    storage: [witness.MAIN_COLUMN_COUNT][]M31,
    views: [witness.MAIN_COLUMN_COUNT][]M31,

    fn init(
        allocator: std.mem.Allocator,
        len: usize,
        initial: M31,
    ) !OwnedColumns {
        var storage: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
        var views: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
        var initialized: usize = 0;
        errdefer for (storage[0..initialized]) |column| allocator.free(column);
        for (&storage, &views) |*owned, *view| {
            owned.* = try allocator.alloc(M31, len);
            initialized += 1;
            @memset(owned.*, initial);
            view.* = owned.*;
        }
        return .{ .allocator = allocator, .storage = storage, .views = views };
    }

    fn deinit(self: *OwnedColumns) void {
        for (self.storage) |column| self.allocator.free(column);
        self.* = undefined;
    }

    fn expectStorageValue(self: *const OwnedColumns, expected: M31) !void {
        for (self.storage) |column| {
            for (column) |actual| try std.testing.expectEqual(expected, actual);
        }
    }
};
