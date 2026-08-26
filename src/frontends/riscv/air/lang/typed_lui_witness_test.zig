const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy_oracle = @import("../../runner/witness/lui_legacy_test_oracle.zig");
const trace_mod = @import("../../runner/trace.zig");
const typed_lui = @import("typed_lui.zig");
const witness = @import("typed_lui_witness.zig");

test "typed LUI witness binding is exact source-independent and self-contained" {
    var generated = try typed_lui.build(std.testing.allocator, .generated);
    var moved = try typed_lui.build(std.testing.allocator, .{ .file = .{
        .path = "moved/lui.air",
        .start = .{ .byte_offset = 72, .line = 9, .column = 1 },
        .end = .{ .byte_offset = 76, .line = 9, .column = 5 },
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
    try std.testing.expectEqual(typed_lui.OPCODE_ID, binding.opcode_id);
    try std.testing.expectEqual(binding.identityDigest(), executor.identityDigest());
    try std.testing.expectEqual(witness.WITNESS_BINDING_DIGEST, executor.identityDigest());
    try std.testing.expectEqual(executor.identityDigest(), moved_executor.identityDigest());
    try std.testing.expect(std.meta.eql(binding, executor.identitySnapshot()));
    for (binding.slots, witness.CANONICAL_RECIPE, 0..) |slot, recipe, column| {
        try std.testing.expectEqual(column, slot.column);
        try std.testing.expectEqual(column, @intFromEnum(slot.value));
        try std.testing.expectEqual(recipe, slot.source);
    }

    // The executor owns the authenticated fixed-size identity, not this
    // binding or the arena from which it was constructed.
    binding.slots[0].source = .trace_clock;
    generated.deinit();
    var storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*column_storage, *column| {
        column.* = column_storage;
    }
    const row = makeRow(5, 0x8abcd, 7, 0x1040, 0x4433_2211, 3);
    try executor.generateMainInto(&columns, &.{row}, 0);
    try std.testing.expectEqual(M31.one(), columns[0][0]);
    try std.testing.expectEqual(M31.fromCanonical(5), columns[3][0]);
    try std.testing.expectEqual(M31.fromCanonical(0xd), columns[13][0]);
}

test "typed LUI witness rejects every malformed binding dimension" {
    var authored = try typed_lui.build(std.testing.allocator, .generated);
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

    malformed = canonical;
    malformed.slots[4].column = 5;
    try expectInvalidBinding(&authored, &malformed);

    malformed = canonical;
    malformed.slots[4].value = malformed.slots[5].value;
    try expectInvalidBinding(&authored, &malformed);

    malformed = canonical;
    malformed.slots[4].source = .trace_rd_previous_byte_1;
    try expectInvalidBinding(&authored, &malformed);

    // Definition validation runs before the supplied binding is trusted. The
    // explicit physical type checks in the witness boundary are an additional
    // defence, not a replacement for semantic identity.
    var malformed_definition = try typed_lui.build(std.testing.allocator, .generated);
    defer malformed_definition.deinit();
    const definition_binding = witness.WitnessBinding.canonical(&malformed_definition);
    malformed_definition.arena.nodes.items[0].key.ty = .byte;
    try std.testing.expectError(
        error.InvalidInternTable,
        witness.Executor.init(&malformed_definition, &definition_binding),
    );
}

test "typed LUI witness is production-exact at immediate destination and chain boundaries" {
    const immediate_boundaries = [_]u32{
        0,
        1,
        0xf,
        0x10,
        0xff,
        0x100,
        0xfff,
        0x1000,
        0x7ffff,
        0x80000,
        0xffffe,
        0xfffff,
    };
    var rows: [64]witness.TraceRow = undefined;
    var count: usize = 0;
    for (immediate_boundaries, 0..) |immediate, index| {
        const rd: u5 = @intCast((index + 1) % 32);
        rows[count] = makeRow(
            rd,
            immediate,
            @intCast(count + 1),
            @intCast(0x1000 + count * 4),
            0x1020_3040 +% @as(u32, @intCast(index)),
            @intCast(index),
        );
        count += 1;
    }
    for (0..32) |raw_rd| {
        const rd: u5 = @intCast(raw_rd);
        rows[count] = makeRow(
            rd,
            immediate_boundaries[raw_rd % immediate_boundaries.len],
            @intCast(count + 1),
            @intCast(0x2000 + count * 4),
            0x8877_6655 +% @as(u32, @intCast(raw_rd)),
            @intCast(raw_rd * 3),
        );
        count += 1;
    }

    const first_x0 = count;
    rows[count] = makeRow(0, 0x80000, 1, 0x3000, 0, 0);
    count += 1;
    const second_x0 = count;
    rows[count] = makeRow(0, 0xfffff, 2, 0x3004, 0, 1);
    count += 1;

    const first_rd7 = makeRow(7, 0x12345, 3, 0x3008, 0x1122_3344, 0);
    rows[count] = first_rd7;
    count += 1;
    rows[count] = makeRow(7, 0xabcde, 4, 0x300c, first_rd7.rd_val, 9);
    count += 1;

    var authored = try typed_lui.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    var actual = try OwnedColumns.init(
        std.testing.allocator,
        64,
        M31.fromCanonical(0x5151),
    );
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, rows[0..count], 6);
    try expectLegacyColumns(rows[0..count], 6, &actual.views);

    for ([_]usize{ first_x0, second_x0 }) |row| {
        try std.testing.expect(actual.views[3][row].isZero());
        for (4..8) |column| try std.testing.expect(actual.views[column][row].isZero());
        for (9..13) |column| try std.testing.expect(actual.views[column][row].isZero());
        try std.testing.expect(actual.views[16][row].isZero());
        try std.testing.expect(actual.views[17][row].isZero());
    }
    try std.testing.expect(actual.views[8][first_x0].isZero());
    try std.testing.expectEqual(M31.one(), actual.views[8][second_x0]);
    for (actual.views) |column| {
        for (column[count..]) |padding| try std.testing.expect(padding.isZero());
    }
}

test "typed LUI witness is production-exact for seeded randomized traces" {
    var prng = std.Random.DefaultPrng.init(0x4530_3035_2d4c_5549);
    const random = prng.random();
    var rows: [96]witness.TraceRow = undefined;
    for (&rows, 0..) |*row, index| {
        const rd = random.int(u5);
        row.* = makeRow(
            rd,
            random.int(u32) & 0xfffff,
            @intCast(index + 1),
            random.int(u32) & ~@as(u32, 3),
            random.int(u32),
            random.int(u32),
        );
    }

    var authored = try typed_lui.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    var actual = try OwnedColumns.init(
        std.testing.allocator,
        128,
        M31.fromCanonical(0x6262),
    );
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, &rows, 7);
    try expectLegacyColumns(&rows, 7, &actual.views);
}

test "typed LUI production authority is singular and allocation-free by construction" {
    const trace_source = @embedFile("../../runner/trace.zig");
    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".lui => typed_lui_witness.writeActiveRow",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, trace_source, "control_witness.lui") == null);

    // The complete production row loop owns only caller-provided stack
    // storage. Its API has no allocator, error path, retained scratch, or
    // dynamic dispatch surface.
    var production_storage: [trace_mod.MAX_FAMILY_COLUMNS][16]M31 = undefined;
    var production: [trace_mod.MAX_FAMILY_COLUMNS][]M31 = undefined;
    for (&production, &production_storage) |*column, *storage| column.* = storage;
    var legacy_storage: [witness.MAIN_COLUMN_COUNT][16]M31 = undefined;
    var legacy: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&legacy, &legacy_storage) |*column, *storage| column.* = storage;
    for (0..16) |index| {
        const row = makeRow(
            @intCast(index),
            @intCast(index * 0x11111),
            @intCast(index + 1),
            @intCast(0x1000 + index * 4),
            @intCast(index * 0x0102_0304),
            @intCast(index),
        );
        trace_mod.fillFamilyColumns(&production, index, row, .lui);
        legacy_oracle.writeRow(&legacy, index, row);
    }
    for (production[0..witness.MAIN_COLUMN_COUNT], legacy) |actual, expected| {
        try std.testing.expectEqualSlices(M31, expected, actual);
    }
}

test "typed LUI authority hot rows retain paired legacy throughput and scaling" {
    // Correctness and allocation-shaped execution run in every mode above.
    // Wall-clock admission is intentionally ReleaseFast-only: Debug/Safe
    // instrumentation measures a different program and is too noisy to be a
    // meaningful performance contract.
    if (builtin.mode != .ReleaseFast) return;

    const allocator = std.testing.allocator;
    const log_rows = [_]u32{ 10, 14, 18 };
    const row_count: usize = @as(usize, 1) << log_rows[log_rows.len - 1];
    const samples = nine_samples;
    const rows = try allocator.alloc(witness.TraceRow, row_count);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| {
        row.* = makeRow(
            @intCast(index % 32),
            @intCast((index * 0x9e37) & 0xfffff),
            @intCast(index + 1),
            @intCast(0x1000 + index * 4),
            @truncate(index *% 0x0101_0101),
            @intCast(index),
        );
    }
    var columns = try OwnedColumns.init(allocator, row_count, M31.zero());
    defer columns.deinit();

    // Warm both instruction streams and page mappings before sampling.
    for (rows, 0..) |row, index| witness.writeActiveRow(&columns.views, index, row);
    consumeColumns(&columns.views, rows.len);
    for (rows, 0..) |row, index| legacy_oracle.writeRow(&columns.views, index, row);
    consumeColumns(&columns.views, rows.len);

    var generated_medians: [log_rows.len]u64 = undefined;
    for (log_rows, 0..) |log_size, case_index| {
        const active = rows[0..(@as(usize, 1) << @intCast(log_size))];
        var generated_times: [samples]u64 = undefined;
        var legacy_times: [samples]u64 = undefined;
        for (0..samples) |sample| {
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
        const generated_median = generated_times[samples / 2];
        const legacy_median = legacy_times[samples / 2];
        generated_medians[case_index] = generated_median;
        std.debug.print(
            "\n  typed LUI authority log_rows={d}: generated={d} ns " ++
                "legacy={d} ns median_speed={d:.4}x\n",
            .{
                log_size,
                generated_median,
                legacy_median,
                @as(f64, @floatFromInt(legacy_median)) /
                    @as(f64, @floatFromInt(generated_median)),
            },
        );

        // Fast deterministic screening before the pinned epoch-3 CI harness:
        // speed = baseline duration / candidate duration, and the paired
        // median must retain the 0.97 non-inferiority floor.
        try std.testing.expect(generated_median * 97 <= legacy_median * 100);
    }
    // Each adjacent case has 16x as many rows: linear + 10% is 17.6x.
    for (1..generated_medians.len) |index| {
        try std.testing.expect(
            generated_medians[index] * 10 <= generated_medians[index - 1] * 176,
        );
    }
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

test "typed LUI witness rejects shapes opcodes and overflow before mutation" {
    var authored = try typed_lui.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    const sentinel = M31.fromCanonical(0x1ace);
    var columns = try OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    var rows = [_]witness.TraceRow{
        makeRow(1, 1, 1, 0x1000, 0, 0),
        makeRow(2, 2, 2, 0x1004, 0, 0),
        makeRow(3, 3, 3, 0x1008, 0, 0),
        makeRow(4, 4, 4, 0x100c, 0, 0),
        makeRow(5, 5, 5, 0x1010, 0, 0),
    };

    const original_last = columns.views[17];
    columns.views[17] = original_last[0..3];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, rows[0..1], 2),
    );
    try columns.expectStorageValue(sentinel);
    columns.views[17] = original_last;

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

    rows[0].opcode = .AUIPC;
    try std.testing.expectError(
        error.InvalidTraceRow,
        executor.generateMainInto(&columns.views, rows[0..1], 2),
    );
    try columns.expectStorageValue(sentinel);
    rows[0].opcode = .LUI;

    const maximum_aligned = std.math.maxInt(usize) &
        ~(@as(usize, @alignOf(M31)) - 1);
    const invalid: [*]M31 = @ptrFromInt(maximum_aligned);
    columns.views[17] = invalid[0..4];
    try std.testing.expectError(
        error.AddressOverflow,
        executor.generateMainInto(&columns.views, rows[0..1], 2),
    );
    try columns.expectStorageValue(sentinel);
}

test "typed LUI witness rejects destination and input aliases before mutation" {
    var authored = try typed_lui.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    const sentinel = M31.fromCanonical(0x2bad);
    var columns = try OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    const rows = [_]witness.TraceRow{makeRow(3, 0x12345, 1, 0x1000, 0, 0)};

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

test "typed LUI witness preserves guards and zeroes only final padding" {
    var authored = try typed_lui.build(std.testing.allocator, .generated);
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
        makeRow(0, 0, 1, 0x1000, 0, 0),
        makeRow(1, 0x80000, 2, 0x1004, 0xdead_beef, 1),
        makeRow(31, 0xfffff, 3, 0x1008, 0x0123_4567, 5),
    };
    try executor.generateMainInto(&columns, &rows, 3);
    try expectLegacyColumns(&rows, 3, &columns);
    for (guarded, columns) |storage, column| {
        try std.testing.expectEqual(guard, storage[0]);
        try std.testing.expectEqual(guard, storage[9]);
        for (column[rows.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}

test "typed LUI witness construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn expectInvalidBinding(
    definition: *const typed_lui.Definition,
    binding: *const witness.WitnessBinding,
) !void {
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(definition, binding),
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var authored = try typed_lui.build(allocator, .generated);
    defer authored.deinit();
    const binding = witness.WitnessBinding.canonical(&authored);
    _ = try witness.Executor.init(&authored, &binding);
}

fn expectLegacyColumns(
    rows: []const witness.TraceRow,
    log_size: u32,
    actual: *const [witness.MAIN_COLUMN_COUNT][]M31,
) !void {
    const allocator = std.testing.allocator;
    const domain_size = @as(usize, 1) << @intCast(log_size);
    try std.testing.expect(rows.len <= domain_size);
    var expected = try OwnedColumns.init(allocator, domain_size, M31.zero());
    defer expected.deinit();
    for (rows, 0..) |row, logical_row| {
        legacy_oracle.writeRow(&expected.views, logical_row, row);
    }
    for (actual, expected.views) |
        actual_column,
        expected_column,
    | {
        try std.testing.expectEqualSlices(
            u8,
            std.mem.sliceAsBytes(expected_column),
            std.mem.sliceAsBytes(actual_column),
        );
    }
}

fn makeRow(
    rd: u5,
    immediate: u32,
    clk: u32,
    pc: u32,
    previous: u32,
    previous_clock: u32,
) witness.TraceRow {
    std.debug.assert(immediate <= 0xfffff);
    const result = immediate << 12;
    return .{
        .clk = clk,
        .pc = pc,
        .opcode = .LUI,
        .rd = rd,
        .rs1 = 0,
        .rs2 = 0,
        .imm = @bitCast(result),
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_prev_val = if (rd == 0) 0 else previous,
        .rd_prev_clk = previous_clock,
        .rd_val = if (rd == 0) 0 else result,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = pc +% 4,
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
