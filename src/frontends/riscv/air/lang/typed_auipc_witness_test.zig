const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy_oracle = @import("../../runner/witness/auipc_legacy_test_oracle.zig");
const support = @import("typed_auipc_witness_test_support.zig");
const typed_auipc = @import("typed_auipc.zig");
const witness = @import("typed_auipc_witness.zig");

test "typed AUIPC witness binding is exact source-independent and self-contained" {
    var generated = try typed_auipc.build(std.testing.allocator, .generated);
    var moved = try typed_auipc.build(std.testing.allocator, .{ .file = .{
        .path = "moved/auipc.air",
        .start = .{ .byte_offset = 72, .line = 9, .column = 1 },
        .end = .{ .byte_offset = 77, .line = 9, .column = 6 },
    } });
    defer moved.deinit();

    var binding = try witness.WitnessBinding.canonical(&generated);
    const executor = try witness.Executor.init(&generated, &binding);
    const moved_binding = try witness.WitnessBinding.canonical(&moved);
    const moved_executor = try witness.Executor.init(&moved, &moved_binding);
    try std.testing.expectEqual(
        witness.WITNESS_BINDING_FORMAT_VERSION,
        binding.format_version,
    );
    try std.testing.expectEqual(typed_auipc.OPCODE_ID, binding.opcode_id);
    try std.testing.expectEqual(binding.identityDigest(), executor.identityDigest());
    try std.testing.expectEqual(witness.WITNESS_BINDING_DIGEST, executor.identityDigest());
    try std.testing.expectEqual(executor.identityDigest(), moved_executor.identityDigest());
    try std.testing.expect(std.meta.eql(binding, executor.identitySnapshot()));
    for (binding.slots, witness.CANONICAL_RECIPE, 0..) |slot, recipe, column| {
        try std.testing.expectEqual(column, slot.column);
        try std.testing.expectEqual(column, @intFromEnum(slot.value));
        try std.testing.expectEqual(recipe, slot.source);
    }
    try std.testing.expectEqual(
        witness.CANONICAL_ARITHMETIC,
        binding.arithmetic,
    );
    try std.testing.expectEqual(
        witness.CANONICAL_DESTINATION_HINT,
        binding.destination_hint,
    );

    // The executor owns a fixed-size authenticated snapshot. It does not keep
    // a pointer into either the mutable binding or the semantic arena.
    binding.slots[0].source = .trace_clock;
    generated.deinit();
    var storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*column_storage, *column| column.* = column_storage;
    const row = support.makeRow(5, @bitCast(@as(u32, 0x8abcd000)), 7, 0x1040, 9, 3);
    try executor.generateMainInto(&columns, &.{row}, 0);
    try std.testing.expectEqual(M31.one(), columns[0][0]);
    try std.testing.expectEqual(M31.fromCanonical(5), columns[3][0]);
    try std.testing.expectEqual(
        M31.zero().sub(M31.fromU64(0x7543_3000)),
        columns[13][0],
    );
}

test "typed AUIPC witness is byte-exact at immediate pc carry and x0 boundaries" {
    const immediates = [_]i32{
        0,
        0x1000,
        0x7fff_f000,
        @bitCast(@as(u32, 0x8000_0000)),
        @bitCast(@as(u32, 0xffff_f000)),
    };
    const pcs = [_]u32{
        0,
        0xff,
        0x100,
        0xffff,
        0x00ff_ffff,
        (@as(u32, 1) << 30) - 4,
    };
    var rows: [64]witness.TraceRow = undefined;
    var count: usize = 0;
    for (immediates) |immediate| {
        for (pcs) |pc| {
            rows[count] = support.makeRow(
                @intCast(count % 32),
                immediate,
                @intCast(count + 1),
                pc,
                0x1020_3040 +% @as(u32, @intCast(count)),
                @intCast(count * 3),
            );
            count += 1;
        }
    }
    rows[count] = support.makeRow(0, @bitCast(@as(u32, 0x8000_0000)), 31, 4, 0, 0);
    const x0_index = count;
    count += 1;
    rows[count] = support.makeRow(31, @bitCast(@as(u32, 0xffff_f000)), 32, 8, 7, 11);
    count += 1;

    var authored = try typed_auipc.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    var actual = try support.OwnedColumns.init(
        std.testing.allocator,
        64,
        M31.fromCanonical(0x5151),
    );
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, rows[0..count], 6);
    try support.expectLegacyColumns(rows[0..count], 6, &actual.views);
    for (rows[0..count], 0..) |row, index|
        try support.expectProofInputParity(&actual.views, index, row);

    for (3..13) |column| try std.testing.expect(actual.views[column][x0_index].isZero());
    try std.testing.expect(actual.views[18][x0_index].isZero());
    try std.testing.expect(actual.views[19][x0_index].isZero());
    for (actual.views) |column| {
        for (column[count..]) |padding| try std.testing.expect(padding.isZero());
    }
}

test "typed AUIPC witness is byte and proof-input exact for randomized traces" {
    var prng = std.Random.DefaultPrng.init(0x4155_4950_432d_7631);
    const random = prng.random();
    var rows: [256]witness.TraceRow = undefined;
    for (&rows, 0..) |*row, index| {
        const immediate_bits = random.int(u32) & 0xffff_f000;
        row.* = support.makeRow(
            random.int(u5),
            @bitCast(immediate_bits),
            @intCast(index + 1),
            random.int(u32) & ((@as(u32, 1) << 30) - 1),
            random.int(u32),
            random.int(u32),
        );
    }
    var authored = try typed_auipc.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const binding = try witness.WitnessBinding.canonical(&authored);
    const executor = try witness.Executor.init(&authored, &binding);
    var actual = try support.OwnedColumns.init(std.testing.allocator, 256, M31.zero());
    defer actual.deinit();
    try executor.generateMainInto(&actual.views, &rows, 8);
    try support.expectLegacyColumns(&rows, 8, &actual.views);
    for (rows, 0..) |row, index|
        try support.expectProofInputParity(&actual.views, index, row);
}

test "typed AUIPC direct hot authority is allocation-free and recipe-static" {
    const source = @embedFile("typed_auipc_witness.zig");
    const trace_source = @embedFile("../../runner/trace.zig");
    try std.testing.expect(std.mem.indexOf(u8, source, "legacy_test_oracle") == null);
    try std.testing.expect(std.mem.indexOf(u8, source, "pub inline fn writeActiveRow") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "inline for (CANONICAL_RECIPE") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".auipc => typed_auipc_witness.writeActiveRow",
    ) != null);
    try std.testing.expect(
        std.mem.indexOf(u8, trace_source, "control_witness.auipc") == null,
    );

    var generated: [witness.MAIN_COLUMN_COUNT][16]M31 = undefined;
    var legacy: [witness.MAIN_COLUMN_COUNT][16]M31 = undefined;
    var generated_views: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    var legacy_views: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&generated, &generated_views) |*storage, *view| view.* = storage;
    for (&legacy, &legacy_views) |*storage, *view| view.* = storage;
    for (0..16) |index| {
        const row = support.makeRow(
            @intCast(index),
            @bitCast(@as(u32, @truncate(index * 0x1111_1000))),
            @intCast(index + 1),
            @intCast(0x1000 + index * 4),
            @truncate(index *% 0x0102_0304),
            @intCast(index),
        );
        witness.writeActiveRow(&generated_views, index, row);
        legacy_oracle.writeRow(&legacy_views, index, row);
    }
    for (generated_views, legacy_views) |actual, expected|
        try std.testing.expectEqualSlices(M31, expected, actual);
}

test "typed AUIPC hot rows retain paired legacy throughput in every build mode" {
    const allocator = std.testing.allocator;
    const log_rows = switch (builtin.mode) {
        .Debug => [_]u32{ 9, 12, 15 },
        .ReleaseSafe => [_]u32{ 10, 13, 16 },
        .ReleaseFast, .ReleaseSmall => [_]u32{ 10, 14, 18 },
    };
    const row_count: usize = @as(usize, 1) << log_rows[log_rows.len - 1];
    const rows = try allocator.alloc(witness.TraceRow, row_count);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| {
        row.* = support.makeRow(
            @intCast(index % 32),
            @bitCast(@as(u32, @truncate(index *% 0x9e37_0000))),
            @intCast(index + 1),
            @intCast((0x1000 +% index *% 4) & ((@as(u32, 1) << 30) - 1)),
            @truncate(index *% 0x0101_0101),
            @intCast(index),
        );
    }
    var columns = try support.OwnedColumns.init(allocator, row_count, M31.zero());
    defer columns.deinit();

    for (rows, 0..) |row, index| witness.writeActiveRow(&columns.views, index, row);
    consumeColumns(&columns.views, rows.len);
    for (rows, 0..) |row, index| legacy_oracle.writeRow(&columns.views, index, row);
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
            "\n  typed AUIPC {s} log_rows={d}: generated={d} ns legacy={d} ns speed={d:.4}x\n",
            .{
                @tagName(builtin.mode),
                log_size,
                generated_median,
                legacy_median,
                @as(f64, @floatFromInt(legacy_median)) /
                    @as(f64, @floatFromInt(generated_median)),
            },
        );
        const retained_percent: u64 = if (builtin.mode == .ReleaseFast) 97 else 90;
        try std.testing.expect(generated_median * retained_percent <= legacy_median * 100);
    }
    for (1..generated_medians.len) |index| {
        const exponent = log_rows[index] - log_rows[index - 1];
        const expected_scale = @as(u64, 1) << @intCast(exponent);
        try std.testing.expect(
            generated_medians[index] * 10 <=
                generated_medians[index - 1] * expected_scale * 12,
        );
    }
}

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
