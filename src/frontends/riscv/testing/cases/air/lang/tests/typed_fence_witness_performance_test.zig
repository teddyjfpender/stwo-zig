const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy_oracle = @import("stwo_riscv_rv32").testing.execution.witness.fence_legacy_test_oracle;
const support = @import("stwo_riscv_rv32").testing.air.lang.typed_fence_witness_test_support;
const typed_fence = @import("stwo_riscv_air_lang").typed_fence;
const witness = @import("stwo_riscv_rv32").air.lang.typed_fence_witness;

test "typed FENCE hot rows retain paired legacy throughput in every build mode" {
    const allocator = std.testing.allocator;
    const log_rows = switch (builtin.mode) {
        .Debug => [_]u32{ 10, 14, 18 },
        .ReleaseSafe => [_]u32{ 10, 14, 18 },
        .ReleaseFast, .ReleaseSmall => [_]u32{ 10, 16, 20 },
    };
    const row_count: usize = @as(usize, 1) << log_rows[log_rows.len - 1];
    const rows = try allocator.alloc(witness.TraceRow, row_count);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| {
        row.* = support.makeRow(
            @intCast(index % 32),
            @intCast((index * 13) % 32),
            @intCast(@as(i32, @intCast(index % 4096)) - 2048),
            @intCast(index + 1),
            @truncate(index *% 4 +% 0x1000),
            @truncate(index *% 0x0101_0101),
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
            "\n  typed FENCE {s} log_rows={d}: generated={d} ns legacy={d} ns speed={d:.4}x\n",
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
