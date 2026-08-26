//! Paired all-mode throughput and scaling admission for BRANCH_EQ.

const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy = @import("../../runner/witness/branch_eq_legacy_test_oracle.zig");
const support = @import("typed_branch_eq_witness_test_support.zig");
const witness = @import("typed_branch_eq_witness.zig");

const nine_samples: usize = 9;
const minimum_legacy_ratio_percent: u64 = if (builtin.mode == .Debug) 90 else 97;

test "typed BRANCH_EQ hot rows retain paired legacy throughput and scaling" {
    const allocator = std.testing.allocator;
    const log_rows = switch (builtin.mode) {
        .Debug => [_]u32{ 9, 12, 15 },
        .ReleaseSafe => [_]u32{ 10, 13, 16 },
        .ReleaseFast, .ReleaseSmall => [_]u32{ 10, 14, 18 },
    };
    const row_count = @as(usize, 1) << log_rows[log_rows.len - 1];
    const rows = try allocator.alloc(witness.TraceRow, row_count);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| {
        const immediate = @as(i32, @intCast(index & 0x7ff)) * 4 - 4096;
        row.* = support.makeRow(
            if ((index & 1) == 0) .BEQ else .BNE,
            @intCast((index *% 17 +% 3) & 31),
            @intCast((index *% 29 +% 5) & 31),
            @truncate(index *% 0x9e37_79b9),
            @truncate(index *% 0x85eb_ca6b),
            immediate,
            @intCast(index + 2),
            @intCast(0x0010_0000 + (index & 0xffff) * 4),
            @intCast(index & 1),
            @intCast(index & 1),
        );
    }
    var columns = try support.OwnedColumns.init(allocator, row_count, M31.zero());
    defer columns.deinit();
    for (rows, 0..) |row, index| witness.writeActiveRow(&columns.views, index, row);
    consumeColumns(&columns.views, rows.len);
    for (rows, 0..) |row, index| legacy.writeRow(&columns.views, index, row);
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
            "\n  typed BRANCH_EQ {s} log_rows={d}: generated={d} ns " ++
                "legacy={d} ns median_speed={d:.4}x\n",
            .{
                @tagName(builtin.mode),
                log_size,
                generated_median,
                legacy_median,
                @as(f64, @floatFromInt(legacy_median)) /
                    @as(f64, @floatFromInt(generated_median)),
            },
        );
        // Debug instrumentation is host-noise-sensitive; keep the strict
        // throughput floor on optimized builds and a bounded smoke floor here.
        try std.testing.expect(
            generated_median * minimum_legacy_ratio_percent <= legacy_median * 100,
        );
    }
    for (1..generated_medians.len) |index| try std.testing.expect(
        generated_medians[index] * 10 <= generated_medians[index - 1] * 176,
    );
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
