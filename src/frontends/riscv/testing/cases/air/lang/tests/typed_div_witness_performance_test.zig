const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const corpus = @import("stwo_riscv_rv32").air.lang.typed_div_corpus;
const legacy = @import("stwo_riscv_rv32").testing.execution.witness.div_legacy_test_oracle;
const typed_div = @import("stwo_riscv_air_lang").typed_div;
const witness = @import("stwo_riscv_rv32").air.lang.typed_div_witness;

const correctness = @import("typed_div_witness_test.zig");
const OwnedColumns = correctness.OwnedColumns;

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
