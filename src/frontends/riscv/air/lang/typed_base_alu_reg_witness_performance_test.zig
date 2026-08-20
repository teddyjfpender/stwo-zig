//! ReleaseFast paired throughput and scaling admission for BASE_ALU_REG.

const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const Opcode = @import("../../isa/decode.zig").Opcode;
const legacy = @import("../../runner/witness/base_alu_reg_legacy_test_oracle.zig");
const support = @import("typed_base_alu_reg_witness_test_support.zig");
const witness = @import("typed_base_alu_reg_witness.zig");

const operations = [_]Opcode{ .ADD, .SUB, .XOR, .OR, .AND };
const nine_samples: usize = 9;

test "typed BASE_ALU_REG hot rows retain paired legacy throughput and scaling" {
    if (builtin.mode != .ReleaseFast) return;
    const allocator = std.testing.allocator;
    const log_rows = [_]u32{ 10, 14, 18 };
    const row_count = @as(usize, 1) << log_rows[log_rows.len - 1];
    const rows = try allocator.alloc(witness.TraceRow, row_count);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| row.* = support.makeRow(
        operations[index % operations.len],
        @intCast(index & 31),
        @intCast((index *% 17 +% 3) & 31),
        @intCast((index *% 29 +% 5) & 31),
        @truncate(index *% 0x9e37_79b9),
        @truncate(index *% 0x85eb_ca6b),
        @intCast(index + 2),
        @truncate(0x1000 +% index *% 4),
        @truncate(index *% 0x0101_0101),
        @intCast(index & 1),
        @intCast(index & 1),
        @intCast(index & 1),
    );
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
            "\n  typed BASE_ALU_REG log_rows={d}: generated={d} ns " ++
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
