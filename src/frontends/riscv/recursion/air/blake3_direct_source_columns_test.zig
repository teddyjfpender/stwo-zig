const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const storage = @import("blake3_parent_row_storage.zig");
const source = @import("blake3_direct_source_columns_v1.zig");
fn emptyPrepared(a: std.mem.Allocator) storage.Prepared {
    var value = storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..storage.Airs.len) |i| value.fixed[i] = &.{};
    return value;
}
test "direct PCS public source cohorts match legacy scattered columns and transfer ownership" {
    const a = std.testing.allocator;
    inline for (source.cohorts) |slot| {
        const Air = storage.Airs[slot];
        for ([_]usize{ 0, 1, 3, 9, 33 }) |count| {
            const rows = try a.alloc(Air.Row, count);
            defer a.free(rows);
            const trusted = try a.alloc(Air.Row, count);
            defer a.free(trusted);
            for (rows, trusted, 0..) |*row, *fixed, i| {
                for (row, 0..) |*word, j| word.* = M.fromCanonical(@intCast(17 * i + j));
                fixed.* = row.*;
                @memset(fixed[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], M.zero());
            }
            var count_sink = source.Counts{};
            const split = count / 2;
            try count_sink.append(slot, rows[0..split], trusted[0..split]);
            try count_sink.append(slot, rows[split..], trusted[split..]);
            var legacy = storage.Builder.init(a);
            defer legacy.deinit();
            var direct = try source.Builder.init(a, &legacy, count_sink.counts);
            defer direct.deinit();
            try direct.append(slot, rows[0..split], trusted[0..split]);
            try direct.append(slot, rows[split..], trusted[split..]);
            try std.testing.expectEqual(@as(usize, 0), legacy.rows[slot].capacity);
            try std.testing.expectEqual(@as(usize, 0), legacy.fixed[slot].capacity);
            var prepared = emptyPrepared(a);
            defer prepared.deinit();
            try direct.takeInto(&prepared.main, &prepared.fixed);
            const log: u32 = if (count <= 1) 1 else std.math.log2_int_ceil(usize, count);
            var expected: std.ArrayList(Column) = .empty;
            defer {
                for (expected.items) |column| a.free(column.values);
                expected.deinit(a);
            }
            try @import("blake3_row_columns.zig").project(Air, a, rows, log, 1, &expected);
            for (expected.items, prepared.main[slot]) |old, new| try std.testing.expectEqualSlices(M, old.values, new.values);
            for (trusted, prepared.fixed[slot]) |fixed, compact| try std.testing.expectEqualDeep(storage.compactFixed(Air, fixed), compact);
            const borrowed = try @import("blake3_recursive_column_rows_v1.zig").ForAir(Air).init(prepared.main[slot], prepared.fixed[slot]);
            try std.testing.expectEqual(count, borrowed.rowCount());
            for (rows, 0..) |row, i| try std.testing.expectEqualDeep(row, borrowed.rowAt(i));
            // Drop a consumed cohort, then all remaining empty/padded cohorts.
            prepared.releaseCohort(slot);
            prepared.releaseCohort(slot);
            prepared.releaseRows();
            try std.testing.expectEqual(@as(usize, 0), try prepared.retainedBytes());
        }
    }
}
test "direct source columns preserve fixed admission and fail incomplete geometry before transfer" {
    const a = std.testing.allocator;
    const Air = storage.Airs[6];
    const rows: [3]Air.Row = @splat(@splat(M.zero()));
    var trusted = rows;
    trusted[0][Air.PHYSICAL_MAIN_COLUMN_COUNT] = M.one();
    var counts = source.Counts{};
    try counts.append(6, &rows, &rows);
    var legacy = storage.Builder.init(a);
    defer legacy.deinit();
    var direct = try source.Builder.init(a, &legacy, counts.counts);
    defer direct.deinit();
    try std.testing.expectError(error.InvalidNativeParentRows, direct.append(6, &rows, &trusted));
    try direct.append(6, rows[0..2], rows[0..2]);
    var prepared = emptyPrepared(a);
    defer prepared.deinit();
    try std.testing.expectError(error.DirectRecursiveRowCountMismatch, direct.takeInto(&prepared.main, &prepared.fixed));
    try std.testing.expectEqual(@as(usize, 0), prepared.main[6].len);
    try direct.append(6, rows[2..], rows[2..]);
    try direct.takeInto(&prepared.main, &prepared.fixed);
    counts.counts[6] = (1 << 24) + 1;
    try std.testing.expectError(error.InvalidTraceShape, source.Builder.init(a, &legacy, counts.counts));
}
