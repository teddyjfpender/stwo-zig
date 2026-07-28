const std = @import("std");
const runtime_mod = @import("stwo_metal_backend").runtime;
const m31 = @import("stwo_core").fields.m31;
const trace = @import("stwo_native_examples").backend_support.wide_fibonacci.trace;

const M31 = m31.M31;

test "metal: forced quadratic recurrence trace matches generic non-target shape" {
    const expected_allocator = std.testing.allocator;
    const actual_allocator = std.heap.page_allocator;
    const statement = trace.Statement{ .log_n_rows = 12, .sequence_len = 37 };
    const expected = try trace.generate(expected_allocator, statement);
    defer trace.deinit(expected_allocator, expected);

    const actual = try actual_allocator.alloc([]M31, statement.sequence_len);
    defer actual_allocator.free(actual);
    var initialized: usize = 0;
    defer for (actual[0..initialized]) |column| actual_allocator.free(column);
    const row_count = @as(usize, 1) << @intCast(statement.log_n_rows);
    var pointers: [256][*]u32 = undefined;
    for (actual, 0..) |*column, index| {
        column.* = try actual_allocator.alloc(M31, row_count);
        initialized += 1;
        pointers[index] = @ptrCast(column.ptr);
    }

    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    const stats = try runtime.quadraticRecurrenceTrace(
        pointers[0..actual.len],
        @intCast(row_count),
        statement.log_n_rows,
        trace.quadratic_recurrence_recipe,
    );

    try std.testing.expect(stats.gpu_ms > 0);
    try std.testing.expectEqual(@as(u32, 0), stats.copyback_columns);
    for (expected, actual) |expected_column, actual_column| {
        try std.testing.expectEqualSlices(M31, expected_column, actual_column);
    }
}
