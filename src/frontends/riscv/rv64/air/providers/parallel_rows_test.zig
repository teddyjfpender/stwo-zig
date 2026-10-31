const std = @import("std");
const engine = @import("stwo_prover_engine");
const core = @import("stwo_core");
const R = @import("parallel_rows.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const N = 16384;
const Context = struct {
    completed: std.atomic.Value(usize) = .init(0),
    fail_first: bool = false,
    fn run(pointer: *const anyopaque, start: usize, end: usize, output: *engine.air.accumulation.ColumnAccumulator) anyerror!void {
        const self: *const Context = @ptrCast(@alignCast(pointer));
        for (start..end) |row| output.accumulate(row, Q.fromBase(M.fromCanonical(@intCast(row + 1))));
        _ = @constCast(&self.completed).fetchAdd(end - start, .seq_cst);
        if (self.fail_first and start == 0) return error.KernelFailed;
    }
};
test "joined row ranges preserve additive output and never share fresh cursors" {
    var values: [4][N]M = @splat(@splat(M.zero()));
    var col = engine.secure_column.SecureColumnByCoords{ .columns = .{ &values[0], &values[1], &values[2], &values[3] }, .owns_columns = false };
    var output = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &.{}, .col = &col, .next_fresh_index = 0 };
    var context = Context{};
    const kernel = R.Kernel{ .context = &context, .run = Context.run };
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = R.MIN_STACK, .backing_allocator = std.testing.allocator });
    defer pool.deinit();
    try R.evaluate(kernel, N, &output, null);
    try R.evaluate(kernel, N, &output, &pool);
    try std.testing.expectEqual(2 * N, context.completed.load(.seq_cst));
    for (0..N) |row| try std.testing.expect(col.at(row).eql(Q.fromBase(M.fromCanonical(@intCast(2 * (row + 1))))));
    try std.testing.expect(output.next_fresh_index == null);
    try std.testing.expectError(error.InvalidPackedRowExtent, R.evaluate(kernel, N - 1, &output, &pool));
    var small: engine.work_pool.WorkPool = .{};
    try small.initInPlaceWithOptions(.{ .worker_count = 1, .stack_size = R.MIN_STACK / 2, .backing_allocator = std.testing.allocator });
    defer small.deinit();
    try std.testing.expectError(error.InvalidPackedRowWorkerStack, R.evaluate(kernel, 16, &output, &small));
}
test "row kernel failure drains every helper and returns its pool lease" {
    var values: [4][N]M = @splat(@splat(M.zero()));
    var col = engine.secure_column.SecureColumnByCoords{ .columns = .{ &values[0], &values[1], &values[2], &values[3] }, .owns_columns = false };
    var output = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &.{}, .col = &col, .next_fresh_index = 0 };
    var context = Context{ .fail_first = true };
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = R.MIN_STACK, .backing_allocator = std.testing.allocator });
    defer pool.deinit();
    const available = pool.availableWorkers();
    try std.testing.expectError(error.KernelFailed, R.evaluate(.{ .context = &context, .run = Context.run }, N, &output, &pool));
    try std.testing.expectEqual(N, context.completed.load(.seq_cst));
    try std.testing.expectEqual(available, pool.availableWorkers());
}
test "partial row submission drains borrowed jobs before context retirement" {
    var values: [4][N]M = @splat(@splat(M.zero()));
    var col = engine.secure_column.SecureColumnByCoords{ .columns = .{ &values[0], &values[1], &values[2], &values[3] }, .owns_columns = false };
    var output = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &.{}, .col = &col, .next_fresh_index = 0 };
    var context = Context{};
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = R.MIN_STACK, .backing_allocator = std.testing.allocator });
    defer pool.deinit();
    const available = pool.availableWorkers();
    try std.testing.expectError(error.InjectedPackedRowSubmissionFailure, R.testing.failAfter(.{ .context = &context, .run = Context.run }, N, &output, &pool, 1));
    try std.testing.expectEqual(N / 4, context.completed.load(.seq_cst));
    try std.testing.expectEqual(available, pool.availableWorkers());
}
