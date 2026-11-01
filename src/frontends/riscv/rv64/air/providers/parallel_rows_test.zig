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
test "cooperative row ranges on a composition queue equal the serial kernel" {
    var serial_values: [4][N]M = @splat(@splat(M.zero()));
    var serial_col = engine.secure_column.SecureColumnByCoords{ .columns = .{ &serial_values[0], &serial_values[1], &serial_values[2], &serial_values[3] }, .owns_columns = false };
    var serial_output = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &.{}, .col = &serial_col, .next_fresh_index = 0 };
    var serial_context = Context{};
    try R.evaluate(.{ .context = &serial_context, .run = Context.run }, N, &serial_output, null);

    const Queue = engine.work_pool.cooperative;
    const Item = struct {
        values: [4][N]M = @splat(@splat(M.zero())),
        context: Context = .{},
        failure: ?anyerror = null,
        done: bool = false,
        taken: bool = false,
        fn take(c: *anyopaque) ?usize {
            const self: *@This() = @ptrCast(@alignCast(c));
            if (self.taken) return null;
            self.taken = true;
            return 0;
        }
        fn run(c: *anyopaque, _: usize) void {
            const self: *@This() = @ptrCast(@alignCast(c));
            var col = engine.secure_column.SecureColumnByCoords{ .columns = .{ &self.values[0], &self.values[1], &self.values[2], &self.values[3] }, .owns_columns = false };
            var output = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &.{}, .col = &col, .next_fresh_index = 0 };
            R.evaluate(.{ .context = &self.context, .run = Context.run }, N, &output, null) catch |err| {
                self.failure = err;
            };
        }
        fn finish(c: *anyopaque, _: usize) void {
            const self: *@This() = @ptrCast(@alignCast(c));
            self.done = true;
        }
        fn exhausted(c: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(c));
            return self.done;
        }
    };
    const item = try std.testing.allocator.create(Item);
    defer std.testing.allocator.destroy(item);
    item.* = .{};
    var queue = Queue.Queue.init(4);
    const top = Queue.TopLevel{ .context = item, .take = Item.take, .run = Item.run, .finish = Item.finish, .exhausted = Item.exhausted };
    var threads: [3]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Queue.Queue.drive, .{ &queue, top });
    queue.drive(top);
    for (threads) |thread| thread.join();
    try std.testing.expect(item.failure == null);
    try std.testing.expectEqual(@as(usize, 1), queue.batches_published);
    try std.testing.expectEqual(N, item.context.completed.load(.seq_cst));
    for (serial_values, item.values) |expected, actual| try std.testing.expectEqualSlices(M, &expected, &actual);
}
test "cooperative column transforms on a composition queue equal the serial transform" {
    const T = @import("domain_transform.zig");
    const allocator = std.testing.allocator;
    const log = 10;
    const size = 1 << log;
    const columns = 11;
    const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
    var twiddles = try engine.poly.twiddles.precomputeM31(allocator, domain.half_coset);
    defer engine.poly.twiddles.deinitM31(allocator, &twiddles);
    const tree = engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
    var serial_storage: [columns][size]M = undefined;
    var queued_storage: [columns][size]M = undefined;
    for (&serial_storage, &queued_storage, 0..) |*s, *q, c| for (s, q, 0..) |*x, *y, i| {
        x.* = M.fromCanonical(@intCast((c * 7919 + i * 104729) % 2147483647));
        y.* = x.*;
    };
    var serial: [columns][]M = undefined;
    var queued: [columns][]M = undefined;
    for (&serial, &queued, &serial_storage, &queued_storage) |*s, *q, *ss, *qs| {
        s.* = ss;
        q.* = qs;
    }
    try T.evaluate(&serial, domain, tree, null);

    const Queue = engine.work_pool.cooperative;
    const Item = struct {
        buffers: [][]M,
        domain: @TypeOf(domain),
        tree: @TypeOf(tree),
        failure: ?anyerror = null,
        taken: bool = false,
        done: bool = false,
        fn take(c: *anyopaque) ?usize {
            const self: *@This() = @ptrCast(@alignCast(c));
            if (self.taken) return null;
            self.taken = true;
            return 0;
        }
        fn run(c: *anyopaque, _: usize) void {
            const self: *@This() = @ptrCast(@alignCast(c));
            T.evaluate(self.buffers, self.domain, self.tree, null) catch |err| {
                self.failure = err;
            };
        }
        fn finish(c: *anyopaque, _: usize) void {
            const self: *@This() = @ptrCast(@alignCast(c));
            self.done = true;
        }
        fn exhausted(c: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(c));
            return self.done;
        }
    };
    var item = Item{ .buffers = &queued, .domain = domain, .tree = tree };
    var queue = Queue.Queue.init(3);
    const top = Queue.TopLevel{ .context = &item, .take = Item.take, .run = Item.run, .finish = Item.finish, .exhausted = Item.exhausted };
    var threads: [2]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Queue.Queue.drive, .{ &queue, top });
    queue.drive(top);
    for (threads) |thread| thread.join();
    try std.testing.expect(item.failure == null);
    try std.testing.expectEqual(@as(usize, 1), queue.batches_published);
    for (serial_storage, queued_storage) |expected, actual| try std.testing.expectEqualSlices(M, &expected, &actual);
}
