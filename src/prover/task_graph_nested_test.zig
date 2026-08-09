//! Joined nested-work regressions for the structured task graph.

const std = @import("std");
const task_graph = @import("task_graph.zig");
const work_pool = @import("work_pool.zig");

const TEST_STACK_SIZE: usize = 1024 * 1024;

test "one-worker pool runs compatibility submissions synchronously" {
    const Job = struct {
        fn run(counter: *usize) void {
            counter.* += 1;
        }
    };
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1 });
    defer pool.deinit();
    try std.testing.expectError(
        error.InvalidWorkerBudget,
        pool.acquire(.{ .count = 0 }),
    );

    var counter: usize = 0;
    var wait_group = std.Thread.WaitGroup{};
    pool.spawnWg(&wait_group, Job.run, .{&counter});
    wait_group.wait();
    try std.testing.expectEqual(@as(usize, 1), counter);
}

test "pool-exclusive failure joins nested children before returning" {
    const State = struct {
        child_finished: std.atomic.Value(bool) = .init(false),
        cancellation: ?*const task_graph.CancellationToken = null,

        fn child(self: *@This()) void {
            while (!self.cancellation.?.isCancelled()) {
                std.atomic.spinLoopHint();
            }
            self.child_finished.store(true, .release);
        }

        fn parent(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            self.cancellation = context.cancellation;
            try context.spawnChild(child, .{self});
            return error.ParentFailedAfterSpawn;
        }
    };

    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = TEST_STACK_SIZE,
    });
    defer pool.deinit();

    var state = State{};
    var graph = try task_graph.ComponentTaskGraph.init(std.testing.allocator, 1);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .name = "exclusive-parent",
        .func = State.parent,
        .context = &state,
        .class = .pool_exclusive,
    });

    try std.testing.expectError(
        error.ParentFailedAfterSpawn,
        graph.execute(.{
            .worker_budget = try work_pool.WorkerBudget.init(2),
            .pool = &pool,
        }),
    );
    try std.testing.expect(state.child_finished.load(.acquire));
    try std.testing.expectEqual(@as(usize, 2), pool.availableWorkers());
    try std.testing.expectEqual(@as(usize, 0), graph.report().duplicate_finishes);
}
