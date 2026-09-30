//! Row-span parallelism for witness passes on the shared work pool.
//!
//! `run` splits `[0, rows)` into contiguous spans, one per pool worker (the
//! first on the calling thread), and calls `func(context, span_index, span)`
//! for each. A pass that uses it must be exact under any split: disjoint
//! writes per row, and reductions that are exact field or integer sums (the
//! combine order cannot change a byte). Without a pool, or for few rows, it
//! runs one span on the calling thread.

const std = @import("std");
const work_pool = @import("../work_pool.zig");

pub const Span = struct {
    start: usize,
    end: usize,
};

/// Spans used for `rows` with at least `min_rows` rows each (the pool width
/// caps it). Callers size per-span scratch with it before `run`.
pub fn spanCount(rows: usize, min_rows: usize) usize {
    const pool = work_pool.getGlobalPool() orelse return 1;
    if (rows == 0) return 1;
    const by_rows = @max(@as(usize, 1), rows / @max(min_rows, 1));
    return @max(@as(usize, 1), @min(@min(pool.workerCount(), by_rows), work_pool.MAX_WORKERS));
}

/// The `index`-th of `count` contiguous spans of `rows`.
pub fn span(rows: usize, index: usize, count: usize) Span {
    const width = std.math.divCeil(usize, rows, count) catch unreachable;
    const start = @min(rows, index * width);
    return .{ .start = start, .end = @min(rows, start + width) };
}

/// Calls `func(context, index, span(rows, index, count))` for every
/// `index < count` on the pool, and returns the lowest-index span's error.
pub fn run(
    count: usize,
    rows: usize,
    context: anytype,
    comptime func: fn (@TypeOf(context), usize, Span) anyerror!void,
) anyerror!void {
    std.debug.assert(count >= 1 and count <= work_pool.MAX_WORKERS);
    const Context = @TypeOf(context);
    const Task = struct {
        context: Context,
        index: usize,
        span: Span,
        failure: ?anyerror = null,

        fn call(task: *@This()) void {
            func(task.context, task.index, task.span) catch |err| {
                task.failure = err;
            };
        }
    };
    var tasks: [work_pool.MAX_WORKERS]Task = undefined;
    for (tasks[0..count], 0..) |*task, index| task.* = .{
        .context = context,
        .index = index,
        .span = span(rows, index, count),
    };
    const pool = if (count > 1) work_pool.getGlobalPool() else null;
    if (pool) |active| {
        var wait_group: std.Thread.WaitGroup = .{};
        for (tasks[1..count]) |*task| active.spawnWg(&wait_group, Task.call, .{task});
        Task.call(&tasks[0]);
        wait_group.wait();
    } else for (tasks[0..count]) |*task| Task.call(task);
    for (tasks[0..count]) |task| if (task.failure) |err| return err;
}

test "row spans cover the rows once" {
    const Context = struct {
        hits: []std.atomic.Value(u32),
        fn visit(self: @This(), _: usize, s: Span) anyerror!void {
            for (s.start..s.end) |row| _ = self.hits[row].fetchAdd(1, .monotonic);
        }
    };
    var hits: [1000]std.atomic.Value(u32) = undefined;
    for (&hits) |*hit| hit.* = .init(0);
    for ([_]usize{ 1, 3, 7, 16 }) |count| {
        try run(count, hits.len, Context{ .hits = &hits }, Context.visit);
    }
    for (hits) |hit| try std.testing.expectEqual(@as(u32, 4), hit.load(.monotonic));
}
