//! Shared row-split helpers for Cairo's witness counting passes.
//!
//! Every pass that uses these is an additive histogram: workers own disjoint
//! input spans, count into private copies, and merge with checked adds. The
//! helpers only decide how many workers to use and hand out the spans; the
//! exactness argument belongs to each pass.

const std = @import("std");
const prover = @import("stwo_prover_engine");

pub const work_pool = prover.work_pool;

pub const Bounds = struct {
    /// Total input rows to split.
    rows: usize,
    /// Smallest span worth a worker of its own.
    min_rows_per_worker: usize,
    /// Live bytes one worker's private histogram costs, or zero when the
    /// private state does not scale with the worker count.
    private_bytes_per_worker: usize = 0,
    /// Ceiling on the sum of the private copies. The merge re-reads all of
    /// them, so past this point merge traffic outweighs scatter parallelism.
    max_private_bytes: usize = 0,
};

/// Structural worker count: pool width, row supply and private-copy budget.
/// Returns 1 when there is no pool, which is the serial fallback every caller
/// relies on in test and single-threaded builds.
pub fn workerCount(bounds: Bounds) usize {
    const pool = work_pool.getGlobalPool() orelse return 1;
    if (bounds.rows == 0 or bounds.min_rows_per_worker == 0) return 1;
    const by_rows = std.math.divCeil(usize, bounds.rows, bounds.min_rows_per_worker) catch 1;
    const by_bytes = if (bounds.private_bytes_per_worker == 0)
        work_pool.MAX_WORKERS
    else
        @max(@as(usize, 1), bounds.max_private_bytes / bounds.private_bytes_per_worker);
    const capped = @min(@min(by_rows, by_bytes), work_pool.MAX_WORKERS);
    return @max(@as(usize, 1), @min(pool.workerCount(), capped));
}

pub const Span = struct {
    start: usize,
    end: usize,

    pub fn isEmpty(self: Span) bool {
        return self.start >= self.end;
    }
};

/// The `index`-th of `worker_count` contiguous equal spans of `total`.
pub fn span(total: usize, index: usize, worker_count: usize) Span {
    if (worker_count == 0) return .{ .start = 0, .end = 0 };
    const width = std.math.divCeil(usize, total, worker_count) catch
        return .{ .start = 0, .end = 0 };
    const start = index * width;
    if (start >= total) return .{ .start = total, .end = total };
    return .{ .start = start, .end = @min(total, start + width) };
}

/// Runs one `Work` per element on the pool, keeping the first on the calling
/// thread, then returns the first recorded failure.
///
/// `Work` must expose `fn run(*Work) void` and a `failure: ?anyerror` field.
pub fn dispatch(comptime Work: type, works: []Work) !void {
    if (works.len == 0) return;
    if (works.len > 1) {
        const pool = work_pool.getGlobalPool().?;
        var wait_group: std.Thread.WaitGroup = .{};
        for (works[1..]) |*work| pool.spawnWg(&wait_group, Work.run, .{work});
        Work.run(&works[0]);
        wait_group.wait();
    } else {
        Work.run(&works[0]);
    }
    for (works) |work| {
        if (work.failure) |err| return err;
    }
}

test "pool split spans are disjoint and cover the whole range" {
    for ([_]usize{ 0, 1, 7, 64, 1000 }) |total| {
        for ([_]usize{ 1, 2, 3, 8, 17 }) |workers| {
            var covered: usize = 0;
            var previous_end: usize = 0;
            for (0..workers) |index| {
                const piece = span(total, index, workers);
                try std.testing.expect(piece.start >= previous_end);
                if (!piece.isEmpty()) {
                    try std.testing.expectEqual(previous_end, piece.start);
                    covered += piece.end - piece.start;
                    previous_end = piece.end;
                }
            }
            try std.testing.expectEqual(total, covered);
        }
    }
}
