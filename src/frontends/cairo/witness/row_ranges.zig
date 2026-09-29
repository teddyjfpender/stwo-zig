//! Bounded work tickets for independent witness rows. Each worker keeps its
//! deduction scratch while faster workers claim additional complete batches.
const std = @import("std");

pub const Range = struct { start: usize, end: usize };

pub const Queue = struct {
    next: std.atomic.Value(usize) = .init(0),
    row_count: usize,
    grain: usize,

    pub fn take(self: *Queue) ?Range {
        std.debug.assert(self.grain > 0);
        var start = self.next.load(.monotonic);
        while (start < self.row_count) {
            // Subtract before adding so even a full usize-sized range cannot
            // wrap the cursor and issue duplicate rows.
            const end = start + @min(self.grain, self.row_count - start);
            if (self.next.cmpxchgWeak(start, end, .monotonic, .monotonic)) |actual| {
                start = actual;
            } else {
                return .{ .start = start, .end = end };
            }
        }
        return null;
    }
};

/// Preserve native 256-row deduction batches, with several tickets per worker.
/// Small components retain their existing static split to avoid shrinking the
/// number of usable workers when their complete batch count is too small.
pub fn grain(row_count: usize, workers: usize, minimum_rows: usize) ?usize {
    std.debug.assert(workers > 0 and minimum_rows > 0);
    const alignment = @max(@as(usize, 256), minimum_rows);
    if (workers == 1 or row_count / alignment < workers) return null;
    const desired = std.math.divCeil(usize, row_count, workers * 8) catch unreachable;
    return std.math.mul(usize, std.math.divCeil(usize, desired, alignment) catch unreachable, alignment) catch unreachable;
}

test "Cairo witness row tickets cover every row exactly once across workers" {
    const rows = 12347;
    const visits = try std.testing.allocator.alloc(std.atomic.Value(u32), rows);
    defer std.testing.allocator.free(visits);
    for (visits) |*visit| visit.* = .init(0);
    var queue = Queue{ .row_count = rows, .grain = 256 };
    const Worker = struct {
        fn run(q: *Queue, counts: []std.atomic.Value(u32)) void {
            while (q.take()) |range| {
                for (counts[range.start..range.end]) |*count| _ = count.fetchAdd(1, .monotonic);
            }
        }
    };
    var threads: [8]std.Thread = undefined;
    var spawned: usize = 0;
    defer for (threads[0..spawned]) |thread| thread.join();
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &queue, visits });
        spawned += 1;
    }
    // Join before observing the non-publication, relaxed ticket cursor.
    for (threads[0..spawned]) |thread| thread.join();
    spawned = 0;
    for (visits) |*visit| try std.testing.expectEqual(@as(u32, 1), visit.load(.monotonic));
    try std.testing.expectEqual(@as(?Range, null), queue.take());
}

test "Cairo witness row tickets preserve deduction batches and saturate safely" {
    try std.testing.expectEqual(@as(?usize, null), grain(128, 4, 32));
    try std.testing.expectEqual(@as(?usize, 512), grain(65536, 18, 32));
    try std.testing.expectEqual(@as(?usize, 4096), grain(65536, 8, 4096));
    var queue = Queue{
        .next = .init(std.math.maxInt(usize) - 17),
        .row_count = std.math.maxInt(usize),
        .grain = 256,
    };
    try std.testing.expectEqual(Range{ .start = std.math.maxInt(usize) - 17, .end = std.math.maxInt(usize) }, queue.take().?);
    try std.testing.expectEqual(@as(?Range, null), queue.take());
}
