//! Reopen of a persistent hybrid window (outer_job_factory.zig Hybrid.open):
//! every worker of a parked WorkerSet re-acquires its static arena, or none
//! does. WorkerSet.unpark runs every worker's unpark and returns the first
//! error without re-parking the workers that succeeded; left as is, those
//! keep a full arena through the next request's native window and every
//! later reopen fails WorkerNotParked. `unparkAll` parks them again.
const std = @import("std");

/// `set`: a *Jobs.WorkerSet (or a test double with `unpark(words)` and
/// `slice()` of workers with `isParked()` / `park(.{})`). On failure the
/// set is wholly parked again unless a re-park itself failed; the caller
/// checks `set.parked()` and tears the window down if not.
pub fn unparkAll(set: anytype, words: usize) @TypeOf(set.unpark(words)) {
    return set.unpark(words) catch |err| {
        for (set.slice()) |w| if (!w.isParked()) {
            if (w.park(.{})) |_| {} else |park_err| std.log.warn("GPU_M8_OUTER_WINDOW rollback park failed: {s}", .{@errorName(park_err)});
        };
        return err;
    };
}

// ---------------------------------------------------------------------------
const W = @import("worker.zig");
const fake = @import("fake.zig");
const g = W.Arena.granule;

/// Two workers; the second one's arena request is invalid (not a granule
/// multiple), as if its device could not provide the size the first got.
const PartialSet = struct {
    workers: [2]*W.Worker,
    fn slice(self: *PartialSet) []const *W.Worker {
        return &self.workers;
    }
    fn unpark(self: *PartialSet, words: usize) !u64 {
        var first: ?anyerror = null;
        for (self.workers, 0..) |w, i| {
            _ = w.unpark(if (i == 1) words + 1 else words) catch |err| {
                first = first orelse err;
            };
        }
        if (first) |err| return err;
        return 0;
    }
};

test "a reopen that fails on one worker parks every worker again; a later reopen succeeds" {
    fake.reset();
    const a = std.testing.allocator;
    var set = PartialSet{ .workers = undefined };
    for (&set.workers, 0..) |*w, i| w.* = try W.Worker.create(a, &fake.ops, .{ .plan_from_env = false, .device = @intCast(i), .arena_words = 64 * g, .pinned_slot_words = 1 << 12 });
    defer for (set.workers) |w| w.destroy();
    for (set.workers) |w| _ = try w.park(.{});
    try std.testing.expectError(error.InvalidArena, unparkAll(&set, 32 * g));
    // Worker 0 had unparked; it is parked again (its arena freed).
    for (set.workers) |w| try std.testing.expect(w.isParked());
    try std.testing.expectEqual(@as(usize, 0), set.workers[0].arenaWords());
    // The window is not wedged: the next reopen (both valid) works.
    for (set.workers) |w| _ = try w.unpark(32 * g);
    for (set.workers) |w| try std.testing.expect(!w.isParked());
}
