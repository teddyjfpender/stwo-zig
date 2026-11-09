//! Allocation-free coordination primitives for prepared-domain row shards.

const std = @import("std");

pub const TelemetrySnapshot = struct {
    child_submissions: u64 = 0,
    child_completions: u64 = 0,
    range_failures: u64 = 0,
    local_cancellation_requests: u64 = 0,

    pub fn delta(after: TelemetrySnapshot, before: TelemetrySnapshot) TelemetrySnapshot {
        return .{
            .child_submissions = after.child_submissions -| before.child_submissions,
            .child_completions = after.child_completions -| before.child_completions,
            .range_failures = after.range_failures -| before.range_failures,
            .local_cancellation_requests = after.local_cancellation_requests -|
                before.local_cancellation_requests,
        };
    }
};

pub const Telemetry = struct {
    child_submissions: std.atomic.Value(u64) = .init(0),
    child_completions: std.atomic.Value(u64) = .init(0),
    range_failures: std.atomic.Value(u64) = .init(0),
    local_cancellation_requests: std.atomic.Value(u64) = .init(0),

    pub fn snapshot(self: *const @This()) TelemetrySnapshot {
        return .{
            .child_submissions = self.child_submissions.load(.monotonic),
            .child_completions = self.child_completions.load(.monotonic),
            .range_failures = self.range_failures.load(.monotonic),
            .local_cancellation_requests = self.local_cancellation_requests.load(.monotonic),
        };
    }

    pub fn recordChildSubmission(self: *@This()) void {
        _ = self.child_submissions.fetchAdd(1, .monotonic);
    }

    pub fn recordChildCompletion(self: *@This()) void {
        _ = self.child_completions.fetchAdd(1, .monotonic);
    }

    pub fn recordRangeFailure(self: *@This()) void {
        _ = self.range_failures.fetchAdd(1, .monotonic);
    }

    pub fn recordLocalCancellation(self: *@This()) void {
        _ = self.local_cancellation_requests.fetchAdd(1, .monotonic);
    }
};

/// A failure in range `i` suppresses only ranges with a larger index. Lower
/// ranges keep running, so the post-join ascending scan cannot depend on which
/// helper happened to fail first.
pub const FailureBoundary = struct {
    first_failing_range: std.atomic.Value(usize) = .init(std.math.maxInt(usize)),

    pub fn reset(self: *@This()) void {
        self.first_failing_range.store(std.math.maxInt(usize), .release);
    }

    pub fn shouldCancel(self: *const @This(), range_index: usize) bool {
        return self.first_failing_range.load(.acquire) < range_index;
    }

    /// Publishes a failure before higher ranges make their next cancellation
    /// decision. Returns true when this range lowered the canonical boundary.
    pub fn recordFailure(self: *@This(), range_index: usize) bool {
        var observed = self.first_failing_range.load(.acquire);
        while (range_index < observed) {
            if (self.first_failing_range.cmpxchgWeak(
                observed,
                range_index,
                .acq_rel,
                .acquire,
            )) |actual| {
                observed = actual;
                continue;
            }
            return true;
        }
        return false;
    }
};

test "prepared parallel failure boundary preserves canonical range priority" {
    var boundary = FailureBoundary{};
    try std.testing.expect(boundary.recordFailure(3));
    try std.testing.expect(!boundary.shouldCancel(0));
    try std.testing.expect(!boundary.shouldCancel(3));
    try std.testing.expect(boundary.shouldCancel(4));

    try std.testing.expect(boundary.recordFailure(1));
    try std.testing.expect(!boundary.shouldCancel(0));
    try std.testing.expect(!boundary.shouldCancel(1));
    try std.testing.expect(boundary.shouldCancel(2));
    try std.testing.expect(!boundary.recordFailure(3));

    boundary.reset();
    try std.testing.expect(!boundary.shouldCancel(std.math.maxInt(usize)));
}
