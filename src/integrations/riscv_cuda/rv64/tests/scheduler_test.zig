const std = @import("std");
const S = @import("../scheduler.zig");
const D = S.Device;
const fleet = [_]D{ .{ .ordinal = 2, .free_bytes = 1000, .reserve_bytes = 100 }, .{ .ordinal = 5, .free_bytes = 2000, .reserve_bytes = 200 } };
test "RV64 CUDA scheduler balances devices and fills independent lanes" {
    var s = try S.Scheduler.init(7, &fleet);
    const a = try s.acquire(0, 300);
    const b = try s.acquire(1, 300);
    const c = try s.acquire(2, 300);
    try std.testing.expectEqual(@as(u32, 2), a.device);
    try std.testing.expectEqual(@as(u32, 5), b.device);
    try std.testing.expectEqual(@as(u32, 5), c.device);
    try std.testing.expectEqual(@as(u8, 1), c.lane);
    const d = try s.acquire(3, 300);
    try std.testing.expectEqual(@as(u32, 2), d.device);
    try std.testing.expectError(error.FleetBusy, s.acquire(4, 1));
    try std.testing.expectEqual(@as(u128, 1200), s.liveBytes());
    // Completion order does not alter public ordinals.
    try s.retire(c, .success_joined);
    try s.retire(a, .success_joined);
    try s.retire(d, .success_joined);
    try s.retire(b, .success_joined);
    try std.testing.expectEqual(@as(u128, 0), s.liveBytes());
}
test "RV64 CUDA failed admission and poisoned jobs preserve credits" {
    var s = try S.Scheduler.init(9, &fleet);
    try std.testing.expectError(error.JobExceedsEveryDevice, s.acquire(0, 1801));
    try std.testing.expectError(error.InvalidJobSize, s.acquire(0, 0));
    try std.testing.expectEqual(@as(u128, 0), s.liveBytes());
    const a = try s.acquire(0, 700);
    try std.testing.expectError(error.DuplicateJob, s.acquire(0, 100));
    try s.fail(a);
    try std.testing.expectError(error.FailedJobCannotPublish, s.retire(a, .success_joined));
    try std.testing.expectEqual(@as(u128, 700), s.liveBytes());
    try s.retire(a, .aborted_joined);
    const b = try s.acquire(1, 700);
    try std.testing.expectError(error.InvalidTicket, s.retire(a, .aborted_joined));
    var forged = b;
    forged.bytes -= 1;
    try std.testing.expectError(error.InvalidTicket, s.retire(forged, .success_joined));
    var other = try S.Scheduler.init(10, &fleet);
    try std.testing.expectError(error.InvalidTicket, other.retire(b, .success_joined));
    try s.retire(b, .success_joined);
    try std.testing.expectError(error.InvalidTicket, s.retire(b, .success_joined));
}
test "RV64 CUDA 2 and 4 GPU capacity stays per device with reserve" {
    const p = try @import("../plan.zig").Plan.init(22, 13);
    var devices: [4]D = undefined;
    for (&devices, 0..) |*d, i| d.* = .{ .ordinal = @intCast(i), .free_bytes = 24 * 1024 * 1024 * 1024, .reserve_bytes = 2 * 1024 * 1024 * 1024, .lanes = 4 };
    inline for (.{ 2, 4 }) |n| {
        var s = try S.Scheduler.init(n, devices[0..n]);
        var tickets: [16]S.Ticket = undefined;
        for (tickets[0 .. n * 4], 0..) |*t, i| t.* = try s.acquire(i, p.total_bytes);
        try std.testing.expectEqual(@as(u128, n * 4) * p.total_bytes, s.liveBytes());
        try std.testing.expectError(error.FleetBusy, s.acquire(999, 1));
        for (tickets[0 .. n * 4]) |t| try s.retire(t, .success_joined);
        // Aggregate free memory never authorizes an oversized shard.
        try std.testing.expectError(error.JobExceedsEveryDevice, s.acquire(999, 23 * 1024 * 1024 * 1024));
    }
    try std.testing.expectError(error.InvalidFleet, S.Scheduler.init(1, devices[0..1]));
    try std.testing.expectError(error.InvalidFleet, S.Scheduler.init(0, devices[0..2]));
    devices[1].ordinal = 0;
    try std.testing.expectError(error.DuplicateDevice, S.Scheduler.init(1, devices[0..2]));
}
