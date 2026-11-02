//! Per-physical-proof observations; disjoint timings are additive, whole-process
//! counters and peak RSS across overlapping stages are not.
const std = @import("std");
const Schedule = @import("../services/schedule.zig");
const Profile = @import("stwo_prover_api").stage_profile;
pub const Owner = struct {
    allocator: std.mem.Allocator,
    recorders: []Profile.Recorder,
    pointers: []?*Profile.Recorder,
    stage1_trace: []Schedule.Trace = &.{},
    stage2_trace: []Schedule.Trace = &.{},
    pub fn init(a: std.mem.Allocator, count: usize) !Owner {
        const recorders = try a.alloc(Profile.Recorder, count);
        errdefer a.free(recorders);
        const pointers = try a.alloc(?*Profile.Recorder, count);
        for (recorders, pointers) |*r, *p| {
            r.* = Profile.Recorder.initWithOptions(a, "rv64", "word16_ethereum_physical", .{ .capture_tasks = false, .capture_process_usage = true });
            p.* = r;
        }
        return .{ .allocator = a, .recorders = recorders, .pointers = pointers };
    }
    /// Opt-in allocation only; called before any worker receives these slices.
    /// Failure leaves both old fields empty and the Owner safe to retry/destroy.
    pub fn enableScheduleTraces(self: *Owner) !void {
        if (self.stage1_trace.len != 0 or self.stage2_trace.len != 0) return error.ScheduleTracesAlreadyEnabled;
        const first = try self.allocator.alloc(Schedule.Trace, self.recorders.len);
        errdefer self.allocator.free(first);
        const second = try self.allocator.alloc(Schedule.Trace, self.recorders.len);
        @memset(first, .{});
        @memset(second, .{});
        self.stage1_trace = first;
        self.stage2_trace = second;
    }
    pub fn deinit(self: *Owner) void {
        self.allocator.free(self.stage1_trace);
        self.allocator.free(self.stage2_trace);
        for (self.recorders) |*r| r.deinit();
        self.allocator.free(self.recorders);
        self.allocator.free(self.pointers);
        self.* = undefined;
    }
};

fn scheduleAllocationGate(a: std.mem.Allocator) !void {
    var owner = try Owner.init(a, 3);
    defer owner.deinit();
    try std.testing.expectEqual(@as(usize, 0), owner.stage1_trace.len);
    try owner.enableScheduleTraces();
    try std.testing.expectEqual(@as(usize, 3), owner.stage1_trace.len);
    try std.testing.expectEqual(@as(usize, 3), owner.stage2_trace.len);
    try std.testing.expectError(error.ScheduleTracesAlreadyEnabled, owner.enableScheduleTraces());
}
test "optional schedule observations clean every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, scheduleAllocationGate, .{});
}
