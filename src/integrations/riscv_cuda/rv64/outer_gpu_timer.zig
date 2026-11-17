//! Shared GPU event-pair lifetime and timing callback ownership.
const std = @import("std");
const K = @import("jobs/outer_kernels.zig");
const Events = @import("cuda_events.zig");
pub const GpuTimer = struct {
    api: *const Events.Api,
    events: [2]?*anyopaque = .{ null, null },
    ns: u64 = 0,
    pub fn timing(self: *GpuTimer) K.Timing {
        return .{ .ctx = self, .mark = mark, .resolve = resolve };
    }
    fn mark(raw: *anyopaque, end: bool, stream: *anyopaque) void {
        const self: *GpuTimer = @ptrCast(@alignCast(raw));
        const slot = &self.events[@intFromBool(end)];
        if (slot.* == null and self.api.create(slot, 0) != 0) slot.* = null;
        if (slot.*) |event| if (self.api.record(event, stream) != 0) {
            _ = self.api.destroy(event);
            slot.* = null;
        };
    }
    fn resolve(raw: *anyopaque) void {
        const self: *GpuTimer = @ptrCast(@alignCast(raw));
        const begin = self.events[0] orelse return;
        const end = self.events[1] orelse return;
        var ms: f32 = 0;
        if (self.api.elapsed(&ms, begin, end) == 0 and std.math.isFinite(ms) and ms >= 0) self.ns = @intFromFloat(@as(f64, ms) * 1e6);
    }
    pub fn deinit(self: *GpuTimer) void {
        for (self.events) |event| if (event) |e| {
            _ = self.api.destroy(e);
        };
        self.events = .{ null, null };
    }
};
