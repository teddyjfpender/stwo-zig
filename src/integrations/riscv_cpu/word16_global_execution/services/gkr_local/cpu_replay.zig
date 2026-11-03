//! Optional bounded resident CPU replay. Compact advice remains transport;
//! original MAIN roots and native GKR/binding authority stay mandatory.
const std = @import("std");
const Pipeline = @import("../pipeline.zig");
const Worker = @import("cpu_worker.zig").CpuWorker;
pub const Capture = @import("../../../word16_execution/replay_capture.zig").Capture;
pub const Owner = struct {
    context: *anyopaque,
    retained_host_bytes: usize,
    park: *const fn (*anyopaque, *Worker) anyerror!void,
    restore: *const fn (*anyopaque, *Worker) anyerror!void,
    release: *const fn (*anyopaque) void,
    pub fn deinit(self: *Owner) void {
        self.release(self.context);
        self.* = undefined;
    }
};
pub const Stage = struct {
    context: *anyopaque,
    estimate: *const fn (*anyopaque, Pipeline.DeviceSourceStage.Request) anyerror!usize,
    prepare: *const fn (*anyopaque, std.mem.Allocator, Pipeline.DeviceSourceStage.Request) anyerror!Owner,
};
