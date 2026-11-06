//! TruthJob (stream: recursion): a truth/service proof as one api.Job inside
//! the GPU's memory plan (truth region), replacing the legacy truth stages
//! and their ~14.75 GB outside-arena composition lease [M]. Design:
//! rv64-m8-gpu-native.md §3.3.
//!
//! STUB (contract landing): the job fails closed in `stage`.
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");

pub const TruthJob = struct {
    ordinal: u32,
    class: G.ClassKey,
    pub fn classKey(self: *TruthJob) [32]u8 {
        return self.class;
    }
    pub fn footprint(_: *TruthJob) api.Footprint {
        return .{ .device_words = 0 };
    }
    pub fn stage(_: *TruthJob, _: *api.Stager) !void {
        return error.M8GpuNativeTruthJobNotLanded;
    }
    pub fn enqueue(_: *TruthJob, _: *api.Enqueue) !void {
        return error.M8GpuNativeTruthJobNotLanded;
    }
    pub fn finish(_: *TruthJob, _: api.SlabView) !void {
        return error.M8GpuNativeTruthJobNotLanded;
    }
    pub fn abort(_: *TruthJob) void {}
    pub fn job(self: *TruthJob) api.Job {
        return api.Job.from(TruthJob, self);
    }
};

test "truth job stub is an api.Job" {
    var t = TruthJob{ .ordinal = 0, .class = @splat(3) };
    const j = t.job();
    try std.testing.expectEqual(@as(u8, 3), j.classKey()[0]);
}
