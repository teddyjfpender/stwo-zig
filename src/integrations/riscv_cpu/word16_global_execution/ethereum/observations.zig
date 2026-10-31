//! Per-physical-proof observations; disjoint timings are additive, whole-process
//! counters and peak RSS across overlapping stages are not.
const std = @import("std");
const Profile = @import("stwo_prover_api").stage_profile;
pub const Owner = struct {
    allocator: std.mem.Allocator,
    recorders: []Profile.Recorder,
    pointers: []?*Profile.Recorder,
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
    pub fn deinit(self: *Owner) void {
        for (self.recorders) |*r| r.deinit();
        self.allocator.free(self.recorders);
        self.allocator.free(self.pointers);
        self.* = undefined;
    }
};
