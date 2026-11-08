//! Upload a small, block-public leaf program during install only.
const std = @import("std");
const L = @import("native_leaf_wire.zig");
const api = @import("api.zig");
const W = @import("worker.zig").Worker;
pub const Job = struct {
    program: *const L.Program,
    pub fn classKey(self: *Job) [32]u8 {
        return self.program.key();
    }
    pub fn footprint(self: *Job) api.Footprint {
        return .{ .device_words = 64, .pinned_words = self.program.words.len };
    }
    pub fn stage(self: *Job, s: *api.Stager) !void {
        const p = try s.persistent(self.program.key(), self.program.words.len);
        if (p.fresh) try s.upload(p.buffer, self.program.words);
    }
    pub fn enqueue(_: *Job, _: *api.Enqueue) !void {}
    pub fn finish(_: *Job, _: api.SlabView) !void {}
    pub fn abort(_: *Job) void {}
};
pub fn warm(program: *const L.Program, worker: *W) !void {
    var job = Job{ .program = program };
    var done = struct {
        event: std.Thread.ResetEvent = .{},
        result: anyerror!void = {},
        fn call(raw: *anyopaque, completion: api.Completion) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.result = completion.result;
            self.event.set();
        }
    }{};
    try worker.submit(api.Job.from(Job, &job), .{ .ctx = &done, .done = @TypeOf(done).call });
    done.event.wait();
    try done.result;
}
