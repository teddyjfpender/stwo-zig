const std = @import("std");
const R = @import("request.zig");
const S = @import("scheduler.zig");
const W = @import("worker.zig");
const api = @import("api.zig");
const fake = @import("fake.zig");
const Dag = @import("rv64_ready_dag");

/// A provider over tiny jobs: 2 segments, 1 truth, 3 recursion leaves.
const Fake = struct {
    a: std.mem.Allocator,
    jobs: std.ArrayListUnmanaged(*Job) = .empty,
    request: ?S.Request = null,
    plan: Dag.Plan = undefined,
    sealed: bool = false,
    published: std.ArrayListUnmanaged(u64) = .empty,
    ended: usize = 0,
    const Job = struct {
        index: u32,
        pub fn classKey(_: *Job) [32]u8 {
            return @splat(7);
        }
        pub fn footprint(_: *Job) api.Footprint {
            return .{ .device_words = 128, .slab_words = 1 };
        }
        pub fn stage(_: *Job, _: *api.Stager) !void {}
        pub fn enqueue(self: *Job, e: *api.Enqueue) !void {
            e.slab.device.ptr[0] = self.index;
        }
        pub fn finish(self: *Job, v: api.SlabView) !void {
            if (v.words[0] != self.index) return error.WrongSlab;
        }
        pub fn abort(_: *Job) void {}
    };
    fn of(raw: *anyopaque) *Fake {
        return @ptrCast(@alignCast(raw));
    }
    fn admit(_: *anyopaque, text: []const u8) anyerror!u64 {
        const block = std.fmt.parseUnsigned(u64, text, 10) catch return error.ResidentRequestMalformed;
        if (block != 26235156) return error.MissingResidentBatchBlock;
        return block;
    }
    fn leafDeps(_: *anyopaque, a: std.mem.Allocator, ordinal: u32, r: *const S.Request, out: *std.ArrayListUnmanaged(u32)) anyerror!void {
        try out.append(a, r.stage2[ordinal % 2]);
    }
    fn begin(raw: *anyopaque, _: u64, g: *S.Graph, _: []const *W.Worker, _: []const u8) anyerror!S.Factory {
        const self = of(raw);
        self.plan = try Dag.Plan.initArity(3, 2);
        self.request = try S.buildRequest(g, .{ .segments = 2, .truths = 1 }, &self.plan, self, leafDeps);
        self.sealed = false;
        return .{ .ctx = self, .make = make, .done = done, .host = seal };
    }
    fn started(raw: *anyopaque, s: *S.Scheduler) anyerror!void {
        for (of(raw).request.?.stage1) |id| try s.release(id); // capture: everything at once
    }
    fn make(raw: *anyopaque, _: S.Kind, index: u32) anyerror!api.Job {
        const self = of(raw);
        const j = try self.a.create(Job);
        j.* = .{ .index = index };
        try self.jobs.append(self.a, j);
        return api.Job.from(Job, j);
    }
    fn done(_: *anyopaque, _: S.Kind, _: u32, _: api.Completion) anyerror!void {}
    fn seal(raw: *anyopaque, _: S.Kind, _: u32) anyerror!void {
        of(raw).sealed = true;
    }
    fn publish(raw: *anyopaque, block: u64, out: []const u8) anyerror!void {
        const self = of(raw);
        if (!self.sealed) return error.PublishedBeforeSeal;
        var dir = try std.fs.cwd().openDir(out, .{});
        defer dir.close();
        try dir.writeFile(.{ .sub_path = "bundle.json", .data = "{}" });
        try self.published.append(self.a, block);
    }
    fn end(raw: *anyopaque) void {
        const self = of(raw);
        if (self.request) |*r| r.deinit(std.testing.allocator);
        self.request = null;
        self.ended += 1;
    }
    fn provider(self: *Fake) R.Provider {
        return .{ .ctx = self, .admit = admit, .begin = begin, .started = started, .publish = publish, .end = end };
    }
    fn deinit(self: *Fake) void {
        for (self.jobs.items) |j| self.a.destroy(j);
        self.jobs.deinit(self.a);
        self.published.deinit(self.a);
    }
};

test "serve answers spool requests through a provider: proofs, rejections, receipts, STOP" {
    fake.reset();
    var ws: [2]*W.Worker = undefined;
    for (&ws, 0..) |*w, i| w.* = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .device = @intCast(i), .arena_words = 1 << 12, .pinned_slot_words = 1 << 10 });
    defer for (ws) |w| w.destroy();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("inbox");
    try tmp.dir.writeFile(.{ .sub_path = "inbox/a-cold.request", .data = "26235156\n" });
    try tmp.dir.writeFile(.{ .sub_path = "inbox/b-bad.request", .data = "12345" });
    try tmp.dir.writeFile(.{ .sub_path = "inbox/c-warm.request", .data = "26235156" });
    try tmp.dir.writeFile(.{ .sub_path = "inbox/STOP", .data = "" });
    const spool = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(spool);
    var p = Fake{ .a = std.testing.allocator };
    defer p.deinit();
    try R.serve(std.testing.allocator, p.provider(), &ws, spool, 1);
    try std.testing.expectEqualSlices(u64, &.{ 26235156, 26235156 }, p.published.items);
    try std.testing.expectEqual(@as(usize, 2), p.ended);
    var buf: [256]u8 = undefined;
    try std.testing.expect(std.mem.indexOf(u8, try tmp.dir.readFile("done/a-cold.json", &buf), "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, try tmp.dir.readFile("done/b-bad.json", &buf), "MissingResidentBatchBlock") != null);
    try std.testing.expect(std.mem.indexOf(u8, try tmp.dir.readFile("done/c-warm.json", &buf), "\"sequence\":1") != null);
    const receipt = try tmp.dir.readFileAlloc(std.testing.allocator, "out/c-warm/m8-jobs.json", 1 << 20);
    defer std.testing.allocator.free(receipt);
    try std.testing.expect(std.mem.indexOf(u8, receipt, "\"jobs\": 10") != null); // 2+2+1 natives + 5 recursion nodes
    _ = try tmp.dir.statFile("out/a-cold/bundle.json");
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile("inbox/a-cold.request"));
}
