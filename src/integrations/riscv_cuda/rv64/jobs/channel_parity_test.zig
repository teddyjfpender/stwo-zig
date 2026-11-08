const std = @import("std");
const P = @import("channel_parity.zig");
const W = @import("worker.zig");
const api = @import("api.zig");
const fake = @import("fake.zig");
const Raw = @import("stwo_core").channel.raw_mod_m31;

const One = struct {
    result: ?anyerror!void = null,
    fn sink(self: *One) W.Sink {
        return .{ .ctx = self, .done = done };
    }
    fn done(raw: *anyopaque, c: api.Completion) void {
        const self: *One = @ptrCast(@alignCast(raw));
        self.result = c.result;
    }
};

fn runOnModel(job: *P.ParityJob) !void {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .device = 0, .arena_words = 1 << 16, .pinned_slot_words = 1 << 16 });
    var one: One = .{};
    try w.submit(api.Job.from(P.ParityJob, job), one.sink());
    while (w.load() != 0) std.Thread.yield() catch {};
    w.destroy();
    return one.result.?;
}

test "device channel model equals the host Om31Channel at every boundary" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const script = try P.coverageScript(arena.allocator(), false);
    var job = try P.ParityJob.init(script);
    try runOnModel(&job);
    try std.testing.expectEqual(script.ops.len, job.checked_ops);
    try std.testing.expectEqual(@as(usize, 1), fake.counters.host_waits);
    try std.testing.expectEqual(@as(usize, 1), fake.counters.d2h);
}

test "a diverging host sequence is caught at the exact op" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const script = try P.coverageScript(arena.allocator(), false);
    var job = try P.ParityJob.init(script);
    // Device sees the original; host replay sees op 4 with one changed felt word.
    const ops = try arena.allocator().dupe(P.Op, script.ops);
    const felts = try arena.allocator().dupe(u32, ops[4].mix_felts);
    felts[3] +%= 1;
    ops[4] = .{ .mix_felts = felts };
    const Swap = struct {
        inner: *P.ParityJob,
        ops: []const P.Op,
        pub fn classKey(s: *@This()) [32]u8 {
            return s.inner.classKey();
        }
        pub fn footprint(s: *@This()) api.Footprint {
            return s.inner.footprint();
        }
        pub fn stage(s: *@This(), st: *api.Stager) !void {
            return s.inner.stage(st);
        }
        pub fn enqueue(s: *@This(), e: *api.Enqueue) !void {
            try s.inner.enqueue(e);
            s.inner.script.ops = s.ops;
        }
        pub fn finish(s: *@This(), v: api.SlabView) !void {
            return s.inner.finish(v);
        }
        pub fn abort(s: *@This()) void {
            s.inner.abort();
        }
    };
    var swap = Swap{ .inner = &job, .ops = ops };
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .device = 0, .arena_words = 1 << 16, .pinned_slot_words = 1 << 16 });
    var one: One = .{};
    try w.submit(api.Job.from(@TypeOf(swap), &swap), one.sink());
    while (w.load() != 0) std.Thread.yield() catch {};
    w.destroy();
    try std.testing.expectError(error.ParitySnapshotMismatch, one.result.?);
    try std.testing.expectEqual(@as(usize, 4), job.mismatch_op.?);
}

test "a host sequence recorded through om31_observer replays on the device channel" {
    var rec = P.Recorder{ .a = std.testing.allocator };
    defer rec.deinit();
    var host = Raw.Om31Channel.init();
    host.mixU32s(&.{ 7, 8, 9 });
    var observer = rec.observer(&host);
    const previous = Raw.om31_observer;
    Raw.om31_observer = &observer;
    host.mixU64(0x1234_5678_9abc_def0);
    _ = host.drawSecureFelt();
    _ = host.drawU32s();
    host.mixU32s(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    const felts = try host.drawSecureFelts(std.testing.allocator, 3);
    host.mixFelts(felts);
    std.testing.allocator.free(felts);
    _ = host.drawSecureFelt();
    Raw.om31_observer = previous;
    const script = try rec.script();
    try std.testing.expectEqual(@as(usize, 9), script.ops.len);
    var job = try P.ParityJob.init(script);
    try runOnModel(&job);
    try std.testing.expectEqual(script.ops.len, job.checked_ops);
}
