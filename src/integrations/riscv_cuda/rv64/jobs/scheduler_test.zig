const std = @import("std");
const S = @import("scheduler.zig");
const W = @import("worker.zig");
const api = @import("api.zig");
const fake = @import("fake.zig");
const Dag = @import("rv64_ready_dag");

const Trace = struct {
    mutex: std.Thread.Mutex = .{},
    order: std.ArrayListUnmanaged(struct { kind: S.Kind, index: u32, what: u8 }) = .empty,
    fn add(self: *Trace, kind: S.Kind, index: u32, what: u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.order.append(std.heap.page_allocator, .{ .kind = kind, .index = index, .what = what }) catch unreachable;
    }
    fn at(self: *Trace, kind: S.Kind, index: u32, what: u8) usize {
        for (self.order.items, 0..) |e, i| if (e.kind == kind and e.index == index and e.what == what) return i;
        return std.math.maxInt(usize);
    }
};

const Tiny = struct {
    kind: S.Kind,
    index: u32,
    trace: *Trace,
    fail: bool = false,
    pub fn classKey(self: *Tiny) [32]u8 {
        return @splat(@intFromEnum(self.kind));
    }
    pub fn footprint(_: *Tiny) api.Footprint {
        return .{ .device_words = 256, .slab_words = 1 };
    }
    pub fn stage(_: *Tiny, _: *api.Stager) !void {}
    pub fn enqueue(self: *Tiny, e: *api.Enqueue) !void {
        if (self.fail) return error.InjectedEnqueueFailure;
        e.slab.device.ptr[0] = self.index;
    }
    pub fn finish(self: *Tiny, v: api.SlabView) !void {
        try std.testing.expectEqual(self.index, v.words[0]);
        self.trace.add(self.kind, self.index, 'f');
    }
    pub fn abort(self: *Tiny) void {
        self.trace.add(self.kind, self.index, 'a');
    }
};

const Fac = struct {
    trace: Trace = .{},
    jobs: std.ArrayListUnmanaged(*Tiny) = .empty,
    fail_kind: ?S.Kind = null,
    fn make(raw: *anyopaque, kind: S.Kind, index: u32) anyerror!api.Job {
        const self: *Fac = @ptrCast(@alignCast(raw));
        self.trace.add(kind, index, 'm');
        const t = try std.testing.allocator.create(Tiny);
        t.* = .{ .kind = kind, .index = index, .trace = &self.trace, .fail = self.fail_kind == kind };
        try self.jobs.append(std.testing.allocator, t);
        return api.Job.from(Tiny, t);
    }
    fn done(raw: *anyopaque, kind: S.Kind, index: u32, _: api.Completion) anyerror!void {
        const self: *Fac = @ptrCast(@alignCast(raw));
        self.trace.add(kind, index, 'd');
    }
    fn host(raw: *anyopaque, kind: S.Kind, index: u32) anyerror!void {
        const self: *Fac = @ptrCast(@alignCast(raw));
        self.trace.add(kind, index, 'h');
    }
    fn deinit(self: *Fac) void {
        for (self.jobs.items) |t| std.testing.allocator.destroy(t);
        self.jobs.deinit(std.testing.allocator);
        self.trace.order.deinit(std.heap.page_allocator);
    }
    fn factory(self: *Fac) S.Factory {
        return .{ .ctx = self, .make = make, .done = done, .host = host };
    }
};

fn leafDeps(_: *anyopaque, ordinal: u32, r: *const S.Request, out: *std.ArrayListUnmanaged(u32)) anyerror!void {
    try out.append(std.testing.allocator, r.stage2[ordinal % r.stage2.len]);
    if (ordinal == 0) try out.append(std.testing.allocator, r.truth[0]);
}

fn workers(out: []*W.Worker) !void {
    for (out, 0..) |*w, i| w.* = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .device = @intCast(i), .arena_words = 1 << 14, .pinned_slot_words = 1 << 10 });
}

const Releaser = struct {
    fn run(s: *S.Scheduler, ids: []const u32) void {
        for (ids) |id| {
            std.Thread.sleep(200 * std.time.ns_per_us);
            s.release(id) catch unreachable;
        }
    }
};

test "request DAG: stage-1 on release, seal barrier, stage-2/truth, leaves on natives, folds on children" {
    fake.reset();
    var ws: [2]*W.Worker = undefined;
    try workers(&ws);
    defer for (ws) |w| w.destroy();
    var g = S.Graph{ .a = std.testing.allocator };
    defer g.deinit();
    const plan = try Dag.Plan.initArity(5, 2);
    var fac = Fac{};
    defer fac.deinit();
    var r = try S.buildRequest(&g, .{ .segments = 3, .truths = 1 }, &plan, undefined, leafDeps);
    defer r.deinit(std.testing.allocator);
    var s = try S.Scheduler.init(std.testing.allocator, &g, fac.factory(), &ws);
    defer s.deinit();
    const t = try std.Thread.spawn(.{}, Releaser.run, .{ &s, r.stage1 });
    try s.run();
    t.join();
    const tr = &fac.trace;
    for (0..3) |i| {
        const k: u32 = @intCast(i);
        try std.testing.expect(tr.at(.native_stage1, k, 'd') < tr.at(.seal, 0, 'h'));
        try std.testing.expect(tr.at(.seal, 0, 'h') < tr.at(.native_stage2, k, 'm'));
    }
    try std.testing.expect(tr.at(.seal, 0, 'h') < tr.at(.truth, 0, 'm'));
    for (0..plan.count) |node| {
        const n = plan.nodes[node];
        const kind: S.Kind = if (n.isLeaf()) .leaf else .fold;
        const id: u32 = @intCast(node);
        try std.testing.expect(tr.at(kind, id, 'd') != std.math.maxInt(usize));
        if (n.isLeaf()) {
            try std.testing.expect(tr.at(.native_stage2, @intCast(n.first_leaf % 3), 'd') < tr.at(.leaf, id, 'm'));
        } else for (n.kids()) |kid| {
            const kk: S.Kind = if (plan.nodes[kid].isLeaf()) .leaf else .fold;
            try std.testing.expect(tr.at(kk, @intCast(kid), 'd') < tr.at(.fold, id, 'm'));
        }
    }
    try std.testing.expect(tr.at(.leaf, 0, 'm') > tr.at(.truth, 0, 'd'));
    try std.testing.expectEqual(@as(usize, 3 + 3 + 1 + plan.count), s.dispatched);
    try std.testing.expect(s.affinity_hits > 0);
    try std.testing.expectEqual(s.dispatched, fake.counters.host_waits); // one wait per job, none per stage
}

test "a failed job fails the request after in-flight jobs complete; undispatched jobs are aborted" {
    fake.reset();
    var ws: [1]*W.Worker = undefined;
    try workers(&ws);
    defer ws[0].destroy();
    var g = S.Graph{ .a = std.testing.allocator };
    defer g.deinit();
    const plan = try Dag.Plan.initArity(2, 2);
    var fac = Fac{ .fail_kind = .native_stage2 };
    defer fac.deinit();
    var r = try S.buildRequest(&g, .{ .segments = 2, .truths = 1 }, &plan, undefined, leafDeps);
    defer r.deinit(std.testing.allocator);
    for (r.stage1) |id| g.nodes.items[id].released = true;
    var s = try S.Scheduler.init(std.testing.allocator, &g, fac.factory(), &ws);
    defer s.deinit();
    try std.testing.expectError(error.InjectedEnqueueFailure, s.run());
    try std.testing.expectEqual(@as(usize, 0), s.running);
    try std.testing.expectEqual(std.math.maxInt(usize), fac.trace.at(.leaf, 0, 'm'));
}

test "graph rejects forward dependencies" {
    var g = S.Graph{ .a = std.testing.allocator };
    defer g.deinit();
    _ = try g.add(.truth, 0, 1, &.{}, true);
    try std.testing.expectError(error.DependencyNotYetDefined, g.add(.leaf, 0, 1, &.{1}, true));
}
