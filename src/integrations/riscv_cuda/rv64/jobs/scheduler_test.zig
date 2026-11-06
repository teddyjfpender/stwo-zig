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
    /// Memory-plan tests: staged inputs and work words (0 = the original tiny job).
    staged: usize = 0,
    work: usize = 0,
    pub fn classKey(self: *Tiny) [32]u8 {
        return @splat(@intFromEnum(self.kind));
    }
    pub fn footprint(self: *Tiny) api.Footprint {
        if (self.staged != 0) return .{ .device_words = self.staged + self.work, .staged_words = self.staged, .slab_words = 1 };
        return .{ .device_words = 256, .slab_words = 1 };
    }
    pub fn stage(self: *Tiny, s: *api.Stager) !void {
        if (self.staged == 0) return;
        const b = try s.alloc(self.staged);
        try s.upload(b, &.{ self.index, 1, 2, 3 });
    }
    pub fn enqueue(self: *Tiny, e: *api.Enqueue) !void {
        if (self.fail) return error.InjectedEnqueueFailure;
        if (self.work != 0) e.free(try e.alloc(self.work));
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
    make_fail_kind: ?S.Kind = null,
    staged: usize = 0,
    work: usize = 0,
    /// Async-prep tests: make is called from prep threads; model slow host prep.
    mutex: std.Thread.Mutex = .{},
    make_sleep_us: u64 = 0,
    fn make(raw: *anyopaque, kind: S.Kind, index: u32) anyerror!api.Job {
        const self: *Fac = @ptrCast(@alignCast(raw));
        if (self.make_sleep_us != 0) std.Thread.sleep(self.make_sleep_us * std.time.ns_per_us);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.make_fail_kind == kind) return error.InjectedMakeFailure;
        self.trace.add(kind, index, 'm');
        const t = try std.testing.allocator.create(Tiny);
        t.* = .{ .kind = kind, .index = index, .trace = &self.trace, .fail = self.fail_kind == kind, .staged = self.staged, .work = self.work };
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

fn leafDeps(_: *anyopaque, a: std.mem.Allocator, ordinal: u32, r: *const S.Request, out: *std.ArrayListUnmanaged(u32)) anyerror!void {
    try out.append(a, r.stage2[ordinal % r.stage2.len]);
    if (ordinal == 0) try out.append(a, r.truth[0]);
}

fn workers(out: []*W.Worker) !void {
    for (out, 0..) |*w, i| w.* = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = @intCast(i), .arena_words = 1 << 14, .pinned_slot_words = 1 << 10 });
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
    // Request receipt and measured class plans serialize (diagnostic outputs).
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir);
    try @import("request.zig").writeReceipt(std.testing.allocator, &g, &s, 26235156, 1, dir);
    const text = try tmp.dir.readFileAlloc(std.testing.allocator, "m8-jobs.json", 1 << 20);
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"native_stage1\"") != null);
    const plans = try std.fs.path.join(std.testing.allocator, &.{ dir, "plans.json" });
    defer std.testing.allocator.free(plans);
    try @import("mod.zig").writePlans(std.testing.allocator, &ws, plans);
    const stats = try ws[0].classStats(std.testing.allocator);
    defer std.testing.allocator.free(stats);
    var jobs: u64 = 0;
    for (stats) |e| jobs += e.stat.jobs;
    const other = try ws[1].classStats(std.testing.allocator);
    defer std.testing.allocator.free(other);
    for (other) |e| jobs += e.stat.jobs;
    try std.testing.expectEqual(s.dispatched, jobs);
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

test "a factory failure drains in-flight jobs before returning" {
    fake.reset();
    var ws: [2]*W.Worker = undefined;
    try workers(&ws);
    defer for (ws) |w| w.destroy();
    var g = S.Graph{ .a = std.testing.allocator };
    defer g.deinit();
    const plan = try Dag.Plan.initArity(3, 2);
    var fac = Fac{ .make_fail_kind = .truth };
    defer fac.deinit();
    var r = try S.buildRequest(&g, .{ .segments = 3, .truths = 1 }, &plan, undefined, leafDeps);
    defer r.deinit(std.testing.allocator);
    for (r.stage1) |id| g.nodes.items[id].released = true;
    var s = try S.Scheduler.init(std.testing.allocator, &g, fac.factory(), &ws);
    defer s.deinit();
    try std.testing.expectError(error.InjectedMakeFailure, s.run());
    try std.testing.expectEqual(@as(usize, 0), s.running);
    for (ws) |w| try std.testing.expectEqual(@as(usize, 0), w.load());
}

test "placement by footprint: a request whose classes cannot overlap pairwise completes under the policy" {
    // Every class: 4 granules staged, 8 granules of work → arena peak 14 granules
    // (staged + channel state + slab + work). Arena 16 granules: no class fits beside
    // another's staged inputs, so every worker must serialize, never fail a job.
    const P = @import("plan.zig");
    const gr = W.Arena.granule;
    var text: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer text.deinit();
    try text.writer.print("{{\"schema\":\"{s}\",\"gpu\":{{\"arena_words\":{d},\"max_concurrent_jobs\":1}},\"classes\":[", .{ P.schema, 16 * gr });
    for ([_]S.Kind{ .native_stage1, .native_stage2, .truth, .leaf, .fold }, 0..) |k, i| {
        const key: [32]u8 = @splat(@intFromEnum(k));
        try text.writer.print("{s}{{\"label\":\"{s}\",\"class_key\":\"{s}\",\"peak_words\":{d},\"staged_words\":{d},\"slab_words\":1,\"max_concurrent\":1}}", .{ if (i == 0) "" else ",", @tagName(k), std.fmt.bytesToHex(key, .lower), 14 * gr, 4 * gr });
    }
    try text.writer.writeAll("]}");
    const policy = try P.Policy.parse(std.testing.allocator, text.written());
    defer policy.deinit();
    _ = try P.checkPolicyLayout(policy);
    fake.reset();
    var ws: [2]*W.Worker = undefined;
    for (&ws, 0..) |*w, i| w.* = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = @intCast(i), .arena_words = 1 << 20, .pinned_slot_words = 1 << 10, .plan = policy });
    defer for (ws) |w| w.destroy();
    var g = S.Graph{ .a = std.testing.allocator };
    defer g.deinit();
    const plan = try Dag.Plan.initArity(6, 2);
    var fac = Fac{ .staged = 4 * gr, .work = 8 * gr };
    defer fac.deinit();
    var r = try S.buildRequest(&g, .{ .segments = 4, .truths = 2, .truth_after_seal = false }, &plan, undefined, leafDeps);
    defer r.deinit(std.testing.allocator);
    for (r.stage1) |id| g.nodes.items[id].released = true;
    var s = try S.Scheduler.init(std.testing.allocator, &g, fac.factory(), &ws);
    defer s.deinit();
    try s.run();
    try std.testing.expectEqual(@as(usize, 4 + 4 + 2 + plan.count), s.dispatched);
    try std.testing.expectEqual(s.dispatched, fake.counters.host_waits);
    var over: u64 = 0;
    for (ws) |w| {
        try std.testing.expectEqual(@as(usize, 16 * gr), w.config.arena_words);
        const stats = try w.classStats(std.testing.allocator);
        defer std.testing.allocator.free(stats);
        for (stats) |e| over += e.stat.over_plan;
    }
    try std.testing.expectEqual(@as(u64, 0), over);
}

test "async prep: the request DAG completes with make on a prep pool, dependency order intact" {
    fake.reset();
    var ws: [2]*W.Worker = undefined;
    try workers(&ws);
    defer for (ws) |w| w.destroy();
    var g = S.Graph{ .a = std.testing.allocator };
    defer g.deinit();
    const plan = try Dag.Plan.initArity(6, 2);
    var fac = Fac{ .make_sleep_us = 300 };
    defer fac.deinit();
    var r = try S.buildRequest(&g, .{ .segments = 4, .truths = 1 }, &plan, undefined, leafDeps);
    defer r.deinit(std.testing.allocator);
    var s = try S.Scheduler.initWith(std.testing.allocator, &g, fac.factory(), &ws, .{ .prep_threads = 3 });
    defer s.deinit();
    const t = try std.Thread.spawn(.{}, Releaser.run, .{ &s, r.stage1 });
    try s.run();
    t.join();
    const tr = &fac.trace;
    for (0..4) |i| try std.testing.expect(tr.at(.seal, 0, 'h') < tr.at(.native_stage2, @intCast(i), 'm'));
    for (0..plan.count) |node| {
        const n = plan.nodes[node];
        const id: u32 = @intCast(node);
        if (n.isLeaf()) {
            try std.testing.expect(tr.at(.native_stage2, @intCast(n.first_leaf % 4), 'd') < tr.at(.leaf, id, 'm'));
            try std.testing.expect(tr.at(.leaf, id, 'd') != std.math.maxInt(usize));
        } else for (n.kids()) |kid| {
            const kk: S.Kind = if (plan.nodes[kid].isLeaf()) .leaf else .fold;
            try std.testing.expect(tr.at(kk, @intCast(kid), 'd') < tr.at(.fold, id, 'm'));
        }
    }
    try std.testing.expectEqual(@as(usize, 4 + 4 + 1 + plan.count), s.dispatched);
    try std.testing.expectEqual(s.dispatched, fake.counters.host_waits);
    try std.testing.expectEqual(@as(usize, 0), s.preparing);
    // Several makes were in flight at once (stage-2 x4 + truth after the seal).
    try std.testing.expect(s.max_preparing > 1);
}

test "async prep: a make failure drains in-flight preparations and jobs; nothing leaks" {
    fake.reset();
    var ws: [2]*W.Worker = undefined;
    try workers(&ws);
    defer for (ws) |w| w.destroy();
    var g = S.Graph{ .a = std.testing.allocator };
    defer g.deinit();
    const plan = try Dag.Plan.initArity(4, 2);
    var fac = Fac{ .make_fail_kind = .truth, .make_sleep_us = 200 };
    defer fac.deinit();
    var r = try S.buildRequest(&g, .{ .segments = 3, .truths = 1 }, &plan, undefined, leafDeps);
    defer r.deinit(std.testing.allocator);
    for (r.stage1) |id| g.nodes.items[id].released = true;
    var s = try S.Scheduler.initWith(std.testing.allocator, &g, fac.factory(), &ws, .{ .prep_threads = 2 });
    defer s.deinit();
    try std.testing.expectError(error.InjectedMakeFailure, s.run());
    try std.testing.expectEqual(@as(usize, 0), s.running);
    try std.testing.expectEqual(@as(usize, 0), s.preparing);
    for (ws) |w| try std.testing.expectEqual(@as(usize, 0), w.load());
    try std.testing.expectEqual(std.math.maxInt(usize), fac.trace.at(.leaf, 0, 'm'));
}

test "async prep: an enqueue failure with prep threads returns after everything drained" {
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
    var s = try S.Scheduler.initWith(std.testing.allocator, &g, fac.factory(), &ws, .{ .prep_threads = 2 });
    defer s.deinit();
    try std.testing.expectError(error.InjectedEnqueueFailure, s.run());
    try std.testing.expectEqual(@as(usize, 0), s.running);
    try std.testing.expectEqual(@as(usize, 0), s.preparing);
}
