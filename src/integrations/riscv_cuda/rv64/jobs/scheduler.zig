//! Scheduler (spec §3.6): one request DAG onto the per-GPU DeviceWorkers.
//!
//! Nodes are device jobs (made lazily when ready, so a job can consume its
//! dependencies' `finish` outputs) or host steps (the native seal barrier),
//! run on the scheduler thread while the workers keep proving. The request
//! graph is: native stage-1 per segment (released as capture hands segments
//! over) → host seal over all stage-1 slabs → stage-2 per segment and truth
//! jobs → recursion leaves on their native completions → folds on children
//! (node identities and root-critical priorities from `ready_dag.Plan`).
//!
//! Placement, in order: key affinity (a worker whose previous job had the
//! same class key: warm class plan / graph), then root-critical (higher
//! priority first, then lower id), then the least-loaded worker. With a
//! memory policy (plan.zig) every choice is first restricted to workers the
//! job fits on by footprint (`Worker.fits`: its staged inputs beside the job
//! that worker would stage it next to); if none fits, the least-loaded
//! accepting worker still takes it and serializes the pair. A worker
//! receives a job only while `Worker.accepts()` (its 3-stage pipeline has a
//! free slot), so each worker holds one finishing, one enqueued and one
//! staged job at most.
const std = @import("std");
const api = @import("api.zig");
const W = @import("worker.zig");

pub const Kind = enum { native_stage1, seal, native_stage2, truth, leaf, fold };

pub const Factory = struct {
    ctx: *anyopaque,
    /// Build the job for node (kind, index) once all its dependencies finished.
    make: *const fn (*anyopaque, Kind, u32) anyerror!api.Job,
    /// Consume the completion on the scheduler thread (publish, chain outputs).
    done: *const fn (*anyopaque, Kind, u32, api.Completion) anyerror!void,
    /// Host step (only for `.seal`): runs on the scheduler thread.
    host: ?*const fn (*anyopaque, Kind, u32) anyerror!void = null,
};

pub const State = enum { waiting, ready, running, done, failed };

pub const Node = struct {
    kind: Kind,
    index: u32,
    priority: u32,
    released: bool,
    deps_first: u32,
    deps_len: u32,
    state: State = .waiting,
    job: ?api.Job = null,
    key: [32]u8 = @splat(0),
    worker: ?usize = null,
    receipt: api.Receipt = .{},
};

pub const Graph = struct {
    a: std.mem.Allocator,
    nodes: std.ArrayListUnmanaged(Node) = .empty,
    deps: std.ArrayListUnmanaged(u32) = .empty,
    pub fn deinit(self: *Graph) void {
        self.nodes.deinit(self.a);
        self.deps.deinit(self.a);
    }
    pub fn add(self: *Graph, kind: Kind, index: u32, priority: u32, deps: []const u32, released: bool) !u32 {
        const id: u32 = @intCast(self.nodes.items.len);
        for (deps) |d| if (d >= id) return error.DependencyNotYetDefined;
        const first: u32 = @intCast(self.deps.items.len);
        try self.deps.appendSlice(self.a, deps);
        try self.nodes.append(self.a, .{ .kind = kind, .index = index, .priority = priority, .released = released, .deps_first = first, .deps_len = @intCast(deps.len) });
        return id;
    }
    pub fn depsOf(self: *const Graph, id: u32) []const u32 {
        const n = self.nodes.items[id];
        return self.deps.items[n.deps_first..][0..n.deps_len];
    }
};

/// Native + recursion request shape. `leafDeps` names, for recursion leaf
/// ordinal `l`, the native node ids it proves (stage-2 / truth node ids, as
/// returned in `Request`).
pub const Shape = struct {
    segments: u32,
    truths: u32,
    /// Truth/service proofs need the sealed global relation; set false for
    /// truth families that are independent of the seal (they then fill the barrier).
    truth_after_seal: bool = true,
};

pub const Request = struct {
    stage1: []u32,
    seal: u32,
    stage2: []u32,
    truth: []u32,
    recursion: []u32, // by ready_dag node id
    pub fn deinit(self: *Request, a: std.mem.Allocator) void {
        a.free(self.stage1);
        a.free(self.stage2);
        a.free(self.truth);
        a.free(self.recursion);
    }
};

/// Priorities: native work gates everything, so it outranks recursion; within
/// recursion `plan.priority` (depth × 2 + leaf) puts the long root chain first.
pub const priority_stage1: u32 = 1 << 20;
pub const priority_stage2: u32 = (1 << 20) - 1;
pub const priority_truth: u32 = (1 << 20) - 2;

/// `plan` is a `ready_dag.Plan` (duck-typed: nodes, count, root, priority);
/// `leaf_deps(ctx, a, ordinal, request, out)` appends (with `a`) the native node ids of a leaf.
pub fn buildRequest(g: *Graph, shape: Shape, plan: anytype, leaf_ctx: *anyopaque, leaf_deps: *const fn (*anyopaque, std.mem.Allocator, u32, *const Request, *std.ArrayListUnmanaged(u32)) anyerror!void) !Request {
    const a = g.a;
    var r: Request = .{ .stage1 = try a.alloc(u32, shape.segments), .seal = 0, .stage2 = try a.alloc(u32, shape.segments), .truth = try a.alloc(u32, shape.truths), .recursion = try a.alloc(u32, plan.count) };
    errdefer r.deinit(a);
    for (r.stage1, 0..) |*id, i| id.* = try g.add(.native_stage1, @intCast(i), priority_stage1, &.{}, false);
    r.seal = try g.add(.seal, 0, priority_stage1, r.stage1, true);
    for (r.stage2, 0..) |*id, i| id.* = try g.add(.native_stage2, @intCast(i), priority_stage2, &.{r.seal}, true);
    for (r.truth, 0..) |*id, i| id.* = try g.add(.truth, @intCast(i), priority_truth, if (shape.truth_after_seal) &.{r.seal} else &.{}, true);
    var deps: std.ArrayListUnmanaged(u32) = .empty;
    defer deps.deinit(a);
    // ready_dag: children precede parents.
    for (0..plan.count) |node| {
        deps.clearRetainingCapacity();
        const n = plan.nodes[node];
        if (n.isLeaf()) {
            try leaf_deps(leaf_ctx, a, @intCast(n.first_leaf), &r, &deps);
            r.recursion[node] = try g.add(.leaf, @intCast(node), plan.priority(node), deps.items, true);
        } else {
            for (n.kids()) |kid| try deps.append(a, r.recursion[kid]);
            r.recursion[node] = try g.add(.fold, @intCast(node), plan.priority(node), deps.items, true);
        }
    }
    return r;
}

pub const Scheduler = struct {
    a: std.mem.Allocator,
    graph: *Graph,
    factory: Factory,
    workers: []const *W.Worker,
    last_key: [8]?[32]u8 = @splat(null),
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    completions: std.ArrayListUnmanaged(Finished) = .empty,
    releases: std.ArrayListUnmanaged(u32) = .empty,
    remaining: usize = 0,
    running: usize = 0,
    failure: ?anyerror = null, // scheduler thread only
    async_failure: ?anyerror = null, // set by worker threads under `mutex`
    dispatched: u64 = 0,
    affinity_hits: u64 = 0,
    /// Dispatches where no accepting worker fit the job by footprint (it serialized).
    unfit_dispatches: u64 = 0,

    const Finished = struct { id: u32, completion: api.Completion };

    pub fn init(a: std.mem.Allocator, graph: *Graph, factory: Factory, workers: []const *W.Worker) !Scheduler {
        if (workers.len == 0 or workers.len > 8) return error.InvalidWorkerSet;
        return .{ .a = a, .graph = graph, .factory = factory, .workers = workers, .remaining = graph.nodes.items.len };
    }
    pub fn deinit(self: *Scheduler) void {
        self.completions.deinit(self.a);
        self.releases.deinit(self.a);
    }

    /// Capture hands a native segment over (any thread).
    pub fn release(self: *Scheduler, id: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.releases.append(self.a, id);
        self.cond.signal();
    }

    fn sink(self: *Scheduler) W.Sink {
        return .{ .ctx = self, .done = onDone };
    }
    fn onDone(raw: *anyopaque, c: api.Completion) void {
        const self: *Scheduler = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.graph.nodes.items, 0..) |n, id| if (n.state == .running and n.job != null and n.job.?.ctx == c.job.ctx) {
            self.completions.append(self.a, .{ .id = @intCast(id), .completion = c }) catch {
                self.async_failure = self.async_failure orelse error.OutOfMemory;
            };
            break;
        };
        self.cond.signal();
    }

    fn depsDone(self: *Scheduler, id: u32) bool {
        for (self.graph.depsOf(id)) |d| if (self.graph.nodes.items[d].state != .done) return false;
        return true;
    }

    fn promote(self: *Scheduler) !void {
        for (self.graph.nodes.items, 0..) |*n, id| {
            if (n.state != .waiting or !n.released or !self.depsDone(@intCast(id))) continue;
            if (n.kind != .seal) {
                n.job = self.factory.make(self.factory.ctx, n.kind, n.index) catch |err| {
                    // Never return while jobs are in flight: latch and drain.
                    self.failure = self.failure orelse err;
                    n.state = .failed;
                    continue;
                };
                n.key = n.job.?.classKey();
            }
            n.state = .ready;
        }
    }

    fn better(a: Node, b: Node, a_id: usize, b_id: usize) bool {
        if (a.priority != b.priority) return a.priority > b.priority;
        return a_id < b_id;
    }

    /// One placement decision; returns false when nothing could be placed.
    fn placeOne(self: *Scheduler) !bool {
        var best_affine: ?struct { id: usize, worker: usize } = null;
        var best: ?usize = null;
        const nodes = self.graph.nodes.items;
        for (nodes, 0..) |n, id| {
            if (n.state != .ready or n.kind == .seal) continue;
            if (best == null or better(n, nodes[best.?], id, best.?)) best = id;
            for (self.workers, 0..) |w, wi| {
                const key = self.last_key[wi] orelse continue;
                if (!std.mem.eql(u8, &key, &n.key) or !w.accepts() or !w.fits(n.job.?)) continue;
                if (best_affine == null or better(n, nodes[best_affine.?.id], id, best_affine.?.id)) best_affine = .{ .id = id, .worker = wi };
            }
        }
        if (best_affine) |pick| {
            self.affinity_hits += 1;
            return self.dispatch(pick.id, pick.worker);
        }
        const id = best orelse return false;
        // Least loaded among workers it fits on; else least loaded overall.
        var fit: ?usize = null;
        var any: ?usize = null;
        var fit_load: usize = std.math.maxInt(usize);
        var any_load: usize = std.math.maxInt(usize);
        for (self.workers, 0..) |w, wi| {
            if (!w.accepts()) continue;
            const l = w.load();
            if (l < any_load) {
                any_load = l;
                any = wi;
            }
            if (l < fit_load and w.fits(nodes[id].job.?)) {
                fit_load = l;
                fit = wi;
            }
        }
        const target = fit orelse any orelse return false;
        if (fit == null) self.unfit_dispatches += 1;
        return self.dispatch(id, target);
    }

    fn dispatch(self: *Scheduler, id: usize, wi: usize) !bool {
        const n = &self.graph.nodes.items[id];
        self.workers[wi].submit(n.job.?, self.sink()) catch |err| switch (err) {
            error.WorkerBusy => return false,
            else => {
                // Worker closing or device-faulted: this job never ran.
                n.job.?.vtable.abort(n.job.?.ctx);
                n.state = .failed;
                self.failure = self.failure orelse err;
                return false;
            },
        };
        n.state = .running;
        n.worker = wi;
        self.last_key[wi] = n.key;
        self.running += 1;
        self.dispatched += 1;
        return true;
    }

    fn finishNode(self: *Scheduler, f: Finished) void {
        const n = &self.graph.nodes.items[f.id];
        self.running -= 1;
        n.receipt = f.completion.receipt;
        const ok = if (f.completion.result) |_| true else |err| blk: {
            self.failure = self.failure orelse err;
            break :blk false;
        };
        if (ok) {
            self.factory.done(self.factory.ctx, n.kind, n.index, f.completion) catch |err| {
                self.failure = self.failure orelse err;
                n.state = .failed;
                return;
            };
        } else {
            // A job that failed in its stage/enqueue was aborted by the worker.
            self.factory.done(self.factory.ctx, n.kind, n.index, f.completion) catch {};
        }
        n.state = if (ok) .done else .failed;
        self.remaining -= 1;
    }

    /// Jobs made for ready nodes that will never be dispatched (request failed).
    fn abandonReady(self: *Scheduler) void {
        for (self.graph.nodes.items) |*n| if (n.state == .ready) {
            if (n.job) |j| j.vtable.abort(j.ctx);
            n.state = .failed;
        };
    }

    /// Run the whole request. Returns the first failure after every
    /// dispatched job has completed (no job memory is abandoned in flight).
    pub fn run(self: *Scheduler) !void {
        while (true) {
            self.mutex.lock();
            const finished = try self.a.dupe(Finished, self.completions.items);
            self.completions.clearRetainingCapacity();
            const released = try self.a.dupe(u32, self.releases.items);
            self.releases.clearRetainingCapacity();
            const failed_async = self.async_failure;
            self.mutex.unlock();
            defer self.a.free(finished);
            defer self.a.free(released);
            for (released) |id| {
                if (id >= self.graph.nodes.items.len) return error.InvalidRelease;
                self.graph.nodes.items[id].released = true;
            }
            for (finished) |f| self.finishNode(f);
            if (failed_async) |err| self.failure = self.failure orelse err;
            if (self.failure) |err| {
                if (self.running == 0) {
                    self.abandonReady();
                    return err;
                }
            } else {
                if (self.remaining == 0) return;
                try self.promote();
                if (self.failure != null) continue;
                // Host barrier: runs here while workers keep proving queued work.
                for (self.graph.nodes.items) |*n| if (n.state == .ready and n.kind == .seal) {
                    const step = self.factory.host orelse return error.MissingHostStep;
                    n.state = .running;
                    step(self.factory.ctx, n.kind, n.index) catch |err| {
                        n.state = .failed;
                        self.failure = err;
                        break;
                    };
                    n.state = .done;
                    self.remaining -= 1;
                };
                if (self.failure == null) {
                    try self.promote();
                    while (self.failure == null and try self.placeOne()) {}
                }
                if (self.remaining == 0) return;
            }
            self.mutex.lock();
            if (self.completions.items.len == 0 and self.releases.items.len == 0)
                self.cond.timedWait(&self.mutex, 200 * std.time.ns_per_us) catch {};
            self.mutex.unlock();
        }
    }
};

// Tests: scheduler_test.zig (separate test binary, see rv64_jobs_sched_test_root.zig).
