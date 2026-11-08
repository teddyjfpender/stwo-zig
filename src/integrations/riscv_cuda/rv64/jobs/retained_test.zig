//! Request-scoped retained regions (retained.zig) on the host device model:
//! Stage1 -> seal -> Stage2 carriage, leak at shutdown, abort, double release,
//! park with live regions, budget, pins across a release, failed creator.
const std = @import("std");
const W = @import("worker.zig");
const R = @import("retained.zig");
const api = @import("api.zig");
const fake = @import("fake.zig");
const g = W.Arena.granule;

/// Producer: creates (request, name) in stage, fills it in enqueue.
/// Consumer: finds it (find-only) in stage, sums it in enqueue.
const Job = struct {
    request: u64,
    name: [32]u8 = R.name("s1.main", 0),
    words: usize = 2 * g,
    role: enum { producer, consumer, either } = .producer,
    /// Fail enqueue after touching the region (a failed creator).
    fail: bool = false,
    value: u32 = 7,
    fresh: ?bool = null,
    buffer: ?api.DeviceBuffer = null,
    result: u32 = 0,
    stage_error: ?anyerror = null,
    pub fn classKey(_: *Job) [32]u8 {
        return @splat(9);
    }
    pub fn footprint(_: *Job) api.Footprint {
        return .{ .device_words = 4 * g, .slab_words = 4, .pinned_words = 64 };
    }
    pub fn stage(self: *Job, s: *api.Stager) !void {
        switch (self.role) {
            .producer, .either => {
                const r = s.retain(self.request, self.name, self.words) catch |err| {
                    self.stage_error = err;
                    return err;
                };
                self.fresh = r.fresh;
                self.buffer = r.buffer;
                if (r.fresh) {
                    // Upload into the retained region is legal (job memory).
                    const init = [_]u32{ self.value, self.value, self.value, self.value };
                    try s.upload(r.buffer, &init);
                }
            },
            .consumer => self.buffer = s.retained(self.request, self.name, self.words) catch |err| {
                self.stage_error = err;
                return err;
            },
        }
    }
    pub fn enqueue(self: *Job, e: *api.Enqueue) !void {
        const b = self.buffer.?;
        if (self.role == .producer and self.fresh.?) b.ptr[4] = self.value * 2;
        var sum: u32 = 0;
        for (b.ptr[0..5]) |x| sum += x;
        e.slab.device.ptr[0] = sum;
        if (self.fail) return error.InjectedEnqueueFailure;
    }
    pub fn finish(self: *Job, v: api.SlabView) !void {
        self.result = v.words[0];
    }
    pub fn abort(_: *Job) void {}
};

const Done = struct {
    mutex: std.Thread.Mutex = .{},
    n: usize = 0,
    errors: usize = 0,
    fn sink(self: *Done) W.Sink {
        return .{ .ctx = self, .done = on };
    }
    fn on(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (c.result) |_| {} else |_| self.errors += 1;
        self.n += 1;
    }
    fn wait(self: *Done, n: usize) void {
        while (true) {
            self.mutex.lock();
            const d = self.n;
            self.mutex.unlock();
            if (d >= n) return;
            std.Thread.yield() catch {};
        }
    }
};

fn put(w: *W.Worker, job: api.Job, sink: W.Sink) !void {
    while (true) {
        w.submit(job, sink) catch |err| switch (err) {
            error.WorkerBusy => {
                std.Thread.yield() catch {};
                continue;
            },
            else => return err,
        };
        return;
    }
}

fn makeWorker(budget: usize) !*W.Worker {
    return W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 64 * g, .pinned_slot_words = 1 << 12, .retained_budget_words = budget });
}

/// Wait until the worker thread has freed every released region.
fn settle(w: *W.Worker, request: u64) void {
    while (w.retainedWords(request) != 0) std.Thread.yield() catch {};
}

test "a region created by stage 1 survives to stage 2 of the same request (same buffer, same contents)" {
    fake.reset();
    const w = try makeWorker(0);
    defer w.destroy();
    var d = Done{};
    var s1 = Job{ .request = 1 };
    try put(w, api.Job.from(Job, &s1), d.sink());
    d.wait(1);
    // ... the host barrier would run here; other jobs come and go ...
    var other = Job{ .request = 2, .value = 3 };
    try put(w, api.Job.from(Job, &other), d.sink());
    var s2 = Job{ .request = 1, .role = .consumer };
    try put(w, api.Job.from(Job, &s2), d.sink());
    d.wait(3);
    try std.testing.expectEqual(@as(usize, 0), d.errors);
    try std.testing.expect(s1.fresh.?);
    try std.testing.expectEqual(s1.buffer.?.ptr, s2.buffer.?.ptr);
    try std.testing.expectEqual(@as(u32, 4 * 7 + 14), s1.result);
    try std.testing.expectEqual(s1.result, s2.result);
    try std.testing.expectEqual(@as(usize, 4 * g), w.retainedWords(null));
    try std.testing.expectEqual(@as(usize, 2 * g), w.retainedWords(1));
    // Explicit release of request 1 frees exactly its region.
    const frees = fake.counters.frees;
    try std.testing.expectEqual(@as(usize, 1), try w.releaseRequestAndWait(1));
    try std.testing.expectEqual(frees + 1, fake.counters.frees);
    try std.testing.expectEqual(@as(usize, 2 * g), w.retainedWords(null));
    // The released key is gone for stage 2 jobs (find-only refuses).
    var late = Job{ .request = 1, .role = .consumer };
    try put(w, api.Job.from(Job, &late), d.sink());
    d.wait(4);
    try std.testing.expectEqual(@as(usize, 1), d.errors);
    try std.testing.expectEqual(error.RetainedRegionNotFound, late.stage_error.?);
    const st = w.retainedStats();
    try std.testing.expectEqual(@as(u64, 2), st.created);
    try std.testing.expectEqual(@as(u64, 1), st.freed);
    try std.testing.expectEqual(@as(u64, 4 * g), st.peak_words);
}

test "leak: regions never released are freed (and counted) at shutdown; no device memory leaks" {
    fake.reset();
    {
        const w = try makeWorker(0);
        defer w.destroy();
        var d = Done{};
        var a = Job{ .request = 5 };
        var b = Job{ .request = 5, .name = R.name("s1.bind", 0) };
        try put(w, api.Job.from(Job, &a), d.sink());
        try put(w, api.Job.from(Job, &b), d.sink());
        d.wait(2);
        try std.testing.expectEqual(@as(usize, 0), d.errors);
        try std.testing.expectEqual(@as(usize, 4 * g), w.retainedWords(5));
    }
    // Every device allocation (arena + 2 regions) was freed; `frees` also
    // counts the 3 eager pinned host slots (fake hostFree -> freeU32).
    try std.testing.expectEqual(@as(usize, 3), fake.counters.allocations);
    try std.testing.expectEqual(fake.counters.allocations + 3, fake.counters.frees);
    try std.testing.expectEqual(@as(usize, 0), fake.counters.bad_frees);
}

test "abort: releaseRequest frees every region of the request, idempotently; a failed creator's region is released" {
    fake.reset();
    const w = try makeWorker(0);
    defer w.destroy();
    var d = Done{};
    var a = Job{ .request = 8, .name = R.name("s1.main", 0) };
    var b = Job{ .request = 8, .name = R.name("s1.main", 1) };
    var keep = Job{ .request = 9 };
    try put(w, api.Job.from(Job, &a), d.sink());
    try put(w, api.Job.from(Job, &b), d.sink());
    try put(w, api.Job.from(Job, &keep), d.sink());
    d.wait(3);
    try std.testing.expectEqual(@as(usize, 2), try w.releaseRequest(8));
    settle(w, 8);
    try std.testing.expectEqual(@as(usize, 0), try w.releaseRequest(8)); // idempotent
    try std.testing.expectEqual(@as(usize, 2 * g), w.retainedWords(null)); // request 9 untouched
    // A creator that fails: its fresh region is released (contents undefined)
    // and freed once the job is reported.
    var bad = Job{ .request = 10, .fail = true };
    try put(w, api.Job.from(Job, &bad), d.sink());
    d.wait(4);
    try std.testing.expectEqual(@as(usize, 1), d.errors);
    settle(w, 10);
    try std.testing.expectEqual(@as(usize, 0), try w.releaseRequest(10));
    try std.testing.expectEqual(@as(usize, 0), fake.counters.bad_frees);
}

test "double release is refused (not freed twice); release of an unknown region is refused" {
    fake.reset();
    const w = try makeWorker(0);
    defer w.destroy();
    var d = Done{};
    var a = Job{ .request = 3 };
    try put(w, api.Job.from(Job, &a), d.sink());
    d.wait(1);
    try w.releaseRetained(3, R.name("s1.main", 0));
    try std.testing.expectError(error.RetainedRegionNotLive, w.releaseRetained(3, R.name("s1.main", 0)));
    try std.testing.expectError(error.RetainedRegionNotLive, w.releaseRetained(4, R.name("s1.main", 0)));
    settle(w, 3);
    try std.testing.expectEqual(@as(usize, 0), fake.counters.bad_frees);
    try std.testing.expectEqual(@as(u64, 1), w.retainedStats().freed);
}

test "park keeps live regions (not in the arena); park(release_retained) frees them" {
    fake.reset();
    const w = try makeWorker(0);
    defer w.destroy();
    var d = Done{};
    var s1 = Job{ .request = 11 };
    try put(w, api.Job.from(Job, &s1), d.sink());
    d.wait(1);
    const frees = fake.counters.frees;
    const pr = try w.park(.{});
    try std.testing.expectEqual(frees + 1, fake.counters.frees); // the arena only
    try std.testing.expectEqual(@as(usize, 2 * g), pr.retained_words);
    // Release while parked: the worker thread still frees it.
    try std.testing.expectEqual(@as(usize, 1), try w.releaseRequestAndWait(11));
    _ = try w.unpark(0);
    var s1b = Job{ .request = 12 };
    try put(w, api.Job.from(Job, &s1b), d.sink());
    d.wait(2);
    var s2 = Job{ .request = 12, .role = .consumer };
    try put(w, api.Job.from(Job, &s2), d.sink());
    d.wait(3);
    try std.testing.expectEqual(@as(usize, 0), d.errors);
    try std.testing.expectEqual(s1b.result, s2.result);
    const pr2 = try w.park(.{ .release_retained = true });
    try std.testing.expectEqual(@as(usize, 0), pr2.retained_words);
    try std.testing.expectEqual(@as(usize, 0), w.retainedWords(null));
    _ = try w.unpark(0);
}

test "budget: creation beyond the retained budget is refused (accounted), existing regions still found" {
    fake.reset();
    const w = try makeWorker(3 * g);
    defer w.destroy();
    var d = Done{};
    var a = Job{ .request = 1, .name = R.name("x", 0) };
    var b = Job{ .request = 1, .name = R.name("x", 1) };
    var again = Job{ .request = 1, .name = R.name("x", 0), .role = .consumer };
    try put(w, api.Job.from(Job, &a), d.sink());
    d.wait(1);
    try put(w, api.Job.from(Job, &b), d.sink());
    d.wait(2);
    try std.testing.expectEqual(error.RetainedBudgetExhausted, b.stage_error.?);
    try put(w, api.Job.from(Job, &again), d.sink());
    d.wait(3);
    try std.testing.expectEqual(@as(usize, 1), d.errors);
    try std.testing.expectEqual(@as(u64, 1), w.retainedStats().budget_refusals);
    try std.testing.expectEqual(a.result, again.result);
}

test "a region released while a job still pins it is freed only after that job is reported" {
    fake.reset();
    const w = try makeWorker(0);
    defer w.destroy();
    // A consumer that blocks in finish until the release has been requested.
    const Gate = struct {
        inner: Job,
        go: std.atomic.Value(bool) = .init(false),
        in_finish: std.atomic.Value(bool) = .init(false),
        pub fn classKey(self: *@This()) [32]u8 {
            return self.inner.classKey();
        }
        pub fn footprint(self: *@This()) api.Footprint {
            return self.inner.footprint();
        }
        pub fn stage(self: *@This(), s: *api.Stager) !void {
            return self.inner.stage(s);
        }
        pub fn enqueue(self: *@This(), e: *api.Enqueue) !void {
            return self.inner.enqueue(e);
        }
        pub fn finish(self: *@This(), v: api.SlabView) !void {
            self.in_finish.store(true, .release);
            while (!self.go.load(.acquire)) std.Thread.yield() catch {};
            return self.inner.finish(v);
        }
        pub fn abort(_: *@This()) void {}
    };
    var d = Done{};
    var s1 = Job{ .request = 20 };
    try put(w, api.Job.from(Job, &s1), d.sink());
    d.wait(1);
    var s2 = Gate{ .inner = .{ .request = 20, .role = .consumer } };
    try put(w, api.Job.from(Gate, &s2), d.sink());
    while (!s2.in_finish.load(.acquire)) std.Thread.yield() catch {};
    const frees = fake.counters.frees;
    try w.releaseRetained(20, R.name("s1.main", 0));
    // Still pinned by s2 (finishing): not freed.
    std.Thread.sleep(2 * std.time.ns_per_ms);
    try std.testing.expectEqual(frees, fake.counters.frees);
    try std.testing.expectEqual(@as(usize, 2 * g), w.retainedWords(20));
    s2.go.store(true, .release);
    d.wait(2);
    settle(w, 20);
    try std.testing.expectEqual(frees + 1, fake.counters.frees);
    try std.testing.expectEqual(s1.result, s2.inner.result);
}

test "table bookkeeping: geometry mismatch, re-create after release while the old region is pinned" {
    const a = std.testing.allocator;
    var t = R.Table{};
    defer t.deinit(a);
    var m1: [64]u32 = undefined;
    var m2: [64]u32 = undefined;
    const k = R.Key{ .request = 1, .name = R.name("k", 0) };
    try t.insert(a, k, .{ .ptr = &m1, .words = 64 });
    try std.testing.expectError(error.RetainedRegionExists, t.insert(a, k, .{ .ptr = &m2, .words = 64 }));
    try std.testing.expectError(error.RetainedGeometryMismatch, t.pin(k, 32));
    // Released while pinned (the creator's pin): not freeable yet.
    try std.testing.expect((try t.release(k)) == null);
    // Same key re-created by a new job: a distinct region.
    try t.insert(a, k, .{ .ptr = &m2, .words = 64 });
    try std.testing.expectEqual(@as(usize, 128), t.liveWords(1));
    // The OLD region's last unpin frees the old buffer, never the new one.
    const f = t.unpin(.{ .ptr = &m1, .words = 64 }).?;
    try std.testing.expectEqual(@as([*]u32, &m1), f.ptr);
    t.drop(f);
    try std.testing.expectEqual(@as([*]u32, &m2), (try t.pin(k, 64)).ptr);
    try std.testing.expect(t.contains(@intFromPtr(&m2) + 4, 63));
    try std.testing.expect(!t.contains(@intFromPtr(&m2) + 4, 64));
}
