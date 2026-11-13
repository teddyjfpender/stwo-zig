//! Persistent service (runtime-persist): park/unpark of the static arena,
//! grow-only lazy pinned slots, the planned footprint seen from enqueue, and
//! class stats visible to a completion waiter. Host device model only.
const std = @import("std");
const W = @import("worker.zig");
const P = @import("plan.zig");
const api = @import("api.zig");
const fake = @import("fake.zig");
const g = W.Arena.granule;

fn key(n: u8) [32]u8 {
    return @splat(n);
}

const Job = struct {
    k: u8,
    staged: usize = g,
    work: usize = g,
    declared_device: usize = 4 * g,
    pinned: usize = 64,
    persistent: ?usize = null,
    fresh: ?bool = null,
    result: u32 = 0,
    seen: api.Footprint = .{ .device_words = 0 },
    seen_planned: bool = false,
    input: [4]u32 = .{ 1, 2, 3, 4 },
    buf: ?api.DeviceBuffer = null,
    pub fn classKey(self: *Job) [32]u8 {
        return key(self.k);
    }
    pub fn footprint(self: *Job) api.Footprint {
        return .{ .device_words = self.declared_device, .staged_words = self.staged, .slab_words = 4, .pinned_words = self.pinned };
    }
    pub fn stage(self: *Job, s: *api.Stager) !void {
        const b = try s.alloc(self.staged);
        try s.upload(b, &self.input);
        self.buf = b;
        if (self.persistent) |words| {
            const got = try s.persistent(key(100 + self.k), words);
            self.fresh = got.fresh;
            if (got.fresh) try s.upload(got.buffer, &self.input);
        }
    }
    pub fn enqueue(self: *Job, e: *api.Enqueue) !void {
        self.seen = e.footprint();
        self.seen_planned = e.planned();
        const scratch = try e.alloc(self.work);
        var sum: u32 = 0;
        for (self.buf.?.ptr[0..4]) |x| sum += x;
        scratch.ptr[0] = sum + self.k;
        e.slab.device.ptr[0] = scratch.ptr[0];
        e.free(scratch);
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
    last: ?anyerror = null,
    /// Classes visible to the waiter at the moment its completion fired.
    classes_at_done: usize = 0,
    worker: ?*W.Worker = null,
    fn sink(self: *Done) W.Sink {
        return .{ .ctx = self, .done = on };
    }
    fn on(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        if (self.worker) |w| {
            const stats = w.classStats(std.testing.allocator) catch unreachable;
            defer std.testing.allocator.free(stats);
            self.classes_at_done = stats.len;
        }
        self.mutex.lock();
        defer self.mutex.unlock();
        if (c.result) |_| {} else |err| {
            self.errors += 1;
            self.last = err;
        }
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

test "class stats are recorded before the completion fires (no race with a waiter)" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 64 * g, .pinned_slot_words = 1 << 12 });
    defer w.destroy();
    var d = Done{ .worker = w };
    var job = Job{ .k = 7 };
    try put(w, api.Job.from(Job, &job), d.sink());
    d.wait(1);
    try std.testing.expectEqual(@as(usize, 1), d.classes_at_done);
    try std.testing.expectEqual(@as(usize, 0), d.errors);
}

test "park releases only the arena; unpark re-acquires it; jobs before and after are right" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 64 * g, .pinned_slot_words = 1 << 12, .persistent_budget_words = 4 * g });
    defer w.destroy();
    var d = Done{};
    var jobs: [4]Job = .{ .{ .k = 1, .persistent = 2 * g }, .{ .k = 2 }, .{ .k = 1, .persistent = 2 * g }, .{ .k = 3 } };
    try put(w, api.Job.from(Job, &jobs[0]), d.sink());
    try put(w, api.Job.from(Job, &jobs[1]), d.sink());
    // park drains the pipeline first (it does not need the caller to wait).
    const allocs_before = fake.counters.allocations;
    const pinned_before = w.pinned_allocations;
    const epoch0 = w.arenaEpoch();
    const pr = try w.park(.{});
    try std.testing.expectEqual(@as(usize, 2), d.n);
    try std.testing.expectEqual(@as(usize, 64 * g), pr.arena_words);
    try std.testing.expect(w.isParked());
    try std.testing.expectEqual(@as(usize, 0), w.arenaWords());
    try std.testing.expectEqual(@as(usize, 1), fake.counters.frees); // the arena only
    try std.testing.expectError(error.WorkerParked, w.submit(api.Job.from(Job, &jobs[2]), d.sink()));
    try std.testing.expect(!w.accepts());
    try std.testing.expectError(error.WorkerAlreadyParked, w.park(.{}));
    // unpark at the old size (0 = same as before)
    const ur = try w.unpark(0);
    try std.testing.expectEqual(@as(usize, 64 * g), ur.arena_words);
    try std.testing.expectEqual(allocs_before + 1, fake.counters.allocations); // the arena only (pool kept)
    try std.testing.expectEqual(pinned_before, w.pinned_allocations); // pinned slots kept
    if (!ur.same_base) try std.testing.expect(w.arenaEpoch() > epoch0) else try std.testing.expectEqual(epoch0, w.arenaEpoch());
    try std.testing.expectError(error.WorkerNotParked, w.unpark(0));
    try put(w, api.Job.from(Job, &jobs[2]), d.sink());
    try put(w, api.Job.from(Job, &jobs[3]), d.sink());
    d.wait(4);
    try std.testing.expectEqual(@as(usize, 0), d.errors);
    for (jobs) |j| try std.testing.expectEqual(@as(u32, 10 + j.k), j.result);
    // The persistent region survived the park: the class is warm.
    try std.testing.expect(jobs[0].fresh.? and !jobs[2].fresh.?);
    try std.testing.expectEqual(@as(u64, 1), w.parks);
    try std.testing.expectEqual(@as(u64, 1), w.unparks);
}

test "park with release_persistent drops warm regions (fresh again) and advances the persistent epoch" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 64 * g, .pinned_slot_words = 1 << 12, .persistent_budget_words = 4 * g });
    defer w.destroy();
    var d = Done{};
    var a = Job{ .k = 1, .persistent = 2 * g };
    var b = Job{ .k = 1, .persistent = 2 * g };
    try put(w, api.Job.from(Job, &a), d.sink());
    d.wait(1);
    const r = try w.park(.{ .release_persistent = true });
    try std.testing.expectEqual(@as(usize, 4 * g), r.persistent_words);
    try std.testing.expectEqual(@as(u64, 1), w.persistentEpoch());
    _ = try w.unpark(32 * g); // a different size: the epoch must advance
    try std.testing.expectEqual(@as(usize, 32 * g), w.arenaWords());
    try put(w, api.Job.from(Job, &b), d.sink());
    d.wait(2);
    try std.testing.expectEqual(@as(usize, 0), d.errors);
    try std.testing.expect(a.fresh.? and b.fresh.?);
    try std.testing.expectEqual(@as(u32, 11), b.result);
}

test "unpark to a size that cannot be allocated fails, stays parked, and a later unpark works" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 64 * g, .pinned_slot_words = 1 << 12 });
    defer w.destroy();
    _ = try w.park(.{});
    try std.testing.expectError(error.InvalidArena, w.unpark(g + 1));
    try std.testing.expect(w.isParked());
    fake.counters.fail_alloc_after = fake.counters.allocations;
    defer fake.counters.fail_alloc_after = null;
    try std.testing.expectError(error.CudaEnqueueFailed, w.unpark(0));
    try std.testing.expect(w.isParked());
    fake.counters.fail_alloc_after = null;
    _ = try w.unpark(0);
    var d = Done{};
    var job = Job{ .k = 4 };
    try put(w, api.Job.from(Job, &job), d.sink());
    d.wait(1);
    try std.testing.expectEqual(@as(usize, 0), d.errors);
    try std.testing.expectEqual(@as(u32, 14), job.result);
}

test "a parked worker shuts down cleanly (destroy without unpark)" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 64 * g, .pinned_slot_words = 1 << 12 });
    _ = try w.park(.{});
    w.destroy();
    // The arena (freed at park) and the 3 pinned slots (host frees are
    // counted, host allocations are not): everything returned.
    try std.testing.expectEqual(fake.counters.allocations + 3, fake.counters.frees);
}

test "lazy pinned slots: nothing at start, grow once to what jobs need, capped, never shrink" {
    fake.reset();
    const cap: usize = 3 * W.pinned_granule_words;
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 64 * g, .pinned_slot_words = cap, .pinned_lazy = true });
    defer w.destroy();
    try std.testing.expectEqual(@as(usize, 0), w.pinnedBytes());
    try std.testing.expectEqual(@as(u64, 0), w.pinned_allocations);
    var d = Done{};
    var small: [3]Job = .{ .{ .k = 1 }, .{ .k = 2 }, .{ .k = 3 } };
    for (&small) |*j| try put(w, api.Job.from(Job, j), d.sink());
    d.wait(3);
    // One granule per slot, allocated once.
    try std.testing.expectEqual(@as(u64, 3), w.pinned_allocations);
    try std.testing.expectEqual(3 * W.pinned_granule_words * 4, w.pinnedBytes());
    var again: [3]Job = .{ .{ .k = 1 }, .{ .k = 2 }, .{ .k = 3 } };
    for (&again) |*j| try put(w, api.Job.from(Job, j), d.sink());
    d.wait(6);
    try std.testing.expectEqual(@as(u64, 3), w.pinned_allocations); // warm: no new pinned memory
    // A job needing more grows its slot (to 2 granules), within the cap.
    var big = Job{ .k = 5, .pinned = W.pinned_granule_words + 1 };
    try put(w, api.Job.from(Job, &big), d.sink());
    d.wait(7);
    try std.testing.expectEqual(@as(u64, 4), w.pinned_allocations);
    // Over the cap: refused like today's fixed slot.
    var huge = Job{ .k = 6, .pinned = cap + 1 };
    try put(w, api.Job.from(Job, &huge), d.sink());
    d.wait(8);
    try std.testing.expectEqual(@as(usize, 1), d.errors);
    try std.testing.expectEqual(error.JobFootprintExceedsPinned, d.last.?);
    try std.testing.expectEqual(@as(u32, 15), big.result);
}

test "enqueue sees the planned footprint: measured peak with a policy, the declaration without" {
    fake.reset();
    var buf: [1024]u8 = undefined;
    // class 1: declared 40g device, measured peak 8g (staged g + state g + slab g + work).
    const text = try std.fmt.bufPrint(&buf, "{{\"schema\":\"{s}\",\"gpu\":{{\"arena_words\":{d}}},\"classes\":[{{\"class_key\":\"{s}\",\"peak_words\":{d},\"staged_words\":{d}}}]}}", .{ P.schema, 64 * g, std.fmt.bytesToHex(key(1), .lower), 8 * g, g });
    const policy = try P.Policy.parse(std.testing.allocator, text);
    defer policy.deinit();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 64 * g, .pinned_slot_words = 1 << 12, .plan = policy });
    defer w.destroy();
    var d = Done{};
    var planned = Job{ .k = 1, .declared_device = 40 * g };
    var unplanned = Job{ .k = 2, .declared_device = 6 * g };
    try put(w, api.Job.from(Job, &planned), d.sink());
    try put(w, api.Job.from(Job, &unplanned), d.sink());
    d.wait(2);
    try std.testing.expectEqual(@as(usize, 0), d.errors);
    try std.testing.expect(planned.seen_planned and !unplanned.seen_planned);
    try std.testing.expectEqual(@as(usize, 8 * g - 2 * g), planned.seen.device_words); // peak - state granule - slab granule
    try std.testing.expectEqual(@as(usize, 6 * g), unplanned.seen.device_words);
}

test "park waits for in-flight jobs submitted from another thread" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 64 * g, .pinned_slot_words = 1 << 12 });
    defer w.destroy();
    var d = Done{};
    var jobs: [8]Job = undefined;
    for (&jobs, 0..) |*j, i| j.* = .{ .k = @intCast(i + 1) };
    const Feeder = struct {
        fn run(wk: *W.Worker, js: []Job, dn: *Done) void {
            for (js) |*j| put(wk, api.Job.from(Job, j), dn.sink()) catch return;
        }
    };
    const t = try std.Thread.spawn(.{}, Feeder.run, .{ w, jobs[0..], &d });
    t.join();
    _ = try w.park(.{});
    try std.testing.expectEqual(@as(usize, 8), d.n);
    _ = try w.unpark(0);
    try std.testing.expectEqual(@as(usize, 0), d.errors);
}

test "a park whose persistent release fails still parks (arena-less); unpark recovers; nothing is freed twice" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 64 * g, .pinned_slot_words = 1 << 12 });
    var d = Done{};
    var a = Job{ .k = 1, .persistent = g };
    var b = Job{ .k = 2, .persistent = g };
    try put(w, api.Job.from(Job, &a), d.sink());
    try put(w, api.Job.from(Job, &b), d.sink());
    d.wait(2);
    // Free #1 is the arena, #2 the first persistent buffer: fail #3 (the second one).
    fake.counters.fail_free_after = fake.counters.frees + 2;
    try std.testing.expectError(error.CudaEnqueueFailed, w.park(.{ .release_persistent = true }));
    try std.testing.expect(w.isParked());
    try std.testing.expectEqual(@as(usize, 0), w.arenaWords());
    var refused = Job{ .k = 3 };
    try std.testing.expectError(error.WorkerParked, w.submit(api.Job.from(Job, &refused), d.sink()));
    _ = try w.unpark(0);
    var c = Job{ .k = 1, .persistent = g };
    try put(w, api.Job.from(Job, &c), d.sink());
    d.wait(3);
    try std.testing.expectEqual(@as(usize, 0), d.errors);
    try std.testing.expect(c.fresh.?); // the released regions are gone
    w.destroy();
    try std.testing.expectEqual(@as(usize, 0), fake.counters.bad_frees);
}

test "concurrent unparks: exactly one acquires the arena, the others are refused, no arena leaks" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 64 * g, .pinned_slot_words = 1 << 12 });
    _ = try w.park(.{});
    const before = fake.counters.allocations;
    const Racer = struct {
        fn run(worker: *W.Worker, ok: *std.atomic.Value(usize), refused: *std.atomic.Value(usize)) void {
            if (worker.unpark(0)) |_| {
                _ = ok.fetchAdd(1, .seq_cst);
            } else |err| switch (err) {
                error.WorkerBusy, error.WorkerNotParked => _ = refused.fetchAdd(1, .seq_cst),
                else => unreachable,
            }
        }
    };
    var ok = std.atomic.Value(usize).init(0);
    var refused = std.atomic.Value(usize).init(0);
    var threads: [6]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Racer.run, .{ w, &ok, &refused });
    for (threads) |t| t.join();
    try std.testing.expectEqual(@as(usize, 1), ok.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 5), refused.load(.seq_cst));
    try std.testing.expectEqual(before + 1, fake.counters.allocations); // one arena
    try std.testing.expect(!w.isParked());
    w.destroy();
    try std.testing.expectEqual(fake.counters.allocations + 3, fake.counters.frees);
}

test "lazy pinned growth frees nothing in the pipeline: replaced slots are retired until the next park" {
    fake.reset();
    const cap: usize = 8 * W.pinned_granule_words;
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 64 * g, .pinned_slot_words = cap, .pinned_lazy = true });
    var d = Done{};
    var small: [3]Job = .{ .{ .k = 1 }, .{ .k = 2 }, .{ .k = 3 } };
    for (&small) |*j| try put(w, api.Job.from(Job, j), d.sink());
    d.wait(3);
    const frees = fake.counters.frees;
    // Rising classes regrow slots; nothing is host-freed while jobs run.
    var rising: [3]Job = .{ .{ .k = 4, .pinned = W.pinned_granule_words + 1 }, .{ .k = 5, .pinned = 3 * W.pinned_granule_words }, .{ .k = 6, .pinned = 5 * W.pinned_granule_words } };
    for (&rising) |*j| try put(w, api.Job.from(Job, j), d.sink());
    d.wait(6);
    try std.testing.expectEqual(@as(usize, 0), d.errors);
    try std.testing.expectEqual(frees, fake.counters.frees);
    try std.testing.expectEqual(@as(u64, 6), w.pinned_allocations);
    // Power-of-two growth: 2, 4 and 8 granules.
    try std.testing.expectEqual((2 + 4 + 8) * W.pinned_granule_words * 4, w.pinnedBytes());
    _ = try w.park(.{}); // pipeline idle: the arena and the 3 retired slots are freed
    try std.testing.expectEqual(frees + 1 + 3, fake.counters.frees);
    w.destroy();
    try std.testing.expectEqual(@as(usize, 0), fake.counters.bad_frees);
}

test "pinned growth sizes are powers of two of at least one granule" {
    try std.testing.expectEqual(W.pinned_granule_words, W.Worker.pinnedGrowth(1));
    try std.testing.expectEqual(W.pinned_granule_words, W.Worker.pinnedGrowth(W.pinned_granule_words));
    try std.testing.expectEqual(2 * W.pinned_granule_words, W.Worker.pinnedGrowth(W.pinned_granule_words + 1));
    try std.testing.expectEqual(8 * W.pinned_granule_words, W.Worker.pinnedGrowth(5 * W.pinned_granule_words));
}

test "posted callback outlives its phase delegate and retains stable worker userdata" {
    const a = std.testing.allocator;
    const w = try W.Worker.create(a, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer w.destroy();
    const Probe = struct {
        expected: *W.Worker,
        entered: std.Thread.ResetEvent = .{},
        release: std.Thread.ResetEvent = .{},
        observed: ?*W.Worker = null,
        value: u32 = 0,
        fn run(raw: *anyopaque, worker: *W.Worker) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.entered.set();
            self.release.wait();
            self.observed = worker;
            if (worker != self.expected) return error.WrongPostedWorker;
            self.value = 0x513a_55ed;
            return error.PostedApplicationRefusal;
        }
        fn healthy(raw: *anyopaque, worker: *W.Worker) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (worker != self.expected) return error.WrongPostedWorker;
            self.value += 1;
        }
    };
    var probe = Probe{ .expected = w };
    defer probe.release.set();
    var done = W.CallDone{};
    try w.post(.{ .ctx = &probe, .run = Probe.run }, &done);
    // post's borrowed phase is gone before this gate opens. Its stack frame
    // cannot be the stored callback context or the Worker argument.
    probe.entered.wait();
    _ = w.arenaEpoch();
    _ = w.pinnedBytes();
    probe.release.set();
    try std.testing.expectError(error.PostedApplicationRefusal, w.awaitCall(&done));
    try std.testing.expectEqual(w, probe.observed.?);
    try std.testing.expectEqual(@as(u32, 0x513a_55ed), probe.value);
    try w.call(.{ .ctx = &probe, .run = Probe.healthy });
    try std.testing.expectEqual(@as(u32, 0x513a_55ee), probe.value);
}
