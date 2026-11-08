const std = @import("std");
const W = @import("worker.zig");
const api = @import("api.zig");
const fake = @import("fake.zig");
const Arena = W.Arena;

test "batch event growth failure keeps old events and frees the partial new pair" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1024, .pinned_slot_words = 64 });
    const Check = struct {
        fn run(_: *anyopaque, worker: *W.Worker) !void {
            try worker.reserveBatches(1, 0);
            const old = worker.batch_slots[0][0].staged_event;
            const live = fake.liveEvents();
            fake.counters.fail_event_create_after = fake.counters.event_creations + 1;
            defer fake.counters.fail_event_create_after = null;
            try std.testing.expectError(error.CudaEnqueueFailed, worker.reserveBatches(2, 0));
            try std.testing.expectEqual(old, worker.batch_slots[0][0].staged_event);
            try std.testing.expectEqual(live, fake.liveEvents());
            try std.testing.expectEqual(@as(usize, 0), fake.counters.bad_event_destroys);
        }
    };
    var token: u8 = 0;
    const result = w.call(.{ .ctx = &token, .run = Check.run });
    w.destroy();
    try result;
    try std.testing.expectEqual(@as(usize, 0), fake.counters.bad_event_destroys);
}

test "request timing borrows only its active parity without creating events" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1024, .pinned_slot_words = 64 });
    defer w.destroy();
    const Job = struct {
        parity: u1,
        begin: ?*anyopaque = null,
        pub fn classKey(_: *@This()) [32]u8 {
            return @splat(1);
        }
        pub fn footprint(_: *@This()) api.Footprint {
            return .{ .device_words = 64 };
        }
        pub fn stage(self: *@This(), s: *api.Stager) !void {
            try std.testing.expectError(error.JobTimingParityMismatch, s.timingPair(self.parity ^ 1, 0));
            self.begin = (try s.timingPair(self.parity, 0)).begin;
        }
        pub fn enqueue(_: *@This(), _: *api.Enqueue) !void {}
        pub fn finish(_: *@This(), _: api.SlabView) !void {}
        pub fn abort(_: *@This()) void {}
    };
    const Check = struct {
        fn run(_: *anyopaque, worker: *W.Worker) !void {
            try worker.reserveTimingPairs(1, fake.peer.event_create_timed);
            try worker.reserveBatches(1, 0);
            const created = fake.counters.event_creations;
            var first: ?*anyopaque = null;
            for (0..2) |parity| {
                var job = Job{ .parity = @intCast(parity) };
                var jobs = [_]W.BatchJob{.{ .job = api.Job.from(Job, &job) }};
                var batch = W.Batch{ .jobs = &jobs, .parity = @intCast(parity) };
                worker.runBatch(&batch);
                worker.finishBatch(&batch, true);
                try batch.result;
                try jobs[0].result;
                try std.testing.expect(job.begin != null);
                if (parity == 0) first = job.begin else try std.testing.expect(first != job.begin);
            }
            try std.testing.expectEqual(created, fake.counters.event_creations);
        }
    };
    var token: u8 = 0;
    try w.call(.{ .ctx = &token, .run = Check.run });
}

// ---------------- worker loop on the host model ----------------

const Log = struct {
    mutex: std.Thread.Mutex = .{},
    events: [64][]const u8 = undefined,
    jobs: [64]usize = undefined,
    count: usize = 0,
    fn add(self: *Log, what: []const u8, job: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.events[self.count] = what;
        self.jobs[self.count] = job;
        self.count += 1;
    }
    fn index(self: *Log, what: []const u8, job: usize) usize {
        for (0..self.count) |i| if (self.jobs[i] == job and std.mem.eql(u8, self.events[i], what)) return i;
        return std.math.maxInt(usize);
    }
};

const Gate = struct {
    sem: std.Thread.Semaphore = .{},
};

const Probe = struct {
    id: usize,
    log: *Log,
    footprint_words: usize = 4096,
    readback: api.Readback = .job_slab,
    gate: ?*Gate = null,
    placement: ?api.Placement = null,
    input: [5]u32 = .{ 1, 2, 3, 4, 5 },
    staged: ?api.DeviceBuffer = null,
    result: u32 = 0,
    host_ran: bool = false,
    aborted: bool = false,
    slab_at: usize = 0,
    state_at: usize = 0,
    pub fn classKey(self: *Probe) [32]u8 {
        var k: [32]u8 = @splat(0);
        k[0] = @intCast(self.id % 2);
        return k;
    }
    pub fn footprint(self: *Probe) api.Footprint {
        return .{ .device_words = self.footprint_words, .staged_words = 64, .slab_words = 4, .pinned_words = 64, .readback = self.readback };
    }
    pub fn stage(self: *Probe, s: *api.Stager) !void {
        self.log.add("stage", self.id);
        self.placement = s.placement;
        const b = try s.alloc(5);
        try s.upload(b, &self.input); // not pinned: copied into pinned first
        self.staged = b;
        if (self.gate) |g| g.sem.wait();
    }
    fn hostStep(user: ?*anyopaque) callconv(.c) void {
        const self: *Probe = @ptrCast(@alignCast(user.?));
        self.host_ran = true;
    }
    pub fn enqueue(self: *Probe, e: *api.Enqueue) !void {
        self.log.add("enqueue", self.id);
        try e.waitStaged();
        const scratch = try e.alloc(16);
        // "kernel": sum the staged inputs into the slab (the fake executes in order)
        var sum: u32 = 0;
        for (self.staged.?.ptr[0..5]) |w| sum += w;
        scratch.ptr[0] = sum + @as(u32, @intCast(self.id));
        e.free(scratch);
        e.slab.device.ptr[0] = scratch.ptr[0];
        self.slab_at = @intFromPtr(e.slab.device.ptr);
        self.state_at = @intFromPtr(e.channel.state);
        try e.hostFn(.{ .call = hostStep, .user = self });
    }
    pub fn finish(self: *Probe, v: api.SlabView) !void {
        self.log.add("finish", self.id);
        try std.testing.expectEqual(self.readback, v.readback);
        if (self.readback == .request_slab) {
            try std.testing.expectEqual(@as(usize, 0), v.words.len);
            try std.testing.expectEqual(@as(u64, 0), v.receipt.d2h_bytes);
        } else self.result = v.words[0];
        try std.testing.expectEqual(@as(u32, 1), v.receipt.host_waits);
    }
    pub fn abort(self: *Probe) void {
        self.aborted = true;
        self.log.add("abort", self.id);
    }
};

const Collector = struct {
    mutex: std.Thread.Mutex = .{},
    done: usize = 0,
    errors: usize = 0,
    last_error: ?anyerror = null,
    receipts: [16]api.Receipt = undefined,
    fn sink(self: *Collector) W.Sink {
        return .{ .ctx = self, .done = onDone };
    }
    fn onDone(raw: *anyopaque, c: api.Completion) void {
        const self: *Collector = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (c.result) |_| {} else |err| {
            self.errors += 1;
            self.last_error = err;
        }
        self.receipts[self.done] = c.receipt;
        self.done += 1;
    }
    fn wait(self: *Collector, n: usize) void {
        while (true) {
            self.mutex.lock();
            const d = self.done;
            self.mutex.unlock();
            if (d >= n) return;
            std.Thread.yield() catch {};
        }
    }
};

fn submit(w: *W.Worker, job: api.Job, sink: W.Sink) void {
    while (true) {
        w.submit(job, sink) catch |err| switch (err) {
            error.WorkerBusy => {
                std.Thread.yield() catch {};
                continue;
            },
            else => unreachable,
        };
        return;
    }
}

test "device-published jobs retain private device scratch without host mirrors or readbacks" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1024, .pinned_slot_words = 64 });
    defer w.destroy();
    var log = Log{};
    var c = Collector{};
    var jobs: [3]Probe = undefined;
    for (&jobs, 0..) |*p, i| {
        p.* = .{ .id = i, .log = &log, .footprint_words = 512, .readback = .request_slab };
        submit(w, api.Job.from(Probe, p), c.sink());
    }
    c.wait(jobs.len);
    try std.testing.expectEqual(@as(usize, 0), c.errors);
    try std.testing.expectEqual(@as(usize, 0), fake.counters.d2h);
    for (jobs, c.receipts[0..jobs.len]) |p, r| {
        try std.testing.expect(p.slab_at != 0 and p.slab_at != p.state_at);
        try std.testing.expectEqual(api.Readback.request_slab, r.readback);
        try std.testing.expectEqual(@as(u64, 0), r.d2h_bytes);
    }
}

test "worker rejects invalid footprint before accepting or staging a job" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1024, .pinned_slot_words = 64 });
    defer w.destroy();
    var log = Log{};
    var c = Collector{};
    var p = Probe{ .id = 0, .log = &log, .footprint_words = 1 };
    try std.testing.expectError(error.StagedFootprintExceedsDevice, w.submit(api.Job.from(Probe, &p), c.sink()));
    try std.testing.expectEqual(@as(usize, 0), w.load());
    try std.testing.expectEqual(@as(usize, 0), log.count);
}

test "worker runs the 3-stage pipeline: stage(k+1) before enqueue(k) before finish(k-1)" {
    fake.reset();
    // Depth 4 lets the test hold job k+2 in the mailbox while job k+1 stages.
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 16, .pinned_slot_words = 1 << 12, .max_outstanding = 4 });
    var log: Log = .{};
    var gates: [4]Gate = @splat(.{});
    var probes: [4]Probe = undefined;
    for (&probes, 0..) |*p, i| p.* = .{ .id = i, .log = &log, .gate = &gates[i] };
    var c: Collector = .{};
    for (&probes, 0..) |*p, i| {
        // Returns once job i-1 left the mailbox (it is blocked in its stage),
        // so job i is always waiting when job i-1's stage returns.
        submit(w, api.Job.from(Probe, p), c.sink());
        if (i > 0) gates[i - 1].sem.post();
    }
    gates[3].sem.post();
    c.wait(4);
    w.destroy();
    try std.testing.expectEqual(@as(usize, 0), c.errors);
    for (0..3) |k| {
        try std.testing.expect(log.index("stage", k + 1) < log.index("enqueue", k));
        if (k > 0) try std.testing.expect(log.index("enqueue", k) < log.index("finish", k - 1));
        try std.testing.expect(log.index("finish", k) < log.index("finish", k + 1));
    }
    for (probes, 0..) |p, i| {
        try std.testing.expectEqual(@as(u32, 15 + @as(u32, @intCast(i))), p.result);
        try std.testing.expect(p.host_ran);
        try std.testing.expectEqual(@as(api.Placement, if (i % 2 == 0) .bottom else .top), p.placement.?);
    }
    // Same class + same placement → identical addresses (graph replay needs no rebinding).
    for (0..2) |i| {
        try std.testing.expectEqual(probes[i].slab_at, probes[i + 2].slab_at);
        try std.testing.expectEqual(probes[i].state_at, probes[i + 2].state_at);
        try std.testing.expectEqual(@intFromPtr(probes[i].staged.?.ptr), @intFromPtr(probes[i + 2].staged.?.ptr));
    }
    try std.testing.expect(probes[0].slab_at != probes[1].slab_at);
    try std.testing.expectEqual(@as(usize, 4), fake.counters.host_waits); // exactly one per job
    try std.testing.expectEqual(@as(usize, 4), fake.counters.d2h); // exactly one slab D2H per job
    try std.testing.expectEqual(@as(usize, 4), fake.counters.h2d);
    for (c.receipts[0..4]) |r| {
        try std.testing.expectEqual(@as(u32, 1), r.host_waits);
        try std.testing.expectEqual(@as(u64, 16), r.d2h_bytes);
        try std.testing.expectEqual(@as(u32, 1), r.d2h_copies);
        try std.testing.expectEqual(@as(u32, 1), r.host_callbacks);
        try std.testing.expectEqual(@as(u32, 0), r.capture_release_callbacks);
    }
}

test "worker refuses (does not wait on) a job whose footprint exceeds the arena" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 1, .arena_words = 1 << 14, .pinned_slot_words = 1 << 12 });
    var log: Log = .{};
    var big = Probe{ .id = 7, .log = &log, .footprint_words = 1 << 15 };
    var small = Probe{ .id = 8, .log = &log };
    var c: Collector = .{};
    submit(w, api.Job.from(Probe, &big), c.sink());
    submit(w, api.Job.from(Probe, &small), c.sink());
    c.wait(2);
    w.destroy();
    try std.testing.expectEqual(@as(usize, 1), c.errors);
    try std.testing.expectEqual(error.JobFootprintExceedsArena, c.last_error.?);
    try std.testing.expect(big.aborted);
    try std.testing.expectEqual(std.math.maxInt(usize), log.index("stage", 7));
    try std.testing.expectEqual(@as(u32, 15 + 8), small.result);
}

test "a device fault is terminal for the worker and fails later submissions" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 14, .pinned_slot_words = 1 << 12 });
    fake.counters.fail_event_sync = true;
    var log: Log = .{};
    var p = Probe{ .id = 1, .log = &log };
    var c: Collector = .{};
    submit(w, api.Job.from(Probe, &p), c.sink());
    c.wait(1);
    try std.testing.expectEqual(error.CudaDeviceFault, c.last_error.?);
    try std.testing.expect(p.aborted);
    try std.testing.expectError(error.CudaDeviceFault, w.submit(api.Job.from(Probe, &p), c.sink()));
    fake.counters.fail_event_sync = false;
    w.destroy();
}

test "worker startup failure is reported to the creator" {
    fake.reset();
    try std.testing.expectError(error.InvalidArena, W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 65, .pinned_slot_words = 64 }));
}

const Filler = struct {
    fail: bool,
    fresh: ?bool = null,
    pub fn classKey(_: *Filler) [32]u8 {
        return @splat(1);
    }
    pub fn footprint(_: *Filler) api.Footprint {
        return .{ .device_words = 64 };
    }
    pub fn stage(self: *Filler, s: *api.Stager) !void {
        const p = try s.persistent(@splat(0xfe), 64);
        self.fresh = p.fresh;
        if (self.fail) return error.InjectedFillFailure;
    }
    pub fn enqueue(_: *Filler, _: *api.Enqueue) !void {}
    pub fn finish(_: *Filler, _: api.SlabView) !void {}
    pub fn abort(_: *Filler) void {}
};

test "a failed fill never leaves a persistent entry that later jobs see as warm" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 12, .pinned_slot_words = 64 });
    var c: Collector = .{};
    var first = Filler{ .fail = true };
    var second = Filler{ .fail = false };
    var third = Filler{ .fail = false };
    submit(w, api.Job.from(Filler, &first), c.sink());
    c.wait(1);
    submit(w, api.Job.from(Filler, &second), c.sink());
    c.wait(2);
    submit(w, api.Job.from(Filler, &third), c.sink());
    c.wait(3);
    w.destroy();
    try std.testing.expectEqual(@as(usize, 1), c.errors);
    try std.testing.expect(first.fresh.? and second.fresh.? and !third.fresh.?);
    // arena + two persistent buffers (the retired one included); frees also count the 3 pinned slots
    try std.testing.expectEqual(@as(usize, 3), fake.counters.allocations);
    try std.testing.expectEqual(fake.counters.allocations + 3, fake.counters.frees);
}

test "persistent census counts a shared key once and survives install arena replacement" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 12, .pinned_slot_words = 64 });
    defer w.destroy();
    var c = Collector{};
    var first = Filler{ .fail = false };
    var second = Filler{ .fail = false };
    submit(w, api.Job.from(Filler, &first), c.sink());
    c.wait(1);
    _ = try w.park(.{});
    _ = try w.unpark(1 << 14);
    submit(w, api.Job.from(Filler, &second), c.sink());
    c.wait(2);
    const Census = struct {
        words: u64 = 0,
        fn run(raw: *anyopaque, worker: *W.Worker) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.words = worker.persistentWords();
        }
    };
    var census = Census{};
    try w.call(.{ .ctx = &census, .run = Census.run });
    try std.testing.expect(first.fresh.? and !second.fresh.?);
    try std.testing.expectEqual(@as(u64, 64), census.words);
    try std.testing.expectEqual(@as(usize, 0), c.errors);
}

test "warm-only batches reject a cold persistent key before allocating and reuse an installed key" {
    const Run = struct {
        batch: *W.Batch,
        fn reserve(_: *anyopaque, worker: *W.Worker) anyerror!void {
            try worker.reserveBatches(1, 64);
        }
        fn call(raw: *anyopaque, worker: *W.Worker) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            worker.runBatch(self.batch);
            // Fake copies execute eagerly; no device work remains to wait.
            worker.finishBatch(self.batch, true);
        }
    };
    for ([_]usize{ 0, 256 }) |pool_words| {
        fake.reset();
        const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 12, .pinned_slot_words = 64, .persistent_budget_words = pool_words });
        defer w.destroy();
        var reserve_context: u8 = 0;
        try w.call(.{ .ctx = &reserve_context, .run = Run.reserve });
        for (0..3) |step| {
            var filler = Filler{ .fail = false };
            var jobs = [_]W.BatchJob{.{ .job = api.Job.from(Filler, &filler) }};
            var batch = W.Batch{ .jobs = &jobs, .require_warm_persistent = step != 1 };
            var run = Run{ .batch = &batch };
            const before = fake.counters.allocations;
            try w.call(.{ .ctx = &run, .run = Run.call });
            try batch.result;
            if (step == 0) {
                try std.testing.expectError(error.PersistentClassNotWarmed, jobs[0].result);
                try std.testing.expect(filler.fresh == null);
                try std.testing.expectEqual(before, fake.counters.allocations);
            } else {
                try jobs[0].result;
                try std.testing.expectEqual(step == 1, filler.fresh.?);
                if (step == 2) try std.testing.expectEqual(before, fake.counters.allocations);
            }
        }
    }
}

test "batch pipeline defers neighbour staging only when the class pair cannot fit" {
    const MemoryJob = struct {
        id: usize,
        log: *Log,
        staged_words: usize,
        work_words: usize,
        input: api.DeviceBuffer = undefined,
        pub fn classKey(_: *@This()) [32]u8 {
            return @splat(0x67);
        }
        pub fn footprint(self: *@This()) api.Footprint {
            return .{ .device_words = self.staged_words + self.work_words, .staged_words = self.staged_words };
        }
        pub fn stage(self: *@This(), s: *api.Stager) !void {
            self.log.add("stage", self.id);
            self.input = try s.alloc(self.staged_words);
            @memset(self.input.ptr[0..self.input.words], @intCast(self.id + 1));
        }
        pub fn enqueue(self: *@This(), e: *api.Enqueue) !void {
            self.log.add("enqueue", self.id);
            for (self.input.ptr[0..self.input.words]) |word| try std.testing.expectEqual(@as(u32, @intCast(self.id + 1)), word);
            const work = try e.alloc(self.work_words);
            @memset(work.ptr[0..work.words], 0x67);
            e.free(work);
        }
        pub fn finish(_: *@This(), _: api.SlabView) !void {}
        pub fn abort(_: *@This()) void {}
    };
    const Run = struct {
        batch: *W.Batch,
        fn reserve(_: *anyopaque, worker: *W.Worker) anyerror!void {
            try worker.reserveBatches(2, 64);
        }
        fn call(raw: *anyopaque, worker: *W.Worker) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            worker.runBatch(self.batch);
            worker.finishBatch(self.batch, true); // fake operations execute eagerly
        }
    };
    for ([_]usize{ 896, 512 }) |first_work| {
        fake.reset();
        const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1024, .pinned_slot_words = 64 });
        defer w.destroy();
        var log = Log{};
        var first = MemoryJob{ .id = 0, .log = &log, .staged_words = 64, .work_words = first_work };
        var second = MemoryJob{ .id = 1, .log = &log, .staged_words = 128, .work_words = 128 };
        var jobs = [_]W.BatchJob{ .{ .job = api.Job.from(MemoryJob, &first) }, .{ .job = api.Job.from(MemoryJob, &second) } };
        var batch = W.Batch{ .jobs = &jobs };
        var run = Run{ .batch = &batch };
        var reserve_context: u8 = 0;
        try w.call(.{ .ctx = &reserve_context, .run = Run.reserve });
        try w.call(.{ .ctx = &run, .run = Run.call });
        try batch.result;
        for (jobs) |job| try job.result;
        const deferred = first_work == 896;
        try std.testing.expectEqual(deferred, log.index("enqueue", 0) < log.index("stage", 1));
        try std.testing.expectEqual(@as(u64, @intFromBool(deferred)), batch.memory_serializations);
    }
}
