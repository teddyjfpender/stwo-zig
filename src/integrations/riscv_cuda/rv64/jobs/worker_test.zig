const std = @import("std");
const W = @import("worker.zig");
const api = @import("api.zig");
const fake = @import("fake.zig");
const Arena = W.Arena;

test "arena: staged inputs sit at their side's end and bound the other side's work" {
    var a = Arena{ .base = 0x10000, .words = 1024 };
    a.beginStage(.bottom);
    const b0 = try a.stageAlloc(.bottom, 10); // rounds to 64
    try std.testing.expectEqual(@as(usize, 0x10000), b0);
    a.beginStage(.top);
    const t0 = try a.stageAlloc(.top, 64);
    try std.testing.expectEqual(@as(usize, 0x10000 + 4 * (1024 - 64)), t0);
    // bottom job works between its inputs and the staged top inputs
    a.beginWork(.bottom, true);
    const w0 = try a.workAlloc(128);
    try std.testing.expectEqual(@as(usize, 0x10000 + 4 * 64), w0);
    try std.testing.expectError(error.JobWorkExceedsArena, a.workAlloc(1024 - 64 - 128 - 64 + 1));
    _ = try a.workAlloc(1024 - 64 - 128 - 64);
    try std.testing.expectEqual(@as(usize, 1024 - 64), a.peak);
}

test "arena: top side grows down; LIFO free reclaims; no staged neighbour frees the window" {
    var a = Arena{ .base = 0, .words = 640 };
    a.beginStage(.top);
    _ = try a.stageAlloc(.top, 64);
    a.beginWork(.top, false); // nothing staged on the bottom: whole window
    const x = try a.workAlloc(64);
    try std.testing.expectEqual(@as(usize, 4 * (640 - 128)), x);
    const y = try a.workAlloc(100);
    a.workFree(y, 100);
    const z = try a.workAlloc(128);
    try std.testing.expectEqual(y, z);
    a.workFree(x, 64); // not the most recent: kept until the window resets
    try std.testing.expectEqual(z - 4 * 64, try a.workAlloc(1));
}

test "arena: staged inputs of both sides cannot exceed the arena" {
    var a = Arena{ .base = 0, .words = 256 };
    a.beginStage(.bottom);
    _ = try a.stageAlloc(.bottom, 128);
    a.beginStage(.top);
    _ = try a.stageAlloc(.top, 128);
    try std.testing.expectError(error.StagedInputsExceedArena, a.stageAlloc(.top, 1));
    a.beginStage(.bottom); // the bottom job finished; its inputs are reusable
    _ = try a.stageAlloc(.bottom, 64);
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
        return .{ .device_words = self.footprint_words, .staged_words = 64, .slab_words = 4, .pinned_words = 64 };
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
        self.result = v.words[0];
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
