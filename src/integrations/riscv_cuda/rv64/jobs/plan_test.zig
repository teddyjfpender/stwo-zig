const std = @import("std");
const P = @import("plan.zig");
const W = @import("worker.zig");
const api = @import("api.zig");
const fake = @import("fake.zig");
const Arena = W.Arena;
const Regions = W.Regions;
const g = Arena.granule;

// ---------------- arena: non-LIFO reuse (LIFO-free peak fix) ----------------

/// A PCS-like retirement pattern: a big early buffer dies before a late
/// scratch is needed. LIFO frees cannot reclaim it, so the late scratch sets
/// the peak; with reuse it lands in the hole.
fn latePattern(arena: *Arena) ![3]usize {
    const big = try arena.workAlloc(8 * g);
    const keep = try arena.workAlloc(2 * g);
    arena.workFree(big, 8 * g); // not the most recent allocation
    const late = try arena.workAlloc(6 * g);
    return .{ big, keep, late };
}

test "arena reuse: a non-LIFO free becomes a hole that a later allocation takes; the peak drops" {
    for ([_]api.Placement{ .bottom, .top }) |side| {
        var lifo = Arena{ .base = 0x1000, .words = 64 * g };
        lifo.beginWork(side, false);
        _ = try latePattern(&lifo);
        try std.testing.expectEqual(@as(usize, 16 * g), lifo.peak);
        try std.testing.expectEqual(@as(usize, 10 * g), lifo.live_peak);
        try std.testing.expectEqual(@as(usize, 3), lifo.peak_alloc); // the late scratch set it

        var reuse = Arena{ .base = 0x1000, .words = 64 * g, .reuse = true };
        reuse.beginWork(side, false);
        const at = try latePattern(&reuse);
        // The late scratch lands inside the dead buffer (offsets grow away from the side's end).
        try std.testing.expect(at[2] >= at[0] and at[2] + 4 * 6 * g <= at[0] + 4 * 8 * g);
        if (side == .bottom) try std.testing.expectEqual(at[0], at[2]);
        try std.testing.expectEqual(@as(usize, 10 * g), reuse.peak);
        try std.testing.expectEqual(reuse.peak, reuse.live_peak);
        // Deterministic: the same sequence on the same side gives the same addresses (graph replay).
        var again = Arena{ .base = 0x1000, .words = 64 * g, .reuse = true };
        again.beginWork(side, false);
        try std.testing.expectEqual(at, try latePattern(&again));
    }
}

test "arena reuse: holes coalesce, the bump retracts over a free tail, double frees are ignored" {
    var a = Arena{ .base = 0, .words = 64 * g, .reuse = true };
    a.beginWork(.bottom, false);
    const x = try a.workAlloc(g);
    const y = try a.workAlloc(g);
    const z = try a.workAlloc(g);
    a.workFree(x, g);
    a.workFree(y, g); // coalesces with x
    try std.testing.expectEqual(@as(usize, 1), a.hole_count);
    a.workFree(y, g); // double free: overlaps the hole, ignored
    try std.testing.expectEqual(@as(usize, g), a.live);
    a.workFree(z, g); // most recent: bump retracts over the coalesced hole to the origin
    try std.testing.expectEqual(@as(usize, 0), a.bump);
    try std.testing.expectEqual(@as(usize, 0), a.hole_count);
    try std.testing.expectEqual(x, try a.workAlloc(3 * g));
}

test "arena reuse: best fit, lowest offset on ties, split remainder stays a hole" {
    var a = Arena{ .base = 0, .words = 64 * g, .reuse = true };
    a.beginWork(.bottom, false);
    var b: [6]usize = undefined;
    for (&b, [_]usize{ 4, 1, 2, 1, 2, 1 }) |*p, n| p.* = try a.workAlloc(n * g);
    a.workFree(b[0], 4 * g);
    a.workFree(b[2], 2 * g);
    a.workFree(b[4], 2 * g);
    try std.testing.expectEqual(b[2], try a.workAlloc(2 * g)); // 2-hole beats the 4-hole; first of the two 2-holes
    try std.testing.expectEqual(b[4], try a.workAlloc(g)); // the other 2-hole
    try std.testing.expectEqual(b[4] + 4 * g, try a.workAlloc(g)); // its remainder
    try std.testing.expectEqual(b[0], try a.workAlloc(3 * g));
}

test "arena without reuse keeps today's LIFO behavior exactly" {
    var a = Arena{ .base = 0, .words = 16 * g };
    a.beginWork(.bottom, false);
    const x = try a.workAlloc(g);
    _ = try a.workAlloc(g);
    a.workFree(x, g);
    try std.testing.expectEqual(@as(usize, 0), a.hole_count);
    try std.testing.expectEqual(@as(usize, 2 * g), a.bump);
    try std.testing.expectEqual(x + 8 * g, try a.workAlloc(g));
}

// ---------------- class regions: LRU within a budget ----------------

fn key(n: u8) [32]u8 {
    return @splat(n);
}

test "regions: LRU eviction of unpinned regions, pins block eviction, budget is a hard bound" {
    const a = std.testing.allocator;
    var r = Regions{ .words = 4 * g };
    defer r.deinit(a);
    const k1 = try r.acquire(a, key(1), 2 * g);
    const k2 = try r.acquire(a, key(2), 2 * g);
    try std.testing.expect(k1.fresh and k2.fresh);
    try std.testing.expectEqual(@as(usize, 0), k1.offset);
    try std.testing.expectEqual(@as(usize, 2 * g), k2.offset);
    // Both pinned (in flight): a third class cannot evict either.
    try std.testing.expectError(error.PersistentBudgetExhausted, r.acquire(a, key(3), g));
    r.unpin(key(1));
    r.unpin(key(2));
    // Touch 1 so 2 is least recently used.
    const warm = try r.acquire(a, key(1), 2 * g);
    try std.testing.expect(!warm.fresh);
    r.unpin(key(1));
    const k3 = try r.acquire(a, key(3), 2 * g);
    try std.testing.expect(k3.fresh);
    try std.testing.expectEqual(@as(usize, 2 * g), k3.offset); // took 2's place
    try std.testing.expectEqual(@as(u64, 1), r.evictions);
    try std.testing.expect(r.find(key(2)) == null);
    r.unpin(key(3));
    // 2 comes back fresh (it was evicted) and evicts the LRU (1).
    const back = try r.acquire(a, key(2), 2 * g);
    try std.testing.expect(back.fresh);
    try std.testing.expectEqual(@as(usize, 0), back.offset);
    r.unpin(key(2));
    try std.testing.expectError(error.PersistentRegionExceedsBudget, r.acquire(a, key(9), 4 * g + 1));
    try std.testing.expectError(error.PersistentGeometryMismatch, r.acquire(a, key(3), g));
}

test "regions: eviction frees enough contiguous space (first fit), retired fills are never reused" {
    const a = std.testing.allocator;
    var r = Regions{ .words = 6 * g };
    defer r.deinit(a);
    for ([_]u8{ 1, 2, 3 }) |k| {
        _ = try r.acquire(a, key(k), 2 * g);
        r.unpin(key(k));
    }
    r.retire(key(2)); // failed fill: [2g, 4g) stays occupied
    // 4g contiguous is impossible around the retired range even with 1 and 3
    // gone: the acquire fails WITHOUT evicting anything.
    try std.testing.expectError(error.PersistentBudgetExhausted, r.acquire(a, key(4), 4 * g));
    try std.testing.expectEqual(@as(u64, 0), r.evictions);
    // 2g fits after evicting the LRU (1) only.
    const k5 = try r.acquire(a, key(5), 2 * g);
    try std.testing.expectEqual(@as(usize, 0), k5.offset);
    try std.testing.expectEqual(@as(u64, 1), r.evictions);
    try std.testing.expect(r.find(key(3)) != null);
    const again = try r.acquire(a, key(2), 2 * g); // a retired key is not found: fresh elsewhere
    try std.testing.expect(again.fresh);
}

// ---------------- policy document ----------------

fn policyText(buf: []u8, arena_words: usize, classes: []const struct { k: u8, peak: usize, staged: usize, conc: u32 }, extra_gpu: []const u8) ![]const u8 {
    var w = std.Io.Writer.fixed(buf);
    try w.print("{{\"schema\":\"{s}\",\"gpu\":{{\"arena_words\":{d}{s}}},\"classes\":[", .{ P.schema, arena_words, extra_gpu });
    for (classes, 0..) |c, i| {
        if (i != 0) try w.writeAll(",");
        try w.print("{{\"label\":\"c{d}\",\"class_key\":\"{s}\",\"peak_words\":{d},\"staged_words\":{d},\"slab_words\":64,\"max_concurrent\":{d}}}", .{ c.k, std.fmt.bytesToHex(key(c.k), .lower), c.peak, c.staged, c.conc });
    }
    try w.writeAll("]}");
    return w.buffered();
}

test "policy: parse, resolve a planned class, fall back to the declaration for an unplanned one" {
    var buf: [4096]u8 = undefined;
    const text = try policyText(&buf, 64 * g, &.{ .{ .k = 1, .peak = 20 * g, .staged = 4 * g, .conc = 2 }, .{ .k = 2, .peak = 40 * g, .staged = 8 * g, .conc = 2 } }, "");
    const p = try P.Policy.parse(std.testing.allocator, text);
    defer p.deinit();
    const declared = api.Footprint{ .device_words = 5000 * g, .staged_words = 3 * g, .slab_words = 10, .pinned_words = 7 };
    const r = p.resolve(key(1), declared);
    try std.testing.expect(r.planned);
    try std.testing.expectEqual(@as(usize, 20 * g), r.peak_words);
    try std.testing.expectEqual(@as(usize, 20 * g - g - g), r.footprint.device_words); // minus slab granule and state granule
    try std.testing.expectEqual(@as(usize, 10), r.footprint.slab_words); // slab stays the job's own
    try std.testing.expectEqual(@as(usize, 7), r.footprint.pinned_words);
    try std.testing.expectEqual(@as(usize, 4 * g), r.staged_words);
    try std.testing.expectEqual(P.peakOf(r.footprint), r.peak_words);
    const u = p.resolve(key(9), declared);
    try std.testing.expect(!u.planned);
    try std.testing.expectEqual(P.peakOf(declared), u.peak_words);
    // A measured peak below the job's own parts never wins.
    const small = p.resolve(key(1), .{ .device_words = 0, .staged_words = 30 * g, .slab_words = 64 });
    try std.testing.expectEqual(@as(usize, 32 * g), small.peak_words);
}

test "policy: validation rejects stale or impossible documents" {
    const a = std.testing.allocator;
    var buf: [4096]u8 = undefined;
    try std.testing.expectError(error.MemoryPolicyClassExceedsArena, P.Policy.parse(a, try policyText(&buf, 16 * g, &.{.{ .k = 1, .peak = 20 * g, .staged = 0, .conc = 1 }}, "")));
    // Claims overlap (2) but 40g working + 40g staged > 64g.
    try std.testing.expectError(error.MemoryPolicyConcurrencyClaimDoesNotFit, P.Policy.parse(a, try policyText(&buf, 64 * g, &.{.{ .k = 1, .peak = 48 * g, .staged = 40 * g, .conc = 2 }}, "")));
    try std.testing.expectError(error.MemoryPolicyDuplicateClass, P.Policy.parse(a, try policyText(&buf, 64 * g, &.{ .{ .k = 1, .peak = 8 * g, .staged = 0, .conc = 2 }, .{ .k = 1, .peak = 8 * g, .staged = 0, .conc = 2 } }, "")));
    try std.testing.expectError(error.MemoryPolicyUnalignedClass, P.Policy.parse(a, try policyText(&buf, 64 * g, &.{.{ .k = 1, .peak = 8 * g + 1, .staged = 0, .conc = 2 }}, "")));
    try std.testing.expectError(error.MemoryPolicyClassPeakBelowParts, P.Policy.parse(a, try policyText(&buf, 64 * g, &.{.{ .k = 1, .peak = 4 * g, .staged = 4 * g, .conc = 2 }}, "")));
    try std.testing.expectError(error.MemoryPolicyInvalidArena, P.Policy.parse(a, try policyText(&buf, 64 * g + 3, &.{}, "")));
    try std.testing.expectError(error.MemoryPolicySchemaMismatch, P.Policy.parse(a, "{\"schema\":\"x\",\"gpu\":{\"arena_words\":64}}"));
}

// ---------------- static layout: every co-resident class pair ----------------

test "layout: a pair that fits is disjoint and in bounds on both placements; one that does not is reported" {
    try P.checkPair(64 * g, 40 * g, 8 * g, 24 * g, .bottom);
    try P.checkPair(64 * g, 40 * g, 8 * g, 24 * g, .top);
    try std.testing.expectError(error.PairDoesNotFit, P.checkPair(64 * g, 40 * g, 8 * g, 24 * g + g, .top));
    try P.checkPair(64 * g, 64 * g, 0, 0, .bottom); // alone it may fill the arena
}

test "layout: a generated policy's concurrency claims hold for every class pair (Airbender static arena)" {
    var buf: [4096]u8 = undefined;
    // c1 fits beside everything; c3 is too big to overlap with c2's inputs, so it serializes.
    const text = try policyText(&buf, 64 * g, &.{
        .{ .k = 1, .peak = 20 * g, .staged = 4 * g, .conc = 2 },
        .{ .k = 2, .peak = 30 * g, .staged = 12 * g, .conc = 2 },
        .{ .k = 3, .peak = 56 * g, .staged = 2 * g, .conc = 1 },
    }, "");
    const p = try P.Policy.parse(std.testing.allocator, text);
    defer p.deinit();
    try std.testing.expectEqual(@as(usize, 18), try P.checkPolicyLayout(p));
}

test "layout: the committed memory policy passes the pairwise check" {
    // Runs with cwd = src/integrations/riscv_cuda (build.zig setCwd for test-rv64-jobs).
    const path = "../../../vectors/reports/rv64-m8-20261106/memory-plan/policy.json";
    const p = P.Policy.load(std.testing.allocator, path) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer p.deinit();
    _ = try P.checkPolicyLayout(p);
    try std.testing.expect(p.classes().len != 0);
}

// ---------------- the worker consuming a policy (host device model) ----------------

const Sized = struct {
    k: u8,
    staged: usize,
    work: usize,
    declared_device: usize,
    persistent: ?struct { k: u8, words: usize } = null,
    fresh: ?bool = null,
    gate: ?*std.Thread.Semaphore = null,
    result: u32 = 0,
    input: [4]u32 = .{ 1, 2, 3, 4 },
    buf: ?api.DeviceBuffer = null,
    pub fn classKey(self: *Sized) [32]u8 {
        return key(self.k);
    }
    pub fn footprint(self: *Sized) api.Footprint {
        return .{ .device_words = self.declared_device, .staged_words = self.staged, .slab_words = 4, .pinned_words = 64 };
    }
    pub fn stage(self: *Sized, s: *api.Stager) !void {
        if (self.gate) |sem| sem.wait();
        const b = try s.alloc(self.staged);
        try s.upload(b, &self.input);
        self.buf = b;
        if (self.persistent) |pr| {
            const got = try s.persistent(key(pr.k), pr.words);
            self.fresh = got.fresh;
            if (got.fresh) try s.upload(got.buffer, &self.input);
        }
    }
    pub fn enqueue(self: *Sized, e: *api.Enqueue) !void {
        const scratch = try e.alloc(self.work);
        var sum: u32 = 0;
        for (self.buf.?.ptr[0..4]) |x| sum += x;
        scratch.ptr[0] = sum + self.k;
        e.slab.device.ptr[0] = scratch.ptr[0];
        e.free(scratch);
    }
    pub fn finish(self: *Sized, v: api.SlabView) !void {
        self.result = v.words[0];
    }
    pub fn abort(_: *Sized) void {}
};

const Done = struct {
    mutex: std.Thread.Mutex = .{},
    n: usize = 0,
    errors: usize = 0,
    last: ?anyerror = null,
    fn sink(self: *Done) W.Sink {
        return .{ .ctx = self, .done = on };
    }
    fn on(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
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

fn put(w: *W.Worker, job: api.Job, sink: W.Sink) void {
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

fn statOf(w: *W.Worker, k: u8) !W.ClassStat {
    const stats = try w.classStats(std.testing.allocator);
    defer std.testing.allocator.free(stats);
    for (stats) |e| if (std.mem.eql(u8, &e.key, &key(k))) return e.stat;
    return error.ClassNotRecorded;
}

// A: 4g staged + 8g work; peak = 4g + state g + slab g + 8g = 14g. B: 4g staged.
// Arena 16g: A working beside B's inputs needs 18g, so the pair must serialize.
fn pairJobs(a_job: *Sized, b_job: *Sized) void {
    a_job.* = .{ .k = 1, .staged = 4 * g, .work = 8 * g, .declared_device = 12 * g };
    b_job.* = .{ .k = 2, .staged = 4 * g, .work = g, .declared_device = 5 * g };
}

test "worker without a policy: a pair that does not fit fails the working job (today's hazard)" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .device = 0, .arena_words = 16 * g, .pinned_slot_words = 1 << 12 });
    var a_job: Sized = undefined;
    var b_job: Sized = undefined;
    pairJobs(&a_job, &b_job);
    var gate = std.Thread.Semaphore{};
    a_job.gate = &gate;
    var d = Done{};
    put(w, api.Job.from(Sized, &a_job), d.sink());
    put(w, api.Job.from(Sized, &b_job), d.sink()); // in the mailbox before A's stage returns
    gate.post();
    d.wait(2);
    w.destroy();
    try std.testing.expectEqual(@as(usize, 1), d.errors);
    try std.testing.expectEqual(error.JobWorkExceedsArena, d.last.?);
}

test "worker with a policy: the same pair serializes instead of failing, both proofs are right" {
    fake.reset();
    var buf: [4096]u8 = undefined;
    const text = try policyText(&buf, 16 * g, &.{ .{ .k = 1, .peak = 14 * g, .staged = 4 * g, .conc = 1 }, .{ .k = 2, .peak = 7 * g, .staged = 4 * g, .conc = 2 } }, "");
    const p = try P.Policy.parse(std.testing.allocator, text);
    defer p.deinit();
    _ = try P.checkPolicyLayout(p);
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .device = 0, .arena_words = 1 << 20, .pinned_slot_words = 1 << 12, .plan = p });
    try std.testing.expectEqual(@as(usize, 16 * g), w.config.arena_words); // the policy sized the arena
    var a_job: Sized = undefined;
    var b_job: Sized = undefined;
    pairJobs(&a_job, &b_job);
    var gate = std.Thread.Semaphore{};
    a_job.gate = &gate;
    var d = Done{};
    put(w, api.Job.from(Sized, &a_job), d.sink());
    // A is held in its stage (the tail): B does not fit beside it; another A would not either.
    try std.testing.expect(!w.fits(api.Job.from(Sized, &b_job)));
    put(w, api.Job.from(Sized, &b_job), d.sink());
    gate.post();
    d.wait(2);
    try std.testing.expect(w.fits(api.Job.from(Sized, &b_job))); // nothing waits to be enqueued
    const sa = try statOf(w, 1);
    const sb = try statOf(w, 2);
    w.destroy();
    try std.testing.expectEqual(@as(usize, 0), d.errors);
    try std.testing.expectEqual(@as(u32, 10 + 1), a_job.result);
    try std.testing.expectEqual(@as(u32, 10 + 2), b_job.result);
    try std.testing.expectEqual(@as(u64, 14 * g), sa.sides[0].peak_arena_words);
    try std.testing.expectEqual(@as(u64, 14 * g), sa.planned_peak_words);
    try std.testing.expectEqual(@as(u64, 12 * g), sa.declared_device_words);
    try std.testing.expectEqual(@as(u64, 0), sa.over_plan);
    try std.testing.expectEqual(@as(u64, 1), sb.serialized);
    try std.testing.expectEqual(@as(u64, 1), sb.sides[1].jobs);
}

test "worker with a policy: the measured peak replaces an inflated declaration (no refusal)" {
    fake.reset();
    var buf: [4096]u8 = undefined;
    const text = try policyText(&buf, 32 * g, &.{.{ .k = 2, .peak = 7 * g, .staged = 4 * g, .conc = 2 }}, "");
    const p = try P.Policy.parse(std.testing.allocator, text);
    defer p.deinit();
    var job = Sized{ .k = 2, .staged = 4 * g, .work = g, .declared_device = 1 << 30 }; // hand-declared, far above the arena
    var d = Done{};
    {
        const w0 = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .device = 0, .arena_words = 32 * g, .pinned_slot_words = 1 << 12 });
        put(w0, api.Job.from(Sized, &job), d.sink());
        d.wait(1);
        w0.destroy();
        try std.testing.expectEqual(error.JobFootprintExceedsArena, d.last.?);
    }
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .device = 0, .arena_words = 32 * g, .pinned_slot_words = 1 << 12, .plan = p });
    put(w, api.Job.from(Sized, &job), d.sink());
    d.wait(2);
    w.destroy();
    try std.testing.expectEqual(@as(usize, 1), d.errors);
    try std.testing.expectEqual(@as(u32, 12), job.result);
}

test "worker with a persistent budget: class regions are evicted LRU and refilled fresh" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .device = 0, .arena_words = 64 * g, .pinned_slot_words = 1 << 12, .persistent_budget_words = 4 * g });
    var jobs: [5]Sized = undefined;
    // Classes 1, 2, 3, 1, 2 each holding a 2g persistent region; the budget holds two.
    for (&jobs, [_]u8{ 1, 2, 3, 1, 2 }) |*j, k| j.* = .{ .k = k, .staged = g, .work = g, .declared_device = 4 * g, .persistent = .{ .k = 100 + k, .words = 2 * g } };
    var d = Done{};
    for (&jobs, 0..) |*j, i| {
        put(w, api.Job.from(Sized, j), d.sink());
        d.wait(i + 1); // one at a time: nothing else pins a region
    }
    const s1 = try statOf(w, 1);
    const evictions = w.regions.evictions;
    w.destroy();
    try std.testing.expectEqual(@as(usize, 0), d.errors);
    // 1,2 fresh; 3 evicts 1; 1 evicts 2; 2 evicts 3.
    for (jobs, [_]bool{ true, true, true, true, true }) |j, fresh| try std.testing.expectEqual(fresh, j.fresh.?);
    try std.testing.expectEqual(@as(u64, 3), evictions);
    try std.testing.expectEqual(@as(u64, 2 * g), s1.persistent_words);
    // Arena + one pool + 3 pinned slots: no per-key allocations.
    try std.testing.expectEqual(@as(usize, 2), fake.counters.allocations);
}

test "worker with a persistent budget: a warm class keeps its region (no refill)" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .device = 0, .arena_words = 64 * g, .pinned_slot_words = 1 << 12, .persistent_budget_words = 4 * g });
    var jobs: [4]Sized = undefined;
    for (&jobs, [_]u8{ 1, 2, 1, 2 }) |*j, k| j.* = .{ .k = k, .staged = g, .work = g, .declared_device = 4 * g, .persistent = .{ .k = 100 + k, .words = 2 * g } };
    var d = Done{};
    for (&jobs) |*j| put(w, api.Job.from(Sized, j), d.sink()); // pipelined: regions pinned while in flight
    d.wait(4);
    const evictions = w.regions.evictions;
    w.destroy();
    try std.testing.expectEqual(@as(usize, 0), d.errors);
    try std.testing.expect(jobs[0].fresh.? and jobs[1].fresh.? and !jobs[2].fresh.? and !jobs[3].fresh.?);
    try std.testing.expectEqual(@as(u64, 0), evictions);
}

test "worker plan output: STWO_RV64_M8_JOBS_PLAN_DIR rows parse back (sweep input)" {
    // The env var is read at destroy; write directly through the same code path.
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .device = 3, .arena_words = 64 * g, .pinned_slot_words = 1 << 12, .reuse_frees = true });
    var job = Sized{ .k = 7, .staged = g, .work = 2 * g, .declared_device = 6 * g };
    var d = Done{};
    put(w, api.Job.from(Sized, &job), d.sink());
    d.wait(1);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir);
    try w.writePlanDir(dir);
    w.destroy();
    var it = tmp.dir.iterate();
    const entry = (try it.next()).?;
    const bytes = try tmp.dir.readFileAlloc(std.testing.allocator, entry.name, 1 << 20);
    defer std.testing.allocator.free(bytes);
    const Doc = struct { schema: []const u8, device: u32, arena_words: u64, allocator: []const u8, classes: []const struct { class_key: []const u8, stat: W.ClassStat } };
    const parsed = try std.json.parseFromSlice(Doc, std.testing.allocator, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("rv64-m8-jobs-class-plans/v2", parsed.value.schema);
    try std.testing.expectEqualStrings("reuse", parsed.value.allocator);
    try std.testing.expectEqual(@as(u32, 3), parsed.value.device);
    const row = parsed.value.classes[0];
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(key(7), .lower), row.class_key);
    // 1g staged + state g + slab g + 2g work
    try std.testing.expectEqual(@as(u64, 5 * g), row.stat.sides[0].peak_arena_words);
    try std.testing.expectEqual(@as(u64, 6 * g), row.stat.declared_device_words);
    try std.testing.expectEqual(@as(u64, g), row.stat.sides[0].staged_words);
}
