//! Request retention and completion ownership: pins, retirement, callbacks and class accounting.
const std = @import("std");
const api = @import("api.zig");
const O = @import("ops.zig");
const MP = @import("plan.zig");
const Retained = @import("retained.zig");

const Worker = @import("worker.zig").Worker;
const Records = @import("worker_records.zig");

pub fn retainFor(self: *Worker, slot: *Records.Slot, key: Retained.Key, words: usize, may_create: bool) !api.Retained {
    if (words == 0) return error.InvalidAllocation;
    if (slot.retained_count == slot.retained_refs.len) return error.TooManyRetainedRegions;
    self.mutex.lock();
    if (self.retained.pin(key, words)) |b| {
        self.mutex.unlock();
        slot.retained_refs[slot.retained_count] = b;
        slot.retained_fresh[slot.retained_count] = false;
        slot.retained_count += 1;
        return .{ .buffer = b, .fresh = false };
    } else |err| if (err != error.RetainedRegionNotFound or !may_create) {
        self.mutex.unlock();
        return err;
    }
    // Only this (worker) thread inserts: live words can only shrink until the insert.
    if (!self.retained.admits(words)) {
        self.retained.stats.budget_refusals += 1;
        self.mutex.unlock();
        return error.RetainedBudgetExhausted;
    }
    self.mutex.unlock();
    var ptr: ?[*]u32 = null;
    try O.check(self.ops.exec.alloc_u32_long(self.context, words, &ptr));
    const b = api.DeviceBuffer{ .ptr = ptr orelse return error.CudaAllocationFailed, .words = words };
    self.mutex.lock();
    defer self.mutex.unlock();
    self.retained.insert(self.a, key, b) catch |err| {
        _ = self.ops.exec.free_u32(self.context, b.ptr);
        return err;
    };
    slot.retained_refs[slot.retained_count] = b;
    slot.retained_fresh[slot.retained_count] = true;
    slot.retained_count += 1;
    return .{ .buffer = b, .fresh = true };
}

pub fn stageRetain(self: *Worker, request: u64, name: [32]u8, words: usize, may_create: bool) !api.Retained {
    const slot = self.staging orelse return error.StagerOutsidePhaseOne;
    return retainFor(self, slot, .{ .request = request, .name = name }, words, may_create);
}

pub fn enqueueRetain(self: *Worker, request: u64, name: [32]u8, words: usize, may_create: bool) !api.Retained {
    const slot = self.enqueuing orelse return error.EnqueueOutsidePhaseTwo;
    return retainFor(self, slot, .{ .request = request, .name = name }, words, may_create);
}

pub fn isRetained(self: *Worker, dst: api.DeviceBuffer, words: usize) bool {
    self.mutex.lock();
    defer self.mutex.unlock();
    return self.retained.contains(@intFromPtr(dst.ptr), words);
}

pub fn unpinRetained(self: *Worker, slot: *Records.Slot, ok: bool) void {
    if (slot.retained_count == 0) return;
    var free_now: [16]api.DeviceBuffer = undefined;
    var n: usize = 0;
    self.mutex.lock();
    for (slot.retained_refs[0..slot.retained_count], slot.retained_fresh[0..slot.retained_count]) |b, fresh| {
        if (!ok and fresh) for (self.retained.entries.items) |*e| if (e.buffer.ptr == b.ptr) {
            e.released = true;
        };
        if (self.retained.unpin(b)) |f| {
            free_now[n] = f;
            n += 1;
        }
    }
    self.mutex.unlock();
    slot.retained_count = 0;
    if (n == 0) return;
    // A refused job may have h2d uploads in flight into a fresh region:
    // order the (exec-stream) free after them on the device.
    if (slot.uploads) if (slot.staged_event) |ev| {
        if (O.check(self.ops.exec.event_record(ev, self.h2d_stream))) |_| {
            O.check(self.ops.exec.stream_wait(self.exec_stream, ev)) catch |err| markFatal(self, err);
        } else |err| markFatal(self, err);
    };
    freeRetained(self, free_now[0..n]);
}

pub fn freeRetained(self: *Worker, buffers: []const api.DeviceBuffer) void {
    for (buffers) |b| {
        O.check(self.ops.exec.free_u32(self.context, b.ptr)) catch |err| std.log.err("M8 retained region free failed: {s}", .{@errorName(err)});
    }
    self.mutex.lock();
    defer self.mutex.unlock();
    for (buffers) |b| self.retained.drop(b);
    self.cond.broadcast();
}

pub fn drainRetained(self: *Worker) void {
    self.mutex.lock();
    if (self.retained_pending.items.len == 0) {
        self.mutex.unlock();
        return;
    }
    const pending = self.retained_pending.toOwnedSlice(self.a) catch {
        self.mutex.unlock();
        return;
    };
    self.mutex.unlock();
    defer self.a.free(pending);
    freeRetained(self, pending);
}

pub fn releaseAllRetained(self: *Worker) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    for (self.retained.entries.items) |*e| if (!e.released) {
        e.released = true;
        if (e.pins == 0) self.retained_pending.append(self.a, e.buffer) catch {};
    };
}

pub fn releaseRetained(self: *Worker, request: u64, name: [32]u8) !void {
    self.mutex.lock();
    defer self.mutex.unlock();
    try self.retained_pending.ensureUnusedCapacity(self.a, 1);
    if (try self.retained.release(.{ .request = request, .name = name })) |b| self.retained_pending.appendAssumeCapacity(b);
    self.cond.broadcast();
}

pub fn releaseRequest(self: *Worker, request: u64) !usize {
    self.mutex.lock();
    defer self.mutex.unlock();
    const n = try self.retained.releaseRequest(self.a, request, &self.retained_pending);
    self.cond.broadcast();
    return n;
}

pub fn releaseRequestAndWait(self: *Worker, request: u64) !usize {
    if (self.thread_id == std.Thread.getCurrentId()) return error.ReleaseWaitOnWorkerThread;
    const n = try self.releaseRequest(request);
    self.mutex.lock();
    defer self.mutex.unlock();
    while (self.retained.liveWords(request) != 0 and !self.stopped) self.cond.wait(&self.mutex);
    return n;
}

pub fn retainedWords(self: *Worker, request: ?u64) usize {
    self.mutex.lock();
    defer self.mutex.unlock();
    return self.retained.liveWords(request);
}

pub fn retainedStats(self: *Worker) Retained.Stats {
    self.mutex.lock();
    defer self.mutex.unlock();
    return self.retained.stats;
}

pub fn markFatal(self: *Worker, err: anyerror) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    if (self.fatal == null) self.fatal = err;
}

pub fn report(self: *Worker, slot: *Records.Slot, result: anyerror!void) void {
    settle(self, slot, result);
    slot.sink.done(slot.sink.ctx, .{ .job = slot.job, .result = result, .receipt = slot.receipt });
    self.mutex.lock();
    self.outstanding -= 1;
    self.completed += 1;
    self.cond.broadcast();
    self.mutex.unlock();
}

pub fn settle(self: *Worker, slot: *Records.Slot, result: anyerror!void) void {
    settleKeyed(self, slot, result, null);
}

pub fn settleKeyed(self: *Worker, slot: *Records.Slot, result: anyerror!void, known_key: ?[32]u8) void {
    for (slot.pinned_keys[0..slot.pinned_count]) |key| self.regions.unpin(key);
    slot.pinned_count = 0;
    unpinRetained(self, slot, if (result) |_| true else |_| false);
    if (result) |_| {} else |_| {
        // A failed job may have left its fresh persistent buffers unfilled.
        if (self.regions_buffer != null) {
            for (slot.fresh_keys[0..slot.fresh_count]) |key| self.regions.retire(key);
        } else for (slot.fresh_keys[0..slot.fresh_count]) |key| if (self.persistent_map.fetchRemove(key)) |kv| {
            self.retired.append(self.a, kv.value) catch {}; // OOM: leak until process exit
        };
    }
    slot.fresh_count = 0;
    var key: [32]u8 = @splat(0);
    const ok = if (result) |_| true else |_| false;
    if (ok) key = known_key orelse slot.job.classKey();
    // Class stats are recorded BEFORE the sink fires: a completion waiter
    // may read them (classStats / writePlanDir) as soon as done() returns.
    self.mutex.lock();
    if (ok) if (self.classes.getOrPut(self.a, key)) |entry| {
        if (!entry.found_existing) entry.value_ptr.* = .{};
        const c = entry.value_ptr;
        const r = slot.receipt;
        c.jobs += 1;
        c.peak_arena_words = @max(c.peak_arena_words, r.arena_peak_words);
        c.staged_words = @max(c.staged_words, r.staged_words);
        c.slab_words = @max(c.slab_words, slot.footprint.slab_words);
        c.peak_pinned_words = @max(c.peak_pinned_words, slot.pinned_used);
        c.stage_ns += r.stage_ns;
        c.enqueue_ns += r.enqueue_ns;
        c.wait_ns += r.wait_ns;
        const declared_fp = slot.declared;
        c.declared_device_words = @max(c.declared_device_words, declared_fp.device_words);
        c.declared_staged_words = @max(c.declared_staged_words, declared_fp.staged_words);
        c.declared_pinned_words = @max(c.declared_pinned_words, declared_fp.pinned_words);
        c.declared_peak_words = @max(c.declared_peak_words, MP.peakOf(declared_fp));
        if (slot.resolved.planned) {
            c.planned_peak_words = @max(c.planned_peak_words, slot.resolved.peak_words);
            if (r.arena_peak_words > slot.resolved.peak_words) c.over_plan += 1;
        }
        if (slot.serialized) c.serialized += 1;
        c.persistent_words = @max(c.persistent_words, slot.persistent_words);
        const sd = &c.sides[@intFromEnum(slot.placement)];
        sd.jobs += 1;
        sd.staged_words = @max(sd.staged_words, r.staged_words);
        sd.allocs = @max(sd.allocs, slot.allocs);
        sd.live_peak_words = @max(sd.live_peak_words, slot.live_peak);
        if (r.arena_peak_words >= sd.peak_arena_words) {
            sd.peak_arena_words = r.arena_peak_words;
            sd.peak_alloc = slot.peak_alloc;
            sd.peak_alloc_words = slot.peak_alloc_words;
        }
    } else |_| {};
    self.mutex.unlock();
}
