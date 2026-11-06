//! DeviceWorker (spec §3.2): one OS thread per GPU owning one exec context
//! (1 lane = the exec stream), an h2d stream, a static two-sided arena and three
//! pinned host slots. The loop is Airbender's 3-stage pipeline:
//!
//!     stage(job[k+1], placement = alt(k+1))   // host + h2d stream
//!     enqueue(job[k])                          // exec stream, no host waits
//!     event_sync(job[k-1]); finish(job[k-1])   // the only host wait per job
//!
//! No admission, permits or leases. A job whose declared footprint can never
//! fit the arena is refused immediately (never waited on).
//!
//! Arena discipline (why two sides are enough). Staged inputs of the job on
//! side S occupy the S end of the arena; the job's enqueue allocations grow
//! from there toward the other end, bounded by the inputs currently staged on
//! the other side. All enqueued work shares one exec stream, so two jobs'
//! working sets may reuse the same addresses in sequence. The only concurrent
//! writer is the h2d stream; before its first upload a stage makes the h2d
//! stream wait (on the device) for the most recently enqueued job's done event.
//! Because stage(k+1) precedes enqueue(k), that job is k-1 in steady state.
const std = @import("std");
const api = @import("api.zig");
const O = @import("ops.zig");
const Channel = @import("channel.zig");
const Slab = @import("slab.zig");

pub const Config = struct {
    device: u32,
    arena_words: usize,
    /// Pinned host words per pipeline slot (three slots: finishing, enqueued, staged).
    pinned_slot_words: usize,
    /// Scheduler-visible pipeline depth (mailbox + staged + enqueued + finishing ≤ this).
    max_outstanding: usize = 3,
};

pub const Sink = struct {
    ctx: *anyopaque,
    done: *const fn (*anyopaque, api.Completion) void,
};

/// Two-sided bump allocator over one device allocation (pure bookkeeping).
pub const Arena = struct {
    base: usize = 0,
    words: usize = 0,
    staged: [2]usize = .{ 0, 0 },
    work_side: api.Placement = .bottom,
    work_first: usize = 0, // inclusive lower bound of the work window
    work_end: usize = 0, // exclusive upper bound
    cursor: usize = 0, // bottom: grows up from work_first; top: grows down from work_end
    peak: usize = 0,

    fn side(p: api.Placement) usize {
        return @intFromEnum(p);
    }
    pub fn beginStage(self: *Arena, placement: api.Placement) void {
        self.staged[side(placement)] = 0;
    }
    /// Allocations are rounded to 64 words (256 bytes) so every kernel's
    /// vector/u64 alignment assumption holds for arena sub-ranges.
    pub const granule: usize = 64;
    pub fn stageAlloc(self: *Arena, placement: api.Placement, requested: usize) !usize {
        if (requested == 0) return error.InvalidAllocation;
        const words = std.mem.alignForward(usize, requested, granule);
        const s = side(placement);
        const used = self.staged[0] + self.staged[1];
        if (words > self.words - used) return error.StagedInputsExceedArena;
        self.staged[s] += words;
        return if (placement == .bottom) self.base + 4 * (self.staged[s] - words) else self.base + 4 * (self.words - self.staged[s]);
    }
    /// `other_staged`: whether a job is currently staged on the other side.
    pub fn beginWork(self: *Arena, placement: api.Placement, other_staged: bool) void {
        const other = side(placement.other());
        if (!other_staged) self.staged[other] = 0;
        self.work_side = placement;
        self.work_first = self.staged[0];
        self.work_end = self.words - self.staged[1];
        self.cursor = if (placement == .bottom) self.work_first else self.work_end;
        self.peak = self.staged[side(placement)];
    }
    pub fn workAlloc(self: *Arena, requested: usize) !usize {
        if (requested == 0) return error.InvalidAllocation;
        const words = std.mem.alignForward(usize, requested, granule);
        if (self.work_side == .bottom) {
            if (words > self.work_end - self.cursor) return error.JobWorkExceedsArena;
            const at = self.cursor;
            self.cursor += words;
            self.note();
            return self.base + 4 * at;
        }
        if (words > self.cursor - self.work_first) return error.JobWorkExceedsArena;
        self.cursor -= words;
        self.note();
        return self.base + 4 * self.cursor;
    }
    /// Stream-ordered LIFO free: only the most recent allocation is reclaimed
    /// (others are reclaimed when the job's window resets).
    pub fn workFree(self: *Arena, address: usize, requested: usize) void {
        const words = std.mem.alignForward(usize, requested, granule);
        if (address < self.base or (address - self.base) % 4 != 0) return;
        const at = (address - self.base) / 4;
        if (self.work_side == .bottom) {
            if (at + words == self.cursor and at >= self.work_first) self.cursor = at;
        } else if (at == self.cursor and at + words <= self.work_end) self.cursor = at + words;
    }
    fn note(self: *Arena) void {
        const used = if (self.work_side == .bottom) self.cursor - self.work_first else self.work_end - self.cursor;
        self.peak = @max(self.peak, used + self.staged[side(self.work_side)]);
    }
    pub fn contains(self: *const Arena, address: usize, words: usize) bool {
        return address >= self.base and (address - self.base) % 4 == 0 and (address - self.base) / 4 <= self.words and words <= self.words - (address - self.base) / 4;
    }
};

const Slot = struct {
    job: api.Job = undefined,
    sink: Sink = undefined,
    seq: u64 = 0,
    placement: api.Placement = .bottom,
    footprint: api.Footprint = .{ .device_words = 0 },
    receipt: api.Receipt = .{},
    // pinned slot bookkeeping
    pinned: []u32 = &.{},
    pinned_used: usize = 0,
    // events (owned by the worker for its lifetime)
    staged_event: ?*anyopaque = null,
    done_event: ?*anyopaque = null,
    uploads: bool = false,
    h2d_ordered: bool = false,
    waited_staged: bool = false,
    failed: ?anyerror = null,
    channel: Channel.DeviceChannel = undefined,
    slab: Slab.ProofSlab = undefined,
    slab_host: []u32 = &.{},
};

pub const Worker = struct {
    ops: *const O.Ops,
    config: Config,
    device_ordinal: u32,
    context: *anyopaque = undefined,
    exec_stream: *anyopaque = undefined,
    h2d_stream: *anyopaque = undefined,
    arena: Arena = .{},
    arena_buffer: ?[*]u32 = null,
    slots: [3]Slot = @splat(.{}),
    persistent_map: std.AutoHashMapUnmanaged([32]u8, api.DeviceBuffer) = .empty,
    a: std.mem.Allocator,
    // loop state (worker thread only)
    staging: ?*Slot = null,
    enqueuing: ?*Slot = null,
    last_enqueued: ?*Slot = null,
    next_seq: u64 = 0,
    // submission (any thread)
    thread: ?std.Thread = null,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    mailbox: ?Submission = null,
    closing: bool = false,
    started: bool = false,
    fatal: ?anyerror = null,
    outstanding: usize = 0,
    completed: u64 = 0,

    const Submission = struct { job: api.Job, sink: Sink };

    pub fn create(a: std.mem.Allocator, ops: *const O.Ops, config: Config) !*Worker {
        const self = try a.create(Worker);
        errdefer a.destroy(self);
        self.* = .{ .ops = ops, .config = config, .device_ordinal = config.device, .a = a };
        self.thread = try std.Thread.spawn(.{}, run, .{self});
        // Startup (context creation) runs on the worker thread; report its outcome.
        self.mutex.lock();
        while (!self.started) self.cond.wait(&self.mutex);
        const failed = self.fatal;
        self.mutex.unlock();
        if (failed) |err| {
            self.thread.?.join();
            return err;
        }
        return self;
    }

    pub fn handle(self: *Worker) *api.DeviceWorker {
        return api.DeviceWorker.of(self);
    }

    /// Drain every submitted job, then destroy device resources and join.
    pub fn destroy(self: *Worker) void {
        self.mutex.lock();
        self.closing = true;
        self.cond.broadcast();
        self.mutex.unlock();
        if (self.thread) |t| t.join();
        self.a.destroy(self);
    }

    /// True when the scheduler may submit another job to this worker.
    pub fn accepts(self: *Worker) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.fatal == null and !self.closing and self.mailbox == null and self.outstanding < self.config.max_outstanding;
    }
    pub fn load(self: *Worker) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.outstanding;
    }

    pub fn submit(self: *Worker, job: api.Job, sink: Sink) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.fatal) |err| return err;
        if (self.closing) return error.WorkerClosing;
        if (self.mailbox != null or self.outstanding >= self.config.max_outstanding) return error.WorkerBusy;
        self.mailbox = .{ .job = job, .sink = sink };
        self.outstanding += 1;
        self.cond.broadcast();
    }

    fn take(self: *Worker, block: bool) ?Submission {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (block and self.mailbox == null and !self.closing) self.cond.wait(&self.mutex);
        const out = self.mailbox;
        self.mailbox = null;
        if (out != null) self.cond.broadcast();
        return out;
    }

    fn run(self: *Worker) void {
        const ok = if (self.startup()) |_| true else |err| blk: {
            self.mutex.lock();
            self.fatal = err;
            self.mutex.unlock();
            break :blk false;
        };
        self.mutex.lock();
        self.started = true;
        self.cond.broadcast();
        self.mutex.unlock();
        if (!ok) return;
        var staged: ?*Slot = null;
        var running: ?*Slot = null;
        while (true) {
            const next = self.take(staged == null and running == null);
            if (next == null and staged == null and running == null) break;
            const newly: ?*Slot = if (next) |sub| self.stage(sub) else null;
            const enqueued: ?*Slot = if (staged) |s| self.enqueue(s, newly) else null;
            if (running) |r| self.complete(r);
            running = enqueued;
            staged = newly;
        }
        self.shutdown();
    }

    fn startup(self: *Worker) !void {
        const w = &self.ops.wait;
        var ctx: ?*anyopaque = null;
        const options = O.ContextOptions{ .device_ordinal = self.config.device };
        try O.check(w.context_create(&options, &ctx));
        self.context = ctx orelse return error.CudaContextFailed;
        errdefer _ = w.context_destroy(self.context);
        var exec: ?*anyopaque = null;
        try O.check(w.lane_stream(self.context, 0, &exec));
        self.exec_stream = exec orelse return error.CudaContextFailed;
        var h2d: ?*anyopaque = null;
        try O.check(w.stream_create(self.config.device, &h2d));
        self.h2d_stream = h2d orelse return error.CudaStreamFailed;
        if (self.config.arena_words == 0 or self.config.arena_words % Arena.granule != 0) return error.InvalidArena;
        var arena: ?[*]u32 = null;
        try O.check(self.ops.exec.alloc_u32(self.context, self.config.arena_words, &arena));
        self.arena_buffer = arena orelse return error.CudaArenaFailed;
        self.arena = .{ .base = @intFromPtr(arena.?), .words = self.config.arena_words };
        for (&self.slots) |*slot| {
            try O.check(w.event_create(&slot.staged_event));
            try O.check(w.event_create(&slot.done_event));
            var host: ?*anyopaque = null;
            try O.check(w.host_alloc(self.config.pinned_slot_words * 4, &host));
            slot.pinned = @as([*]u32, @ptrCast(@alignCast(host orelse return error.PinnedAllocationFailed)))[0..self.config.pinned_slot_words];
        }
    }

    fn shutdown(self: *Worker) void {
        const w = &self.ops.wait;
        for (&self.slots) |*slot| {
            if (slot.staged_event) |e| _ = w.event_destroy(e);
            if (slot.done_event) |e| _ = w.event_destroy(e);
            if (slot.pinned.len != 0) _ = w.host_free(slot.pinned.ptr);
        }
        var it = self.persistent_map.valueIterator();
        while (it.next()) |b| _ = self.ops.exec.free_u32(self.context, b.ptr);
        self.persistent_map.deinit(self.a);
        if (self.arena_buffer) |p| _ = self.ops.exec.free_u32(self.context, p);
        _ = w.stream_destroy(self.h2d_stream);
        _ = w.context_destroy(self.context);
    }

    // ---------------- phase 1 ----------------
    fn stage(self: *Worker, sub: Submission) ?*Slot {
        const seq = self.next_seq;
        self.next_seq += 1;
        const slot = &self.slots[seq % 3];
        const staged_event = slot.staged_event;
        const done_event = slot.done_event;
        const pinned = slot.pinned;
        slot.* = .{ .job = sub.job, .sink = sub.sink, .seq = seq, .placement = if (seq % 2 == 0) .bottom else .top, .pinned = pinned, .staged_event = staged_event, .done_event = done_event };
        slot.receipt = .{ .device = self.device_ordinal, .sequence = seq, .placement = slot.placement };
        var timer = std.time.Timer.start() catch unreachable;
        slot.footprint = sub.job.footprint();
        const fixed = Channel.state_words + slot.footprint.slab_words;
        if (slot.footprint.device_words > self.arena.words or fixed > self.arena.words - slot.footprint.device_words) return self.refuse(slot, error.JobFootprintExceedsArena);
        if (slot.footprint.pinned_words > pinned.len or slot.footprint.slab_words > pinned.len - slot.footprint.pinned_words) return self.refuse(slot, error.JobFootprintExceedsPinned);
        if (self.fatal) |err| return self.refuse(slot, err);
        self.arena.beginStage(slot.placement);
        var stager = api.Stager{ .worker = self.handle(), .placement = slot.placement };
        self.staging = slot;
        defer self.staging = null;
        sub.job.vtable.stage(sub.job.ctx, &stager) catch |err| return self.refuse(slot, err);
        if (slot.uploads) O.check(self.ops.exec.event_record(slot.staged_event.?, self.h2d_stream)) catch |err| return self.refuse(slot, err);
        slot.receipt.staged_words = self.arena.staged[@intFromEnum(slot.placement)];
        slot.receipt.stage_ns = timer.read();
        return slot;
    }

    fn refuse(self: *Worker, slot: *Slot, err: anyerror) ?*Slot {
        slot.job.vtable.abort(slot.job.ctx);
        self.report(slot, err);
        return null;
    }

    pub fn stageAlloc(self: *Worker, words: usize) !api.DeviceBuffer {
        const slot = self.staging orelse return error.StagerOutsidePhaseOne;
        const address = try self.arena.stageAlloc(slot.placement, words);
        return .{ .ptr = @ptrFromInt(address), .words = words };
    }

    pub fn stagePinned(self: *Worker, words: usize) ![]u32 {
        const slot = self.staging orelse return error.StagerOutsidePhaseOne;
        return self.pinnedAlloc(slot, words);
    }

    fn pinnedAlloc(_: *Worker, slot: *Slot, words: usize) ![]u32 {
        if (words > slot.pinned.len - slot.pinned_used) return error.JobFootprintExceedsPinned;
        const out = slot.pinned[slot.pinned_used..][0..words];
        slot.pinned_used += words;
        return out;
    }

    pub fn stageUpload(self: *Worker, dst: api.DeviceBuffer, src: []const u32) !void {
        const slot = self.staging orelse return error.StagerOutsidePhaseOne;
        if (src.len == 0) return;
        if (src.len > dst.words) return error.UploadExceedsDestination;
        if (!self.arena.contains(@intFromPtr(dst.ptr), src.len) and !self.isPersistent(dst, src.len)) return error.UploadOutsideJobMemory;
        const pinned_lo = @intFromPtr(slot.pinned.ptr);
        const pinned_hi = pinned_lo + slot.pinned.len * 4;
        const at = @intFromPtr(src.ptr);
        const source: []const u32 = if (at >= pinned_lo and at + src.len * 4 <= pinned_hi) src else blk: {
            const copy = try self.pinnedAlloc(slot, src.len);
            @memcpy(copy, src);
            break :blk copy;
        };
        if (!slot.h2d_ordered) {
            // The previous enqueued job may still use this side of the arena.
            if (self.last_enqueued) |prior| try O.check(self.ops.exec.stream_wait(self.h2d_stream, prior.done_event.?));
            slot.h2d_ordered = true;
        }
        try O.check(self.ops.exec.copy_async(dst.ptr, source.ptr, source.len * 4, @intFromEnum(O.CopyKind.h2d), self.h2d_stream));
        slot.uploads = true;
    }

    fn isPersistent(self: *Worker, dst: api.DeviceBuffer, words: usize) bool {
        var it = self.persistent_map.valueIterator();
        while (it.next()) |b| {
            const lo = @intFromPtr(b.ptr);
            const at = @intFromPtr(dst.ptr);
            if (at >= lo and at + words * 4 <= lo + b.words * 4) return true;
        }
        return false;
    }

    pub fn persistent(self: *Worker, key: [32]u8, words: usize) !api.Persistent {
        if (self.staging == null) return error.StagerOutsidePhaseOne;
        if (self.persistent_map.get(key)) |b| {
            if (b.words != words) return error.PersistentGeometryMismatch;
            return .{ .buffer = b, .fresh = false };
        }
        var ptr: ?[*]u32 = null;
        try O.check(self.ops.exec.alloc_u32_long(self.context, words, &ptr));
        const b = api.DeviceBuffer{ .ptr = ptr orelse return error.CudaAllocationFailed, .words = words };
        try self.persistent_map.put(self.a, key, b);
        return .{ .buffer = b, .fresh = true };
    }

    // ---------------- phase 2 ----------------
    fn enqueue(self: *Worker, slot: *Slot, next: ?*Slot) ?*Slot {
        var timer = std.time.Timer.start() catch unreachable;
        self.arena.beginWork(slot.placement, next != null and next.?.placement != slot.placement);
        self.enqueuing = slot;
        defer self.enqueuing = null;
        self.enqueueBody(slot) catch |err| {
            slot.failed = err;
        };
        // The done event is recorded even after a failure so later h2d waits
        // and this job's completion are well defined.
        O.check(self.ops.exec.event_record(slot.done_event.?, self.exec_stream)) catch |err| {
            self.markFatal(err);
            slot.failed = slot.failed orelse err;
        };
        self.last_enqueued = slot;
        slot.receipt.enqueue_ns = timer.read();
        slot.receipt.arena_peak_words = self.arena.peak;
        return slot;
    }

    fn enqueueBody(self: *Worker, slot: *Slot) !void {
        try self.enqueueWaitStaged();
        const state = try self.enqueueAlloc(Channel.state_words);
        slot.channel = Channel.DeviceChannel.init(self.handle(), &self.ops.exec, self.context, self.exec_stream, state, slot.seq);
        const slab_device: api.DeviceBuffer = if (slot.footprint.slab_words == 0) .{ .ptr = state.ptr, .words = 0 } else try self.enqueueAlloc(slot.footprint.slab_words);
        slot.slab_host = try self.pinnedAlloc(slot, slot.footprint.slab_words);
        slot.slab = .{ .device = slab_device };
        var e = api.Enqueue{ .worker = self.handle(), .placement = slot.placement, .channel = &slot.channel, .slab = &slot.slab };
        try slot.job.vtable.enqueue(slot.job.ctx, &e);
        if (slab_device.words != 0) {
            try O.check(self.ops.exec.copy_async(slot.slab_host.ptr, slab_device.ptr, slab_device.words * 4, @intFromEnum(O.CopyKind.d2h), self.exec_stream));
            slot.receipt.d2h_bytes = slab_device.words * 4;
        }
    }

    pub fn enqueueWaitStaged(self: *Worker) !void {
        const slot = self.enqueuing orelse return error.EnqueueOutsidePhaseTwo;
        if (slot.waited_staged) return;
        if (slot.uploads) try O.check(self.ops.exec.stream_wait(self.exec_stream, slot.staged_event.?));
        slot.waited_staged = true;
    }

    pub fn enqueueAlloc(self: *Worker, words: usize) !api.DeviceBuffer {
        if (self.enqueuing == null) return error.EnqueueOutsidePhaseTwo;
        const address = try self.arena.workAlloc(words);
        return .{ .ptr = @ptrFromInt(address), .words = words };
    }

    pub fn enqueueFree(self: *Worker, b: api.DeviceBuffer) void {
        if (self.enqueuing == null) return;
        self.arena.workFree(@intFromPtr(b.ptr), b.words);
    }

    pub fn enqueueHostFn(self: *Worker, f: api.HostFn) !void {
        if (self.enqueuing == null) return error.EnqueueOutsidePhaseTwo;
        try O.check(self.ops.exec.host_fn(self.exec_stream, f.call, f.user));
    }

    // ---------------- phase 3 ----------------
    fn complete(self: *Worker, slot: *Slot) void {
        var timer = std.time.Timer.start() catch unreachable;
        // lint:host-wait-begin — the single host wait of this job.
        const waited = self.ops.wait.event_sync(slot.done_event.?);
        // lint:host-wait-end
        slot.receipt.wait_ns = timer.read();
        slot.receipt.host_waits = 1;
        if (self.last_enqueued == slot) self.last_enqueued = null;
        if (waited != 0) {
            self.markFatal(error.CudaDeviceFault);
            slot.job.vtable.abort(slot.job.ctx);
            return self.report(slot, error.CudaDeviceFault);
        }
        if (slot.failed) |err| {
            slot.job.vtable.abort(slot.job.ctx);
            return self.report(slot, err);
        }
        const view = api.SlabView{ .words = slot.slab_host, .layout = slot.slab.layout, .receipt = slot.receipt };
        slot.job.vtable.finish(slot.job.ctx, view) catch |err| return self.report(slot, err);
        self.report(slot, {});
    }

    fn markFatal(self: *Worker, err: anyerror) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.fatal == null) self.fatal = err;
    }

    fn report(self: *Worker, slot: *Slot, result: anyerror!void) void {
        slot.sink.done(slot.sink.ctx, .{ .job = slot.job, .result = result, .receipt = slot.receipt });
        self.mutex.lock();
        self.outstanding -= 1;
        self.completed += 1;
        self.cond.broadcast();
        self.mutex.unlock();
    }
};

test {
    _ = @import("worker_test.zig");
}
