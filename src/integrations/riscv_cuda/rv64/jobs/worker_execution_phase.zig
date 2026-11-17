//! Worker execution-phase ownership: posted calls, batches, enqueue ordering and completion.
const std = @import("std");
const api = @import("api.zig");
const O = @import("ops.zig");
const Channel = @import("channel.zig");
const MP = @import("plan.zig");
const JobTiming = @import("job_timing.zig");

const Worker = @import("worker.zig").Worker;
const Records = @import("worker_records.zig");
const ControlOwner = @import("worker_control_phase.zig");
const PlanningOwner = @import("worker_planning_phase.zig");
const RetainedOwner = @import("worker_retained_phase.zig");

pub fn leaveTail(self: *Worker, slot: *Records.Slot) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    if (slot.submit_index != std.math.maxInt(u64) and slot.submit_index + 1 == self.submitted) self.tail_live = false;
}

pub fn pinnedAlloc(_: *Worker, slot: *Records.Slot, words: usize) ![]u32 {
    if (words > slot.pinned.len - slot.pinned_used) return error.JobFootprintExceedsPinned;
    const out = slot.pinned[slot.pinned_used..][0..words];
    slot.pinned_used += words;
    return out;
}

pub fn enqueue(self: *Worker, slot: *Records.Slot, next: ?*Records.Slot) ?*Records.Slot {
    var timer = std.time.Timer.start() catch unreachable;
    self.arena.beginWork(slot.placement, next != null and next.?.placement != slot.placement);
    self.enqueuing = slot;
    defer self.enqueuing = null;
    if (self.fatal) |err| {
        slot.failed = err; // staged before a device fault: never enqueue it
    } else if (slot.failed != null) {
        // batch: a dependency failed host-side; never enqueue the body
    } else enqueueBody(self, slot) catch |err| {
        slot.failed = err;
    };
    // A skipped (or early-failed) body never made the exec stream wait
    // on its staged uploads: do it now, so this done event — and every
    // later quiesce/request wait on the exec stream — dominates every
    // copy the slot issued from the (parity-reused) pinned pool.
    if (slot.uploads and !slot.waited_staged) {
        O.check(self.ops.exec.stream_wait(self.exec_stream, slot.staged_event.?)) catch |err| {
            RetainedOwner.markFatal(self, err);
            slot.failed = slot.failed orelse err;
        };
        slot.waited_staged = true;
    }
    // The done event is recorded even after a failure so later h2d waits
    // and this job's completion are well defined.
    O.check(self.ops.exec.event_record(slot.done_event.?, self.exec_stream)) catch |err| {
        RetainedOwner.markFatal(self, err);
        slot.failed = slot.failed orelse err;
    };
    self.last_enqueued = slot;
    leaveTail(self, slot);
    slot.receipt.enqueue_ns = timer.read();
    slot.receipt.arena_peak_words = self.arena.peak;
    slot.live_peak = self.arena.live_peak;
    slot.peak_alloc = self.arena.peak_alloc;
    slot.peak_alloc_words = self.arena.peak_alloc_words;
    slot.allocs = self.arena.allocs;
    return slot;
}

pub fn enqueueBody(self: *Worker, slot: *Records.Slot) !void {
    try self.enqueueWaitStaged();
    // Batch dependencies: device-side waits on the producers' done events
    // (any GPU). Their records were issued before this enqueue (host latch).
    for (slot.batch_deps) |d| if (d.event) |ev| try O.check(self.ops.exec.stream_wait(self.exec_stream, ev));
    const state = try self.enqueueAlloc(Channel.state_words);
    slot.channel = Channel.DeviceChannel.init(self.handle(), &self.ops.exec, self.context, self.exec_stream, state, slot.seq);
    const slab_device: api.DeviceBuffer = if (slot.footprint.slab_words == 0) .{ .ptr = state.ptr, .words = 0 } else try self.enqueueAlloc(slot.footprint.slab_words);
    slot.slab_host = try pinnedAlloc(self, slot, slot.footprint.hostSlabWords());
    slot.receipt.readback = slot.footprint.readback;
    slot.slab = .{ .device = slab_device };
    var e = api.Enqueue{ .worker = self.handle(), .placement = slot.placement, .channel = &slot.channel, .slab = &slot.slab };
    try slot.job.vtable.enqueue(slot.job.ctx, &e);
    if (slot.footprint.readback == .job_slab and slab_device.words != 0) {
        try O.check(self.ops.exec.copy_async(slot.slab_host.ptr, slab_device.ptr, slab_device.words * 4, @intFromEnum(O.CopyKind.d2h), self.exec_stream));
        slot.receipt.d2h_bytes = slab_device.words * 4;
        slot.receipt.d2h_copies = 1;
    }
}

pub fn call(self: *Worker, c: Records.Call) !void {
    if (self.thread_id == std.Thread.getCurrentId()) return c.run(c.ctx, self);
    var done = Records.CallDone{};
    try self.post(c, &done);
    return self.awaitCall(&done);
}

pub fn post(self: *Worker, c: Records.Call, done: *Records.CallDone) !void {
    if (self.thread_id == std.Thread.getCurrentId()) return error.WorkerPostFromWorkerThread;
    done.* = .{};
    self.mutex.lock();
    defer self.mutex.unlock();
    if (self.fatal) |err| return err;
    if (self.closing) return error.WorkerClosing;
    while (self.control != null or self.unparking or self.parking) self.cond.wait(&self.mutex);
    self.control = .{ .call = .{ .call = c, .done = done } };
    self.cond.broadcast();
}

pub fn awaitCall(self: *Worker, done: *Records.CallDone) anyerror!void {
    self.mutex.lock();
    defer self.mutex.unlock();
    while (!done.done) self.cond.wait(&self.mutex);
    return done.result;
}

pub fn reserveTimingPairs(self: *Worker, count: usize, create_event: JobTiming.Create) !void {
    try onWorkerThread(self);
    try self.timing_pool.reserve(self.a, count, create_event, self.ops.wait.event_destroy);
}

pub fn stageTimingPair(self: *Worker, parity: u1, index: usize) !JobTiming.Pair {
    const slot = self.staging orelse return error.StagerOutsidePhaseOne;
    const active = slot.request_parity orelse return error.JobTimingOutsideRequestBatch;
    if (active != parity) return error.JobTimingParityMismatch;
    return self.timing_pool.get(parity, index);
}

pub fn reserveBatches(self: *Worker, max_jobs: usize, pinned_words: usize) !void {
    try onWorkerThread(self);
    for (0..2) |p| {
        if (self.batch_slots[p].len < max_jobs) {
            const grown = try self.a.alloc(Records.Slot, max_jobs);
            const old_count = self.batch_slots[p].len;
            var made: usize = old_count;
            errdefer {
                // The copied prefix still belongs to the old array until
                // commit. Include the current partially created pair.
                for (grown[old_count..made]) |*g| {
                    if (g.staged_event) |e| _ = self.ops.wait.event_destroy(e);
                    if (g.done_event) |e| _ = self.ops.wait.event_destroy(e);
                }
                self.a.free(grown);
            }
            for (grown, 0..) |*g, i| {
                g.* = .{};
                if (i < self.batch_slots[p].len) {
                    g.staged_event = self.batch_slots[p][i].staged_event;
                    g.done_event = self.batch_slots[p][i].done_event;
                } else {
                    made = i + 1;
                    try O.check(self.ops.wait.event_create(&g.staged_event));
                    try O.check(self.ops.wait.event_create(&g.done_event));
                }
            }
            self.a.free(self.batch_slots[p]);
            self.batch_slots[p] = grown;
        }
        if (self.batch_pinned[p].len < pinned_words) {
            const grown = try ControlOwner.pinnedSlotAlloc(self, pinned_words);
            if (self.batch_pinned[p].len != 0) _ = self.ops.wait.host_free(self.batch_pinned[p].ptr);
            self.batch_pinned[p] = grown;
        }
    }
}

pub fn releaseBatches(self: *Worker) void {
    for (0..2) |p| {
        for (self.batch_slots[p]) |*g| {
            if (g.staged_event) |e| _ = self.ops.wait.event_destroy(e);
            if (g.done_event) |e| _ = self.ops.wait.event_destroy(e);
        }
        self.a.free(self.batch_slots[p]);
        self.batch_slots[p] = &.{};
        if (self.batch_pinned[p].len != 0) _ = self.ops.wait.host_free(self.batch_pinned[p].ptr);
        self.batch_pinned[p] = &.{};
    }
}

pub fn installPlanArena(self: *Worker, phase_a_words: usize, phase_b_words: usize) !api.DeviceBuffer {
    try onWorkerThread(self);
    if (phase_a_words == 0 or phase_a_words % Records.Arena.granule != 0 or phase_b_words < phase_a_words or phase_b_words % Records.Arena.granule != 0) return error.InvalidArena;
    if (self.arena_buffer) |p| try O.check(self.ops.exec.free_u32(self.context, p));
    self.arena_buffer = null;
    var block: ?[*]u32 = null;
    try O.check(self.ops.exec.alloc_u32_long(self.context, phase_b_words, &block));
    self.arena_buffer = block orelse return error.CudaArenaFailed;
    self.arena = .{ .base = @intFromPtr(block.?), .words = phase_a_words, .reuse = self.config.reuse_frees };
    self.config.arena_words = phase_b_words;
    self.plan_phase_words = .{ phase_a_words, phase_b_words };
    self.plan_phase_b = false;
    self.last_enqueued = null;
    self.mutex.lock();
    self.plan_phase_epochs = .{ self.arena_epoch + 1, self.arena_epoch + 2 };
    self.arena_epoch = self.plan_phase_epochs[0];
    self.mutex.unlock();
    return .{ .ptr = block.? + phase_a_words, .words = phase_b_words - phase_a_words };
}

pub fn uninstallPlanArena(self: *Worker) !void {
    try onWorkerThread(self);
    if (self.plan_phase_words[1] == 0) return;
    const words = self.plan_phase_words[0];
    if (self.arena_buffer) |p| {
        self.arena_buffer = null;
        try O.check(self.ops.exec.free_u32(self.context, p));
    }
    self.last_base = self.arena.base;
    self.last_words = words;
    self.arena = .{ .reuse = self.config.reuse_frees };
    self.last_enqueued = null;
    self.mutex.lock();
    defer self.mutex.unlock();
    self.plan_phase_words = .{ 0, 0 };
    self.plan_phase_b = false;
    self.arena_epoch = @max(self.arena_epoch, self.plan_phase_epochs[1]) + 1;
    self.parked = true;
}

pub fn setPhase(self: *Worker, b: bool) void {
    if (self.plan_phase_words[1] == 0 or self.plan_phase_b == b) return;
    self.arena = .{ .base = self.arena.base, .words = self.plan_phase_words[@intFromBool(b)], .reuse = self.config.reuse_frees };
    self.plan_phase_b = b;
    self.mutex.lock();
    self.arena_epoch = self.plan_phase_epochs[@intFromBool(b)];
    self.mutex.unlock();
}

pub fn planPhaseEpochs(self: *Worker) [2]u64 {
    self.mutex.lock();
    defer self.mutex.unlock();
    return self.plan_phase_epochs;
}

pub fn onWorkerThread(self: *Worker) !void {
    if (self.thread_id != std.Thread.getCurrentId()) return error.NotOnWorkerThread;
}

pub fn execStream(self: *Worker) *anyopaque {
    return self.exec_stream;
}

pub fn runBatch(self: *Worker, b: *Records.Batch) void {
    var timer = std.time.Timer.start() catch unreachable;
    defer b.enqueue_ns = timer.read();
    onWorkerThread(self) catch |err| return failBatch(b, err, 0);
    // Validate the complete batch before staging or waiting on any gate.
    for (b.jobs) |bj| bj.job.footprint().validateSizes() catch |err| return failBatch(b, err, 0);
    self.warm_persistent_only = b.require_warm_persistent;
    defer self.warm_persistent_only = false;
    const slots = self.batch_slots[b.parity];
    if (b.jobs.len > slots.len) return failBatch(b, error.BatchExceedsReservedSlots, 0);
    b.pinned_used = 0;
    b.memory_serializations = 0;
    b.slots = slots[0..b.jobs.len];
    setPhase(self, false);
    if (b.preamble) |h| h.run(h.ctx, self) catch |err| return failBatch(b, err, 0);
    var staged: ?*Records.Slot = null;
    for (b.jobs, 0..) |*bj, i| {
        if (bj.phase_b and !self.plan_phase_b) {
            // Phase change: the new window must not be pre-staged into
            // the old one; enqueue the staged job alone first.
            if (staged) |s| batchEnqueue(self, b, s, null);
            staged = null;
            setPhase(self, true);
        }
        // A gated job (capture) is staged only after its gates latched
        // (its stage may read the sealed segment). Enqueue the staged
        // job first so it does not wait behind a later segment's capture.
        if (!gatesLatched(bj)) {
            if (staged) |s| batchEnqueue(self, b, s, null);
            staged = null;
        }
        if (staged) |s| {
            const next = PlanningOwner.resolveFootprint(self, bj.job, bj.job.footprint());
            if (!MP.pairFits(self.arena.words, s.resolved.peak_words, next.staged_words)) {
                // The ordinary mailbox pipeline applies this same test.
                // A batch must also enqueue the current job before staging
                // a neighbour whose inputs would shrink its work window.
                // The next upload is ordered by the done event on-device;
                // this introduces no host/device join.
                batchEnqueue(self, b, s, null);
                staged = null;
                b.memory_serializations += 1;
            }
        }
        const slot = batchStage(self, b, i);
        if (staged) |s| batchEnqueue(self, b, s, slot);
        staged = slot;
    }
    if (staged) |s| batchEnqueue(self, b, s, null);
    if (b.tail) |h| h.run(h.ctx, self) catch |err| {
        std.debug.print("GPU_M8_GN_BATCH_FAILED device={d} phase=tail error={s}\n", .{ self.device_ordinal, @errorName(err) });
        b.result = err;
    };
    b.slots_used = b.jobs.len;
}

pub fn gatesLatched(bj: *const Records.BatchJob) bool {
    for (bj.gates) |g| if (!g.recorded.isSet()) return false;
    return true;
}

pub fn notifyFailed(bj: *Records.BatchJob) void {
    if (bj.on_fail) |f| {
        bj.on_fail = null;
        f.call(f.user);
    }
}

pub fn failBatch(b: *Records.Batch, err: anyerror, first: usize) void {
    std.debug.print("GPU_M8_GN_BATCH_FAILED first={d} jobs={d} error={s}\n", .{ first, b.jobs.len, @errorName(err) });
    b.result = err;
    for (b.jobs[first..]) |*bj| {
        notifyFailed(bj);
        bj.job.vtable.abort(bj.job.ctx);
        bj.result = err;
        // Poison dependents (any GPU): a consumer must never enqueue its
        // body without its producer's done event.
        bj.done.signal(null, true);
    }
    b.slots = &.{};
}

pub fn batchStage(self: *Worker, b: *Records.Batch, i: usize) ?*Records.Slot {
    const bj = &b.jobs[i];
    const slot = &b.slots[i];
    const seq = self.next_seq;
    self.next_seq += 1;
    const declared_fp = bj.job.footprint();
    const resolved = PlanningOwner.resolveFootprint(self, bj.job, declared_fp);
    const need = resolved.footprint.pinnedWords() catch std.math.maxInt(usize);
    const pool = self.batch_pinned[b.parity];
    const pinned: []u32 = if (need <= pool.len - b.pinned_used) pool[b.pinned_used..][0..need] else &.{};
    const staged_event = slot.staged_event;
    const done_event = slot.done_event;
    slot.* = .{ .job = bj.job, .seq = seq, .request_parity = b.parity, .placement = if (seq % 2 == 0) .bottom else .top, .pinned = pinned, .staged_event = staged_event, .done_event = done_event, .resolved = resolved, .declared = declared_fp, .submit_index = std.math.maxInt(u64), .batch_deps = bj.deps };
    slot.receipt = .{ .device = self.device_ordinal, .sequence = seq, .placement = slot.placement };
    slot.footprint = resolved.footprint;
    var timer = std.time.Timer.start() catch unreachable;
    const refused: ?anyerror = blk: {
        resolved.footprint.validate() catch |err| break :blk err;
        // Host gates first (capture seal): stage may read the segment.
        var gate_timer = std.time.Timer.start() catch unreachable;
        for (bj.gates) |g| g.recorded.wait();
        b.gate_wait_ns += gate_timer.read();
        for (bj.gates) |g| if (g.failed.load(.acquire)) break :blk error.BatchDependencyFailed;
        if (need > 0 and pinned.len == 0) break :blk error.JobFootprintExceedsBatchPinned;
        if (!resolved.planned) if (self.policy) |p| if (p.unplanned() == .refuse) break :blk error.JobClassNotInMemoryPolicy;
        const fixed = Channel.state_words + slot.footprint.slab_words;
        if (slot.footprint.device_words > self.arena.words or fixed > self.arena.words - slot.footprint.device_words) break :blk error.JobFootprintExceedsArena;
        if (self.fatal) |err| break :blk err;
        if (self.arena_buffer == null) break :blk error.WorkerParked;
        self.arena.beginStage(slot.placement);
        var stager = api.Stager{ .worker = self.handle(), .placement = slot.placement };
        self.staging = slot;
        defer self.staging = null;
        bj.job.vtable.stage(bj.job.ctx, &stager) catch |err| break :blk err;
        if (slot.uploads) O.check(self.ops.exec.event_record(slot.staged_event.?, self.h2d_stream)) catch |err| break :blk err;
        break :blk null;
    };
    b.pinned_used += pinned.len;
    if (refused) |err| {
        if (err != error.BatchDependencyFailed) std.debug.print("GPU_M8_GN_JOB_FAILED device={d} job={d} phase=stage error={s}\n", .{ self.device_ordinal, i, @errorName(err) });
        // Uploads the stage already issued (h2d, from the parity's pinned
        // pool) must be dominated by the exec stream: no done event of
        // this slot exists, so order them before every later job here.
        if (slot.uploads) {
            const ordered: anyerror!void = blk: {
                O.check(self.ops.exec.event_record(slot.staged_event.?, self.h2d_stream)) catch |e| break :blk e;
                O.check(self.ops.exec.stream_wait(self.exec_stream, slot.staged_event.?)) catch |e| break :blk e;
                break :blk {};
            };
            ordered catch |e| RetainedOwner.markFatal(self, e);
        }
        notifyFailed(bj);
        bj.job.vtable.abort(bj.job.ctx);
        RetainedOwner.settle(self, slot, err);
        bj.result = err;
        bj.settled = true;
        // Refused before enqueue: no done event exists for dependents to
        // wait on, so they must fail (BatchDependencyFailed), not run.
        bj.done.signal(null, true);
        return null;
    }
    slot.receipt.staged_words = self.arena.staged[@intFromEnum(slot.placement)];
    slot.receipt.stage_ns = timer.read();
    return slot;
}

pub fn batchEnqueue(self: *Worker, b: *Records.Batch, slot: *Records.Slot, next: ?*Records.Slot) void {
    const i = (@intFromPtr(slot) - @intFromPtr(b.slots.ptr)) / @sizeOf(Records.Slot);
    const bj = &b.jobs[i];
    // Host latches only (capture release, producers' records issued on
    // any worker thread). No device wait: the device-side order is the
    // stream_wait on each producer's done event inside enqueueBody.
    var gate_timer = std.time.Timer.start() catch unreachable;
    for (bj.deps) |d| {
        d.recorded.wait();
        if (d.failed.load(.acquire)) slot.failed = slot.failed orelse error.BatchDependencyFailed;
    }
    b.gate_wait_ns += gate_timer.read();
    _ = enqueue(self, slot, next);
    if (slot.failed) |err| {
        if (err != error.BatchDependencyFailed) std.debug.print("GPU_M8_GN_JOB_FAILED device={d} job={d} phase=enqueue error={s} arena_words={d} declared_peak_words={d} staged_words={any} high_words={d}\n", .{ self.device_ordinal, i, @errorName(err), self.arena.words, slot.resolved.peak_words, self.arena.staged, self.arena.peak });
    }
    // `after` (capture ring release) runs whatever the body's outcome,
    // after this slot's done record, as long as every gate succeeded (a
    // failed gate means the capture may still own its buffers; the
    // stream's detach returns them once the capture ended). A failed
    // Stage1 that never released its buffers wedged the capture ring.
    if (bj.after) |f| if (gatesSucceeded(bj)) enqueueHostFnRaw(self, slot, f) catch |err| {
        RetainedOwner.markFatal(self, err);
        slot.failed = slot.failed orelse err;
    };
    if (slot.failed != null) notifyFailed(bj);
    bj.done.signal(slot.done_event, slot.failed != null);
}

pub fn gatesSucceeded(bj: *const Records.BatchJob) bool {
    for (bj.gates) |g| if (!g.recorded.isSet() or g.failed.load(.acquire)) return false;
    return true;
}

pub fn enqueueHostFnRaw(self: *Worker, slot: *Records.Slot, f: api.HostFn) !void {
    try O.check(self.ops.exec.host_fn(self.exec_stream, f.call, f.user));
    slot.receipt.host_callbacks += 1;
    if (f.purpose == .capture_release) slot.receipt.capture_release_callbacks += 1;
}

pub fn requestWait(self: *Worker, event: *anyopaque) !u64 {
    var timer = std.time.Timer.start() catch unreachable;
    // lint:host-wait-begin — the ONE host wait of a GPU-native request.
    const waited = self.ops.wait.event_sync(event);
    // lint:host-wait-end
    if (waited != 0) {
        RetainedOwner.markFatal(self, error.CudaDeviceFault);
        return error.CudaDeviceFault;
    }
    return timer.read();
}
