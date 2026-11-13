//! Worker-thread startup, pinned/arena lifetime, park/unpark and shutdown ownership.
const std = @import("std");
const api = @import("api.zig");
const O = @import("ops.zig");

const Worker = @import("worker.zig").Worker;
const Records = @import("worker_records.zig");
const Control = @typeInfo(@FieldType(Worker, "control")).optional.child;
const ExecutionOwner = @import("worker_execution_phase.zig");
const RetainedOwner = @import("worker_retained_phase.zig");

pub fn startup(self: *Worker) !void {
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
    if (self.config.arena_words == 0 or self.config.arena_words % Records.Arena.granule != 0) return error.InvalidArena;
    var arena: ?[*]u32 = null;
    try O.check(self.ops.exec.alloc_u32(self.context, self.config.arena_words, &arena));
    self.arena_buffer = arena orelse return error.CudaArenaFailed;
    self.arena = .{ .base = @intFromPtr(arena.?), .words = self.config.arena_words, .reuse = self.config.reuse_frees };
    if (self.config.persistent_budget_words != 0) {
        if (self.config.persistent_budget_words % Records.Arena.granule != 0) return error.InvalidPersistentBudget;
        var pool: ?[*]u32 = null;
        try O.check(self.ops.exec.alloc_u32_long(self.context, self.config.persistent_budget_words, &pool));
        self.regions_buffer = pool orelse return error.CudaAllocationFailed;
        self.regions.words = self.config.persistent_budget_words;
    }
    for (&self.slots) |*slot| {
        try O.check(w.event_create(&slot.staged_event));
        try O.check(w.event_create(&slot.done_event));
        if (!self.config.pinned_lazy) slot.pinned = try pinnedSlotAlloc(self, self.config.pinned_slot_words);
    }
    self.arena_epoch = 1;
}

pub fn pinnedSlotAlloc(self: *Worker, words: usize) ![]u32 {
    var host: ?*anyopaque = null;
    try O.check(self.ops.wait.host_alloc(words * 4, &host));
    self.pinned_allocated_bytes += words * 4;
    self.pinned_allocations += 1;
    return @as([*]u32, @ptrCast(@alignCast(host orelse return error.PinnedAllocationFailed)))[0..words];
}

pub fn ensurePinned(self: *Worker, slot: *Records.Slot, needed: usize) !void {
    if (!self.config.pinned_lazy or needed <= slot.pinned.len) return;
    if (needed > self.config.pinned_slot_words) return error.JobFootprintExceedsPinned;
    const words = @min(self.config.pinned_slot_words, pinnedGrowth(needed));
    if (slot.pinned.len != 0) try self.pinned_retired.ensureUnusedCapacity(self.a, 1);
    const grown = try pinnedSlotAlloc(self, words);
    if (slot.pinned.len != 0) self.pinned_retired.appendAssumeCapacity(slot.pinned);
    slot.pinned = grown;
}

pub fn pinnedGrowth(needed: usize) usize {
    return std.math.ceilPowerOfTwo(usize, @max(needed, Records.pinned_granule_words)) catch std.math.maxInt(usize);
}

pub fn freeRetiredPinned(self: *Worker) void {
    for (self.pinned_retired.items) |p| _ = self.ops.wait.host_free(p.ptr);
    self.pinned_retired.clearRetainingCapacity();
}

pub fn isClosing(self: *Worker) bool {
    self.mutex.lock();
    defer self.mutex.unlock();
    return self.closing;
}

pub fn takeControl(self: *Worker) ?Control {
    self.mutex.lock();
    defer self.mutex.unlock();
    const c = self.control;
    self.control = null;
    return c;
}

pub fn serviceControl(self: *Worker, c: Control) void {
    if (c == .call) {
        const result = c.call.call.run(c.call.call.ctx, self);
        self.mutex.lock();
        defer self.mutex.unlock();
        c.call.done.result = result;
        c.call.done.done = true;
        self.cond.broadcast();
        return;
    }
    var timer = std.time.Timer.start() catch unreachable;
    // The pipeline is empty here: retired pinned buffers can go.
    freeRetiredPinned(self);
    if (c == .park and c.park.release_retained) RetainedOwner.releaseAllRetained(self);
    RetainedOwner.drainRetained(self);
    var result: anyerror!Records.ParkReceipt = switch (c) {
        .park => |o| releaseArena(self, o),
        .unpark => |words| acquireArena(self, words),
        .call => unreachable, // handled above
    };
    if (result) |*r| {
        r.ns = timer.read();
        r.epoch = self.arena_epoch;
        r.retained_words = self.retainedWords(null);
    } else |_| {}
    self.mutex.lock();
    defer self.mutex.unlock();
    switch (c) {
        // Parked whenever the arena is gone, even if releasing the
        // persistent regions then failed: the worker must not accept
        // jobs it cannot stage, and unpark must be able to recover it.
        .park => if (self.arena_buffer == null) {
            self.parked = true;
            self.parks += 1;
        },
        .unpark => if (result) |_| {
            self.parked = false;
            self.unparks += 1;
        } else |_| {},
        .call => unreachable,
    }
    self.parking = false;
    self.unparking = false;
    self.control_result = result;
    self.control_done = true;
    self.cond.broadcast();
}

pub fn releaseArena(self: *Worker, o: Records.ParkOptions) !Records.ParkReceipt {
    var r = Records.ParkReceipt{ .arena_words = self.arena.words };
    // Every job completed (its done event was waited): nothing on the
    // device still reads the arena, so the free needs no further wait.
    if (self.arena_buffer) |p| try O.check(self.ops.exec.free_u32(self.context, p));
    self.arena_buffer = null;
    self.last_base = self.arena.base;
    self.last_words = self.arena.words;
    self.arena = .{ .reuse = self.config.reuse_frees };
    self.last_enqueued = null;
    if (o.release_persistent) r.persistent_words = try releasePersistent(self);
    return r;
}

pub fn persistentWords(self: *Worker) u64 {
    var words: u64 = if (self.regions_buffer != null) self.regions.words else 0;
    var it = self.persistent_map.valueIterator();
    while (it.next()) |buffer| words += buffer.words;
    return words;
}

pub fn releasePersistent(self: *Worker) !usize {
    var words: usize = 0;
    var first: ?anyerror = null;
    var it = self.persistent_map.valueIterator();
    while (it.next()) |b| {
        words += b.words;
        O.check(self.ops.exec.free_u32(self.context, b.ptr)) catch |err| {
            first = first orelse err;
        };
    }
    self.persistent_map.clearRetainingCapacity();
    for (self.retired.items) |b| O.check(self.ops.exec.free_u32(self.context, b.ptr)) catch |err| {
        first = first orelse err;
    };
    self.retired.clearRetainingCapacity();
    if (self.regions_buffer) |p| {
        words += self.regions.words;
        O.check(self.ops.exec.free_u32(self.context, p)) catch |err| {
            first = first orelse err;
        };
        self.regions_buffer = null;
    }
    self.regions.entries.clearRetainingCapacity();
    self.persistent_epoch += 1;
    if (first) |err| return err;
    return words;
}

pub fn acquireArena(self: *Worker, words_in: usize) !Records.ParkReceipt {
    // Never overwrite (leak) a live static arena.
    if (self.arena_buffer != null) return error.WorkerNotParked;
    const words = if (words_in == 0) self.last_words else words_in;
    if (words == 0 or words % Records.Arena.granule != 0) return error.InvalidArena;
    var arena: ?[*]u32 = null;
    try O.check(self.ops.exec.alloc_u32(self.context, words, &arena));
    self.arena_buffer = arena orelse return error.CudaArenaFailed;
    errdefer {
        _ = self.ops.exec.free_u32(self.context, self.arena_buffer.?);
        self.arena_buffer = null;
    }
    if (self.config.persistent_budget_words != 0 and self.regions_buffer == null) {
        var pool: ?[*]u32 = null;
        try O.check(self.ops.exec.alloc_u32_long(self.context, self.config.persistent_budget_words, &pool));
        self.regions_buffer = pool orelse return error.CudaAllocationFailed;
        self.regions.words = self.config.persistent_budget_words;
    }
    self.arena = .{ .base = @intFromPtr(arena.?), .words = words, .reuse = self.config.reuse_frees };
    self.config.arena_words = words;
    const same = self.arena.base == self.last_base and words == self.last_words;
    if (!same) self.arena_epoch = @max(self.arena_epoch, self.plan_phase_epochs[1]) + 1;
    return .{ .arena_words = words, .same_base = same };
}

pub fn requestControl(self: *Worker, c: Control) !Records.ParkReceipt {
    self.mutex.lock();
    defer self.mutex.unlock();
    // The control slot is single: never overwrite (lose) a posted call.
    while (self.control != null) self.cond.wait(&self.mutex);
    self.control = c;
    self.control_done = false;
    self.cond.broadcast();
    while (!self.control_done) self.cond.wait(&self.mutex);
    self.control_done = false;
    return self.control_result;
}

pub fn park(self: *Worker, o: Records.ParkOptions) !Records.ParkReceipt {
    {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.fatal) |err| return err;
        if (self.closing) return error.WorkerClosing;
        if (self.parked) return error.WorkerAlreadyParked;
        if (self.parking) return error.WorkerParked;
        if (self.unparking) return error.WorkerBusy;
        // The GPU-native plan block holds main_resident (driver views
        // into it) and fixes both phase windows: it is never parked.
        if (self.plan_phase_words[1] != 0) return error.WorkerPlanArenaInstalled;
        self.parking = true;
        while (self.outstanding != 0) self.cond.wait(&self.mutex);
    }
    const r = requestControl(self, .{ .park = o }) catch |err| {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.parking = false;
        return err;
    };
    return r;
}

pub fn unpark(self: *Worker, arena_words: usize) !Records.ParkReceipt {
    {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.fatal) |err| return err;
        if (!self.parked) return error.WorkerNotParked;
        // One control request at a time (the control slot is single).
        if (self.unparking or self.control != null) return error.WorkerBusy;
        self.unparking = true;
    }
    return requestControl(self, .{ .unpark = arena_words });
}

pub fn isParked(self: *Worker) bool {
    self.mutex.lock();
    defer self.mutex.unlock();
    return self.parked;
}

pub fn arenaEpoch(self: *Worker) u64 {
    self.mutex.lock();
    defer self.mutex.unlock();
    return self.arena_epoch;
}

pub fn persistentEpoch(self: *Worker) u64 {
    self.mutex.lock();
    defer self.mutex.unlock();
    return self.persistent_epoch;
}

pub fn arenaWords(self: *Worker) usize {
    self.mutex.lock();
    defer self.mutex.unlock();
    return if (self.parked) 0 else self.config.arena_words;
}

pub fn pinnedBytes(self: *Worker) usize {
    self.mutex.lock();
    defer self.mutex.unlock();
    var n: usize = 0;
    for (self.slots) |s| n += s.pinned.len * 4;
    return n;
}

pub fn shutdown(self: *Worker) void {
    const w = &self.ops.wait;
    for (&self.slots) |*slot| {
        if (slot.staged_event) |e| _ = w.event_destroy(e);
        if (slot.done_event) |e| _ = w.event_destroy(e);
        if (slot.pinned.len != 0) _ = w.host_free(slot.pinned.ptr);
    }
    ExecutionOwner.releaseBatches(self);
    self.timing_pool.deinit(self.a, self.ops.wait.event_destroy);
    freeRetiredPinned(self);
    self.pinned_retired.deinit(self.a);
    RetainedOwner.drainRetained(self);
    {
        // Regions the request protocol never released: free and count
        // them (no job is left, so none is pinned).
        var leaked: std.ArrayListUnmanaged(api.DeviceBuffer) = .empty;
        defer leaked.deinit(self.a);
        self.mutex.lock();
        for (self.retained.entries.items) |e| leaked.append(self.a, e.buffer) catch {};
        self.retained.stats.leaked_at_shutdown += leaked.items.len;
        self.mutex.unlock();
        RetainedOwner.freeRetained(self, leaked.items);
    }
    self.unbudgeted_regions = self.persistent_map.count();
    self.shut_down = true;
    var it = self.persistent_map.valueIterator();
    while (it.next()) |b| _ = self.ops.exec.free_u32(self.context, b.ptr);
    self.persistent_map.deinit(self.a);
    for (self.retired.items) |b| _ = self.ops.exec.free_u32(self.context, b.ptr);
    self.retired.deinit(self.a);
    if (self.regions_buffer) |p| _ = self.ops.exec.free_u32(self.context, p);
    if (self.arena_buffer) |p| _ = self.ops.exec.free_u32(self.context, p);
    _ = w.stream_destroy(self.h2d_stream);
    _ = w.context_destroy(self.context);
}
