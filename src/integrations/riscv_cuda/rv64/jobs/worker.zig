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
const MP = @import("plan.zig");
const Retained = @import("retained.zig");
const JobTiming = @import("job_timing.zig");

const Records = @import("worker_records.zig");
pub const Config = Records.Config;
pub const pinned_granule_words = Records.pinned_granule_words;
pub const ParkReceipt = Records.ParkReceipt;
pub const ParkOptions = Records.ParkOptions;
pub const ClassStat = Records.ClassStat;
pub const SideStat = Records.SideStat;
pub const Sink = Records.Sink;
pub const Arena = Records.Arena;
const Slot = Records.Slot;
pub const Call = Records.Call;
pub const CallDone = Records.CallDone;
pub const BatchDep = Records.BatchDep;
pub const BatchJob = Records.BatchJob;
pub const BatchHook = Records.BatchHook;
pub const Batch = Records.Batch;
pub const Regions = @import("worker_regions.zig").Regions;

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
    /// Buffers of failed fills: possibly still targeted by in-flight copies, freed at shutdown.
    retired: std.ArrayListUnmanaged(api.DeviceBuffer) = .empty,
    /// Pinned slot buffers replaced by lazy growth, freed when the pipeline is
    /// idle (park/unpark service, shutdown) instead of inside `stage`.
    pinned_retired: std.ArrayListUnmanaged([]u32) = .empty,
    a: std.mem.Allocator,
    // loop state (worker thread only)
    staging: ?*Slot = null,
    enqueuing: ?*Slot = null,
    warm_persistent_only: bool = false,
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
    /// Guarded by `mutex` (written on the worker thread, read by `classStats`).
    classes: std.AutoHashMapUnmanaged([32]u8, ClassStat) = .empty,
    /// Memory policy in force (null = today's behavior); `owned_plan` if loaded from env.
    policy: ?*const MP.Policy = null,
    owned_plan: ?*MP.Policy = null,
    regions: Regions = .{},
    regions_buffer: ?[*]u32 = null,
    // tail tracking for `fits` (under `mutex`): the last submitted job until it is enqueued
    submitted: u64 = 0,
    tail_peak: usize = 0,
    tail_live: bool = false,
    /// Worker thread: the next stage follows a serialized (pair-does-not-fit) enqueue.
    serialize_next: bool = false,
    /// Per-key persistent allocations made without a budget (counted before shutdown frees them).
    unbudgeted_regions: usize = 0,
    shut_down: bool = false,
    last_base: usize = 0,
    last_words: usize = 0,
    // park / unpark (spec §3.2 persistent service; M8-INTERFACES runtime-persist)
    /// Under `mutex`: the arena is released; `submit` refuses with WorkerParked.
    parked: bool = false,
    /// Under `mutex`: a park is draining the pipeline; `submit` refuses.
    parking: bool = false,
    /// Under `mutex`: an unpark request is in flight (one control at a time).
    unparking: bool = false,
    control: ?Control = null,
    control_done: bool = false,
    control_result: anyerror!ParkReceipt = .{},
    // ---- GPU-native request batches (rv64-m8-gpu-native.md §3.7-§3.8) ----
    /// Per-parity slot pools (events created at install by `reserveBatches`).
    batch_slots: [2][]Slot = .{ &.{}, &.{} },
    /// Per-parity request-lifetime pinned pools (bump-allocated per batch).
    batch_pinned: [2][]u32 = .{ &.{}, &.{} },
    /// Install-reserved diagnostic events, owned through worker shutdown.
    timing_pool: JobTiming.Pool = .{},
    /// Two-phase plan arena (`installPlanArena`): phase A excludes the
    /// main_resident region above it; phase B grows over it.
    plan_phase_words: [2]usize = .{ 0, 0 },
    plan_phase_b: bool = false,
    /// Stable arena identity per plan phase (A, B): the phase flip happens
    /// twice per request, and both (base, words) pairs are fixed after
    /// install, so a graph cache keyed on `arenaEpoch` stays warm across
    /// requests instead of missing on every flip.
    plan_phase_epochs: [2]u64 = .{ 0, 0 },
    /// Advances whenever the arena's (base, words) differ from the previous
    /// arena's: device addresses baked into captured graphs are stale.
    arena_epoch: u64 = 0,
    /// Advances when persistent regions are released (their contents are gone).
    persistent_epoch: u64 = 0,
    parks: u64 = 0,
    unparks: u64 = 0,
    /// Pinned host bytes allocated over the worker's life (lazy growth included).
    pinned_allocated_bytes: u64 = 0,
    pinned_allocations: u64 = 0,
    /// Request-scoped retained regions (retained.zig). Guarded by `mutex`;
    /// allocated and freed on the worker thread only (exec-context ledger).
    retained: Retained.Table = .{},
    /// Released regions with no pins, waiting for the worker thread's free.
    retained_pending: std.ArrayListUnmanaged(api.DeviceBuffer) = .empty,
    /// The worker thread's id (set first thing in `run`).
    thread_id: std.Thread.Id = 0,
    /// Set under `mutex` once the worker thread finished `shutdown`.
    stopped: bool = false,

    const Submission = struct { job: api.Job, sink: Sink, index: u64, declared: api.Footprint, resolved: MP.Resolved };
    const Control = union(enum) { park: ParkOptions, unpark: usize, call: Posted };
    /// A call and the completion owned by its caller's frame: concurrent
    /// callers never consume each other's completion (one shared done flag
    /// let caller B return A's result and pop its Call while B's was queued).
    const Posted = struct { call: Call, done: *CallDone };

    pub fn create(a: std.mem.Allocator, ops: *const O.Ops, config_in: Config) !*Worker {
        var config = config_in;
        const owned: ?*MP.Policy = if (config.plan == null and config.plan_from_env) try MP.Policy.fromEnv(a) else null;
        errdefer if (owned) |p| p.deinit();
        const policy: ?*const MP.Policy = config.plan orelse owned;
        if (policy) |p| {
            // The policy's arena replaces the configured default; an explicit
            // STWO_RV64_M8_JOBS_ARENA_BYTES (operator override) still wins.
            if (std.posix.getenv("STWO_RV64_M8_JOBS_ARENA_BYTES") == null) config.arena_words = @intCast(p.gpu.arena_words);
            if (config.persistent_budget_words == 0) config.persistent_budget_words = @intCast(p.gpu.persistent_budget_words);
            if (config.retained_budget_words == 0) config.retained_budget_words = @intCast(p.gpu.retained_budget_words);
            // Pinned slots only grow (a harness may need more than any swept class);
            // an explicit STWO_RV64_M8_JOBS_PINNED_BYTES still wins.
            if (std.posix.getenv("STWO_RV64_M8_JOBS_PINNED_BYTES") == null) config.pinned_slot_words = @max(config.pinned_slot_words, @as(usize, @intCast(p.gpu.pinned_slot_words)));
            config.reuse_frees = config.reuse_frees or p.gpu.allocator == .reuse;
            config.max_outstanding = @min(config.max_outstanding, p.gpu.max_outstanding);
        }
        const self = try a.create(Worker);
        errdefer a.destroy(self);
        self.* = .{ .ops = ops, .config = config, .device_ordinal = config.device, .a = a, .policy = policy, .owned_plan = owned };
        self.retained.budget_words = config.retained_budget_words;
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
        if (std.posix.getenv(MP.env_plan_dir)) |dir| self.writePlanDir(dir) catch |err| std.log.err("M8 worker class plan output failed: {s}", .{@errorName(err)});
        self.classes.deinit(self.a);
        self.regions.deinit(self.a);
        self.retained.deinit(self.a);
        self.retained_pending.deinit(self.a);
        if (self.owned_plan) |p| p.deinit();
        self.a.destroy(self);
    }

    /// The memory policy this worker plans with (null = none).
    pub const plan = @import("worker_planning_phase.zig").plan;

    const resolveFootprint = @import("worker_planning_phase.zig").resolveFootprint;

    /// Placement by footprint (scheduler): true when `job`'s staged inputs fit
    /// beside the job this worker would stage it next to (the last submitted
    /// job, until it is enqueued). Always true without a policy. A job that does
    /// not fit is still correct on this worker (it serializes), just not overlapped.
    pub const fits = @import("worker_planning_phase.zig").fits;

    /// Measured class plans + allocator state (STWO_RV64_M8_JOBS_PLAN_DIR).
    pub const writePlanDir = @import("worker_planning_phase.zig").writePlanDir;

    /// True when the scheduler may submit another job to this worker.
    pub const accepts = @import("worker_planning_phase.zig").accepts;
    /// Snapshot of the measured class plans (caller frees with `a`).
    pub const ClassEntry = struct { key: [32]u8, stat: ClassStat };
    pub const classStats = @import("worker_planning_phase.zig").classStats;
    pub const load = @import("worker_planning_phase.zig").load;

    pub fn submit(self: *Worker, job: api.Job, sink: Sink) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.fatal) |err| return err;
        if (self.closing) return error.WorkerClosing;
        if (self.parked or self.parking) return error.WorkerParked;
        if (self.mailbox != null or self.outstanding >= self.config.max_outstanding) return error.WorkerBusy;
        const declared_fp = job.footprint();
        try declared_fp.validateSizes();
        const r = self.resolveFootprint(job, declared_fp);
        try r.footprint.validate();
        self.mailbox = .{ .job = job, .sink = sink, .index = self.submitted, .declared = declared_fp, .resolved = r };
        self.submitted += 1;
        self.tail_peak = r.peak_words;
        self.tail_live = true;
        self.outstanding += 1;
        self.cond.broadcast();
    }

    fn take(self: *Worker, block: bool) ?Submission {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (block and self.mailbox == null and !self.closing and self.control == null and self.retained_pending.items.len == 0) self.cond.wait(&self.mutex);
        const out = self.mailbox;
        self.mailbox = null;
        if (out != null) self.cond.broadcast();
        return out;
    }

    fn run(self: *Worker) void {
        self.thread_id = std.Thread.getCurrentId();
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
            // Released retained regions are freed here, on the worker thread.
            self.drainRetained();
            const idle = staged == null and running == null;
            // Park/unpark run only with an empty pipeline (park drains first).
            if (idle) if (self.takeControl()) |c| {
                self.serviceControl(c);
                continue;
            };
            const next = self.take(idle);
            if (next == null and idle) {
                if (self.isClosing()) break;
                continue; // woken for a control request
            }
            if (next) |sub| if (staged) |s| if (!self.pairFits(s, sub)) {
                // Memory plan: the staged job does not fit beside this job's
                // inputs. Enqueue it alone first; `sub` then stages behind it
                // (its uploads wait on the device for it), never failing either.
                const alone = self.enqueue(s, null);
                if (running) |r| self.complete(r);
                running = alone;
                staged = null;
                self.serialize_next = true;
            };
            const newly: ?*Slot = if (next) |sub| self.stage(sub) else null;
            const enqueued: ?*Slot = if (staged) |s| self.enqueue(s, newly) else null;
            if (running) |r| self.complete(r);
            running = enqueued;
            staged = newly;
        }
        self.shutdown();
        self.mutex.lock();
        self.stopped = true;
        self.cond.broadcast();
        self.mutex.unlock();
    }

    fn pairFits(self: *Worker, staged: *Slot, next: Submission) bool {
        if (self.policy == null) return true;
        return MP.pairFits(self.arena.words, staged.resolved.peak_words, next.resolved.staged_words);
    }

    const startup = @import("worker_control_phase.zig").startup;

    /// Lazy pinned slots: grow `slot` to hold `needed` words. Legal here: the
    /// slot's previous job completed (its event was waited) before this stage.
    const ensurePinned = @import("worker_control_phase.zig").ensurePinned;

    /// Lazy slot size for `needed` words: a power of two, at least one granule.
    pub const pinnedGrowth = @import("worker_control_phase.zig").pinnedGrowth;

    /// Pipeline idle only (no job reads the retired buffers any more).

    // ---------------- park / unpark ----------------

    const isClosing = @import("worker_control_phase.zig").isClosing;

    const takeControl = @import("worker_control_phase.zig").takeControl;

    const serviceControl = @import("worker_control_phase.zig").serviceControl;

    /// Best effort: every buffer is freed once and dropped from its container
    /// whatever the outcome (a failed free is never retried, so shutdown
    /// cannot free it twice); the first failure is reported.
    /// Worker thread, or quiesced install: exact live allocation words.
    /// Unlike class declarations this counts shared keys only once.
    pub const persistentWords = @import("worker_control_phase.zig").persistentWords;

    /// Release the static arena (back to the process-wide device arena, so
    /// the legacy owner may use it) and keep everything else: context,
    /// streams, events, pinned slots, class stats, persistent regions (unless
    /// `o.release_persistent`). Waits until every submitted job completed;
    /// `submit` refuses (error.WorkerParked) from the call on. Any thread.
    pub const park = @import("worker_control_phase.zig").park;

    /// Re-acquire a static arena of `arena_words` (0 = the size before the
    /// park). `same_base` / `arenaEpoch` tell graph caches whether device
    /// addresses they captured are still valid. Any thread.
    pub const unpark = @import("worker_control_phase.zig").unpark;

    pub const isParked = @import("worker_control_phase.zig").isParked;

    /// Identity of the current arena's (base, words); a graph cache that
    /// captured device addresses keys or flushes on it.
    pub const arenaEpoch = @import("worker_control_phase.zig").arenaEpoch;

    /// Advances when persistent regions were released by a park.
    pub const persistentEpoch = @import("worker_control_phase.zig").persistentEpoch;

    /// Current static arena size in words (0 while parked).
    pub const arenaWords = @import("worker_control_phase.zig").arenaWords;

    /// Pinned host bytes currently held by the three slots.
    pub const pinnedBytes = @import("worker_control_phase.zig").pinnedBytes;

    const shutdown = @import("worker_control_phase.zig").shutdown;

    // ---------------- phase 1 ----------------
    fn stage(self: *Worker, sub: Submission) ?*Slot {
        const seq = self.next_seq;
        self.next_seq += 1;
        const slot = &self.slots[seq % 3];
        const staged_event = slot.staged_event;
        const done_event = slot.done_event;
        const grow = self.ensurePinned(slot, sub.resolved.footprint.pinnedWords() catch std.math.maxInt(usize));
        const pinned = slot.pinned;
        slot.* = .{ .job = sub.job, .sink = sub.sink, .seq = seq, .placement = if (seq % 2 == 0) .bottom else .top, .pinned = pinned, .staged_event = staged_event, .done_event = done_event, .resolved = sub.resolved, .declared = sub.declared, .submit_index = sub.index, .serialized = self.serialize_next };
        self.serialize_next = false;
        slot.receipt = .{ .device = self.device_ordinal, .sequence = seq, .placement = slot.placement };
        var timer = std.time.Timer.start() catch unreachable;
        slot.footprint = sub.resolved.footprint;
        if (!sub.resolved.planned) if (self.policy) |p| if (p.unplanned() == .refuse) return self.refuse(slot, error.JobClassNotInMemoryPolicy);
        const fixed = Channel.state_words + slot.footprint.slab_words;
        if (slot.footprint.device_words > self.arena.words or fixed > self.arena.words - slot.footprint.device_words) return self.refuse(slot, error.JobFootprintExceedsArena);
        if (slot.footprint.pinned_words > pinned.len or slot.footprint.hostSlabWords() > pinned.len - slot.footprint.pinned_words) return self.refuse(slot, error.JobFootprintExceedsPinned);
        if (self.fatal) |err| return self.refuse(slot, err);
        grow catch |err| return self.refuse(slot, err);
        if (self.arena_buffer == null) return self.refuse(slot, error.WorkerParked);
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

    /// The slot no longer waits to be enqueued: it stops being `fits`'s tail.
    const leaveTail = @import("worker_execution_phase.zig").leaveTail;

    fn refuse(self: *Worker, slot: *Slot, err: anyerror) ?*Slot {
        self.leaveTail(slot);
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

    const pinnedAlloc = @import("worker_execution_phase.zig").pinnedAlloc;

    pub fn stageUpload(self: *Worker, dst: api.DeviceBuffer, src: []const u32) !void {
        const slot = self.staging orelse return error.StagerOutsidePhaseOne;
        if (src.len == 0) return;
        if (src.len > dst.words) return error.UploadExceedsDestination;
        if (!self.arena.contains(@intFromPtr(dst.ptr), src.len) and !self.isPersistent(dst, src.len) and !self.isRetained(dst, src.len)) return error.UploadOutsideJobMemory;
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
        if (self.regions_buffer) |pool| {
            const lo = @intFromPtr(pool);
            const at = @intFromPtr(dst.ptr);
            return at >= lo and (at - lo) / 4 <= self.regions.words and words <= self.regions.words - (at - lo) / 4;
        }
        var it = self.persistent_map.valueIterator();
        while (it.next()) |b| {
            const lo = @intFromPtr(b.ptr);
            const at = @intFromPtr(dst.ptr);
            if (at >= lo and at + words * 4 <= lo + b.words * 4) return true;
        }
        return false;
    }

    pub fn persistent(self: *Worker, key: [32]u8, words: usize) !api.Persistent {
        const slot = self.staging orelse return error.StagerOutsidePhaseOne;
        if (self.regions_buffer) |pool| {
            if (self.warm_persistent_only and self.regions.find(key) == null) return error.PersistentClassNotWarmed;
            if (slot.pinned_count == slot.pinned_keys.len) return error.TooManyPersistentRegions;
            if (slot.fresh_count == slot.fresh_keys.len and self.regions.find(key) == null) return error.TooManyPersistentFills;
            const got = try self.regions.acquire(self.a, key, words);
            slot.pinned_keys[slot.pinned_count] = key;
            slot.pinned_count += 1;
            slot.persistent_words += words;
            if (got.fresh) {
                slot.fresh_keys[slot.fresh_count] = key;
                slot.fresh_count += 1;
            }
            return .{ .buffer = .{ .ptr = pool + got.offset, .words = words }, .fresh = got.fresh };
        }
        slot.persistent_words += words;
        if (self.persistent_map.get(key)) |b| {
            if (b.words != words) return error.PersistentGeometryMismatch;
            return .{ .buffer = b, .fresh = false };
        }
        if (self.warm_persistent_only) return error.PersistentClassNotWarmed;
        if (slot.fresh_count == slot.fresh_keys.len) return error.TooManyPersistentFills;
        try self.persistent_map.ensureUnusedCapacity(self.a, 1);
        var ptr: ?[*]u32 = null;
        try O.check(self.ops.exec.alloc_u32_long(self.context, words, &ptr));
        const b = api.DeviceBuffer{ .ptr = ptr orelse return error.CudaAllocationFailed, .words = words };
        self.persistent_map.putAssumeCapacity(key, b);
        slot.fresh_keys[slot.fresh_count] = key;
        slot.fresh_count += 1;
        return .{ .buffer = b, .fresh = true };
    }

    // ---------------- request-scoped retained regions ----------------

    /// Find-or-create (`create`) or find-only the region (request, name) for
    /// the job in `slot`, pinning it until the job is reported. Worker thread.
    pub const stageRetain = @import("worker_retained_phase.zig").stageRetain;

    pub const enqueueRetain = @import("worker_retained_phase.zig").enqueueRetain;

    const isRetained = @import("worker_retained_phase.zig").isRetained;

    /// At report (worker thread): one unpin per region the job pinned. A
    /// region a FAILED job created is released (its contents are undefined).
    /// Regions whose last pin drops after a release are freed here.
    /// Worker thread: free released, unpinned regions (stream-ordered free).
    /// A failed free is never retried (the region is dropped either way).
    const drainRetained = @import("worker_retained_phase.zig").drainRetained;

    /// Release one region (any thread, non-blocking). Freed on the worker
    /// thread once no job pins it. error.RetainedRegionNotLive on a second release.
    pub const releaseRetained = @import("worker_retained_phase.zig").releaseRetained;

    /// Release every live region of `request` (end of request or abort; any
    /// thread, non-blocking, idempotent). Returns how many were released.
    pub const releaseRequest = @import("worker_retained_phase.zig").releaseRequest;

    /// As `releaseRequest`, then wait until every region of `request` is
    /// freed (jobs that pin one finish first). Never from a Sink callback
    /// (those run on the worker thread).
    pub const releaseRequestAndWait = @import("worker_retained_phase.zig").releaseRequestAndWait;

    /// Words held by retained regions (of `request`, or all), released-but-pinned included.
    pub const retainedWords = @import("worker_retained_phase.zig").retainedWords;
    pub const retainedStats = @import("worker_retained_phase.zig").retainedStats;

    // ---------------- phase 2 ----------------
    const enqueue = @import("worker_execution_phase.zig").enqueue;

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

    pub fn enqueueFootprint(self: *Worker) api.Footprint {
        const slot = self.enqueuing orelse return .{ .device_words = 0 };
        return slot.footprint;
    }
    pub fn enqueuePlanned(self: *Worker) bool {
        const slot = self.enqueuing orelse return false;
        return slot.resolved.planned;
    }

    pub fn enqueueHostFn(self: *Worker, f: api.HostFn) !void {
        const slot = self.enqueuing orelse return error.EnqueueOutsidePhaseTwo;
        try self.enqueueHostFnRaw(slot, f);
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
        const view = api.SlabView{ .words = slot.slab_host, .layout = slot.slab.layout, .readback = slot.footprint.readback, .receipt = slot.receipt };
        slot.job.vtable.finish(slot.job.ctx, view) catch |err| return self.report(slot, err);
        self.report(slot, {});
    }

    const markFatal = @import("worker_retained_phase.zig").markFatal;

    const report = @import("worker_retained_phase.zig").report;

    /// Pins, fresh-region retirement and class stats of a finished slot
    /// (shared by the pipeline's `report` and the batch's `finishBatch`).
    const settle = @import("worker_retained_phase.zig").settle;

    /// `known_key`: the class key read BEFORE `finish` (a job may free itself
    /// in finish; batch phase 3 never touches the job after it).
    const settleKeyed = @import("worker_retained_phase.zig").settleKeyed;

    // ---------------- GPU-native request batches ----------------
    //
    // rv64-m8-gpu-native.md §3.8: a request is ONE batch per GPU. The worker
    // stages and enqueues every job of the batch back to back (stage k+1
    // before enqueue k, as the pipeline does), with cross-job and cross-GPU
    // dependencies as device-side event waits; it never waits on the device
    // per job. The driver performs the request's single host wait
    // (`requestWait`) after every GPU's batch tail was enqueued, then
    // `finishBatch` runs each job's phase 3 on this thread without a wait.
    // Batches run through `call` with the pipeline idle.

    /// Runs `run(ctx, worker)` on the worker thread with the pipeline idle
    /// (the control slot, like park/unpark). Any thread; returns its result.
    /// Safe for concurrent callers: each waits on its own completion.
    pub const call = @import("worker_execution_phase.zig").call;

    /// Queue `c` for the worker thread and return without waiting for it
    /// (the driver dispatches one GPU's batch while it enqueues another's,
    /// with no per-request thread). `c.ctx` and `done` must stay valid until
    /// `awaitCall(done)` returned. Not from the worker thread itself.
    pub const post = @import("worker_execution_phase.zig").post;

    /// The result of a `post`ed call (blocks until it ran).
    pub const awaitCall = @import("worker_execution_phase.zig").awaitCall;

    /// Install-only diagnostics, reserved on the owning GPU thread.
    pub const reserveTimingPairs = @import("worker_execution_phase.zig").reserveTimingPairs;

    pub const stageTimingPair = @import("worker_execution_phase.zig").stageTimingPair;

    /// Install (worker thread, idle): `max_jobs` slots per parity with their
    /// events and a pinned pool of `pinned_words` per parity. Grow-only;
    /// never on the request path.
    pub const reserveBatches = @import("worker_execution_phase.zig").reserveBatches;

    /// Install (worker thread, idle): replace the arena with ONE allocation
    /// of `phase_b_words`; phase A uses its first `phase_a_words`, and the
    /// rest is returned as the main_resident region (MAIN of every segment on
    /// this GPU, witness -> PCS). A batch job with `phase_b` grows the arena
    /// over it (stream-ordered: every earlier job on this exec stream is
    /// before it). The base is the same in both phases.
    pub const installPlanArena = @import("worker_execution_phase.zig").installPlanArena;

    /// Teardown (worker thread, every batch finished or quiesced): free the
    /// plan block and leave the worker parked (no arena; `unpark` may
    /// acquire a plain one again). Without it the worker kept the block and
    /// could never park again (WorkerPlanArenaInstalled).
    pub const uninstallPlanArena = @import("worker_execution_phase.zig").uninstallPlanArena;

    /// The arena epochs of plan phases A and B (install-time constants; 0
    /// before `installPlanArena`). Any thread.
    pub const planPhaseEpochs = @import("worker_execution_phase.zig").planPhaseEpochs;

    /// Exec stream and context for driver hooks (worker thread only).
    pub const execStream = @import("worker_execution_phase.zig").execStream;

    /// Stage and enqueue every job of `b` (worker thread, via `call`). Never
    /// waits on the device. Per-job failures are recorded in the job (and
    /// signalled to dependents); `b.result` reports hook/plan failures.
    pub const runBatch = @import("worker_execution_phase.zig").runBatch;

    /// A job settled failed host-side: its `on_fail` hook (e.g. cancel the
    /// capture whose gates would otherwise never fire), once.
    pub const failBatch = @import("worker_execution_phase.zig").failBatch;

    const enqueueHostFnRaw = @import("worker_execution_phase.zig").enqueueHostFnRaw;

    /// The request's single host wait (driver thread): blocks until `event`
    /// (the root GPU's final event, recorded after it waited on every other
    /// GPU's batch tail) completed. Device faults are fatal for the worker.
    pub const requestWait = @import("worker_execution_phase.zig").requestWait;

    /// Phase 3 of every job of `b` (worker thread, via `call`, after the
    /// request wait): `finish` with the job's slab view, no per-job wait.
    pub fn finishBatch(self: *Worker, b: *Batch, device_ok: bool) void {
        for (b.jobs, 0..) |*bj, i| {
            if (bj.settled) continue;
            if (i >= b.slots.len) continue;
            const slot = &b.slots[i];
            bj.settled = true;
            slot.receipt.host_waits = 0;
            bj.receipt = slot.receipt;
            if (!device_ok) {
                bj.job.vtable.abort(bj.job.ctx);
                bj.result = error.CudaDeviceFault;
                self.settle(slot, error.CudaDeviceFault);
                continue;
            }
            if (slot.failed) |err| {
                bj.job.vtable.abort(bj.job.ctx);
                bj.result = err;
                self.settle(slot, err);
                continue;
            }
            const view = api.SlabView{ .words = slot.slab_host, .layout = slot.slab.layout, .readback = slot.footprint.readback, .receipt = slot.receipt };
            const class = bj.job.classKey();
            bj.result = bj.job.vtable.finish(bj.job.ctx, view);
            self.settleKeyed(slot, bj.result, class);
        }
        if (self.last_enqueued) |le| if (@intFromPtr(le) >= @intFromPtr(b.slots.ptr) and @intFromPtr(le) < @intFromPtr(b.slots.ptr) + b.slots.len * @sizeOf(Slot)) {
            self.last_enqueued = null;
        };
        b.slots = &.{};
    }
};

test {
    _ = @import("worker_test.zig");
    _ = @import("worker_service_test.zig");
}
