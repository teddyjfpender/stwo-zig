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
const MP = @import("plan.zig");
const Retained = @import("retained.zig");
const JobTiming = @import("job_timing.zig");

pub const Config = struct {
    device: u32,
    arena_words: usize,
    /// Pinned host words per pipeline slot (three slots: finishing, enqueued, staged).
    pinned_slot_words: usize,
    /// Scheduler-visible pipeline depth (mailbox + staged + enqueued + finishing ≤ this).
    max_outstanding: usize = 3,
    /// Memory policy (plan.zig). Null: `Worker.create` loads STWO_RV64_M8_JOBS_PLAN
    /// if set; unset keeps today's behavior (declared footprints, this arena size).
    plan: ?*const MP.Policy = null,
    /// One pool for Stager.persistent with LRU eviction (0 = per-key
    /// allocations kept for the worker's lifetime, today's behavior).
    persistent_budget_words: usize = 0,
    /// Reclaim non-LIFO `Enqueue.free`s inside a job's window (lowers peaks).
    /// Also STWO_RV64_M8_JOBS_ARENA_REUSE=1 or a policy with allocator=reuse.
    reuse_frees: bool = false,
    /// Honor STWO_RV64_M8_JOBS_PLAN / STWO_RV64_M8_JOBS_ARENA_REUSE (process-wide).
    /// Host-model tests that assert on a specific arena opt out.
    plan_from_env: bool = true,
    /// Pinned slots are allocated on first need and only grow (to the job's
    /// pinned + slab words, rounded up to a power of two of at least
    /// `pinned_granule_words`, so a slot regrows O(log) times), capped at
    /// `pinned_slot_words`. A grown slot's old buffer is NOT freed in the
    /// pipeline (cudaFreeHost synchronizes the device): it is retired and
    /// freed at the next park/unpark or at shutdown, when the pipeline is
    /// idle. Off: three slots of `pinned_slot_words` at start (today's
    /// behavior). A persistent service sets it: the allocation is paid once
    /// per process, sized by what jobs really stage.
    pinned_lazy: bool = false,
    /// Cap on request-scoped retained regions (retained.zig; 0 = accounted,
    /// uncapped). A policy's gpu.retained_budget_words fills it when 0.
    retained_budget_words: usize = 0,
};

/// Lazy pinned slots grow in steps of this many words (16 MiB).
pub const pinned_granule_words: usize = 4 << 20;

/// Outcome of `Worker.park` / `Worker.unpark` (host wall clock on the worker thread).
pub const ParkReceipt = struct {
    /// Arena words released (park) or acquired (unpark).
    arena_words: usize = 0,
    /// Persistent pool words released (park with release_persistent).
    persistent_words: usize = 0,
    ns: u64 = 0,
    /// Arena epoch after the operation (see `Worker.arenaEpoch`).
    epoch: u64 = 0,
    /// unpark: the arena landed at the same base and size as before the park.
    same_base: bool = false,
    /// Retained (request-scoped) words still live after the control step.
    retained_words: usize = 0,
};

pub const ParkOptions = struct {
    /// Also release the persistent region pool / per-key persistent buffers.
    /// Their contents are lost (every key is fresh again) and the persistent
    /// epoch advances. Default: keep them (warm class regions across requests).
    release_persistent: bool = false,
    /// Also release every live request-scoped retained region (all requests).
    /// Default: retained regions survive a park (they are not in the arena).
    release_retained: bool = false,
};

/// Measured per-class plan (spec §3.7 hook): what the class actually used,
/// next to what it declared. Input for the memory-plan sweep.
pub const ClassStat = struct {
    jobs: u64 = 0,
    declared_device_words: u64 = 0,
    peak_arena_words: u64 = 0,
    staged_words: u64 = 0,
    slab_words: u64 = 0,
    peak_pinned_words: u64 = 0,
    stage_ns: u64 = 0,
    enqueue_ns: u64 = 0,
    wait_ns: u64 = 0,
    // v2 (memory-plan sweep): declared parts, per-side measurements, policy outcome.
    declared_staged_words: u64 = 0,
    declared_pinned_words: u64 = 0,
    /// MP.peakOf(declared footprint): what the declaration claims the arena must hold.
    declared_peak_words: u64 = 0,
    /// Peak the policy planned with (0 = class not in the policy / no policy).
    planned_peak_words: u64 = 0,
    /// Jobs whose measured arena peak exceeded the planned peak (stale policy).
    over_plan: u64 = 0,
    /// Jobs the worker staged only after its predecessor was enqueued (pair did not fit).
    serialized: u64 = 0,
    /// Largest Stager.persistent total one job referenced (fresh or warm).
    persistent_words: u64 = 0,
    sides: [2]SideStat = .{ .{}, .{} },
};

/// Per placement (0 = bottom, 1 = top) measurements of a class.
pub const SideStat = struct {
    jobs: u64 = 0,
    /// Own staged inputs + bump high-water of the work window (what the window must hold).
    peak_arena_words: u64 = 0,
    /// Own staged inputs + high-water of live (allocated, not freed) words:
    /// the peak a perfect allocator would reach. peak - live_peak is LIFO waste.
    live_peak_words: u64 = 0,
    staged_words: u64 = 0,
    /// Allocation index (1-based, in enqueue order) that set the peak, and its size.
    peak_alloc: u64 = 0,
    peak_alloc_words: u64 = 0,
    allocs: u64 = 0,
};

pub const Sink = struct {
    ctx: *anyopaque,
    done: *const fn (*anyopaque, api.Completion) void,
};

pub const Arena = @import("arena.zig").Arena;

/// Class-persistent regions in one pool (Stager.persistent with a budget):
/// first-fit placement, LRU eviction of regions no in-flight job pins. Pure
/// bookkeeping over offsets; the worker maps them into one device allocation.
///
/// Why eviction is safe without a host wait: a region is evictable only when
/// no staged, enqueued or finishing job pins it, so every job that touched it
/// was enqueued before the job now filling its successor. Exec-stream writes
/// are ordered after them; h2d uploads first wait (on the device) for the most
/// recently enqueued job (Worker.stageUpload). A failed fill is retired (kept
/// occupied, never found or reused): its h2d copy may still be in flight.
pub const Regions = struct {
    words: usize = 0,
    entries: std.ArrayListUnmanaged(Entry) = .empty, // sorted by offset
    tick: u64 = 0,
    evictions: u64 = 0,
    evicted_words: u64 = 0,
    high_water: usize = 0,

    pub const Entry = struct { key: [32]u8, offset: usize, words: usize, requested: usize, last_use: u64, pins: u32 = 0, retired: bool = false };
    pub const Acquired = struct { offset: usize, fresh: bool };

    pub fn deinit(self: *Regions, a: std.mem.Allocator) void {
        self.entries.deinit(a);
    }
    pub fn find(self: *const Regions, key: [32]u8) ?usize {
        for (self.entries.items, 0..) |e, i| if (!e.retired and std.mem.eql(u8, &e.key, &key)) return i;
        return null;
    }
    /// Find or place `key`; pins it (one `unpin` per successful acquire).
    pub fn acquire(self: *Regions, a: std.mem.Allocator, key: [32]u8, requested: usize) !Acquired {
        if (requested == 0) return error.InvalidAllocation;
        self.tick += 1;
        if (self.find(key)) |i| {
            const e = &self.entries.items[i];
            if (e.requested != requested) return error.PersistentGeometryMismatch;
            e.last_use = self.tick;
            e.pins += 1;
            return .{ .offset = e.offset, .fresh = false };
        }
        const words = std.mem.alignForward(usize, requested, Arena.granule);
        if (words > self.words) return error.PersistentRegionExceedsBudget;
        try self.entries.ensureUnusedCapacity(a, 1);
        // Fail without evicting when even evicting every unpinned region cannot make room.
        if (self.gap(words, true) == null) return error.PersistentBudgetExhausted;
        while (true) {
            if (self.gap(words, false)) |g| {
                self.entries.insertAssumeCapacity(g.index, .{ .key = key, .offset = g.offset, .words = words, .requested = requested, .last_use = self.tick, .pins = 1 });
                self.high_water = @max(self.high_water, g.offset + words);
                return .{ .offset = g.offset, .fresh = true };
            }
            var victim: ?usize = null;
            for (self.entries.items, 0..) |e, i| {
                if (e.pins != 0 or e.retired) continue;
                if (victim == null or e.last_use < self.entries.items[victim.?].last_use) victim = i;
            }
            const v = victim orelse return error.PersistentBudgetExhausted;
            self.evictions += 1;
            self.evicted_words += self.entries.items[v].words;
            _ = self.entries.orderedRemove(v);
        }
    }
    /// First fit. `evictable_free`: treat unpinned live regions as free (feasibility only).
    fn gap(self: *const Regions, words: usize, evictable_free: bool) ?struct { index: usize, offset: usize } {
        var end: usize = 0;
        for (self.entries.items, 0..) |e, i| {
            if (evictable_free and e.pins == 0 and !e.retired) continue;
            if (e.offset - end >= words) return .{ .index = i, .offset = end };
            end = e.offset + e.words;
        }
        if (self.words - end >= words) return .{ .index = self.entries.items.len, .offset = end };
        return null;
    }
    pub fn unpin(self: *Regions, key: [32]u8) void {
        for (self.entries.items) |*e| if (std.mem.eql(u8, &e.key, &key) and e.pins != 0) {
            e.pins -= 1;
            return;
        };
    }
    /// A failed fill: keep the space occupied forever, never hand it out again.
    pub fn retire(self: *Regions, key: [32]u8) void {
        if (self.find(key)) |i| self.entries.items[i].retired = true;
    }
    pub fn used(self: *const Regions) usize {
        var n: usize = 0;
        for (self.entries.items) |e| n += e.words;
        return n;
    }
};

const Slot = struct {
    request_parity: ?u1 = null,
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
    /// Persistent entries this job created (fresh); dropped if the job fails.
    // 64: a native-hybrid Stage2 job fills one twiddle key per global log, plus INTER/composition/PCS keys.
    fresh_keys: [64][32]u8 = undefined,
    fresh_count: usize = 0,
    /// Pool regions this job pinned (one unpin each when it leaves the pipeline).
    pinned_keys: [64][32]u8 = undefined,
    pinned_count: usize = 0,
    persistent_words: usize = 0,
    /// Request-scoped retained regions this job pinned (retained.zig); one
    /// unpin each at report. `retained_fresh`: created by this job.
    retained_refs: [16]api.DeviceBuffer = undefined,
    retained_fresh: [16]bool = undefined,
    retained_count: usize = 0,
    /// Batch dependencies (GPU-native request batches only).
    batch_deps: []const *BatchDep = &.{},
    /// Footprint the worker planned with (plan.zig; declared when unplanned).
    resolved: MP.Resolved = MP.declared(.{ .device_words = 0 }),
    /// The job's own declaration (sweep records declared vs measured).
    declared: api.Footprint = .{ .device_words = 0 },
    /// Submission index (scheduler-visible tail tracking for `fits`).
    submit_index: u64 = 0,
    serialized: bool = false,
    // arena measurements of this job's window
    live_peak: usize = 0,
    peak_alloc: usize = 0,
    peak_alloc_words: usize = 0,
    allocs: usize = 0,
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
        if (config.plan_from_env) if (std.posix.getenv("STWO_RV64_M8_JOBS_ARENA_REUSE")) |v| {
            if (std.mem.eql(u8, v, "1")) config.reuse_frees = true else if (!std.mem.eql(u8, v, "0")) return error.InvalidM8JobsEnvironment;
        };
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
    pub fn plan(self: *const Worker) ?*const MP.Policy {
        return self.policy;
    }

    fn resolve(self: *const Worker, job: api.Job) MP.Resolved {
        return self.resolveFootprint(job, job.footprint());
    }
    fn resolveFootprint(self: *const Worker, job: api.Job, fp: api.Footprint) MP.Resolved {
        const p = self.policy orelse return MP.declared(fp);
        return p.resolve(job.classKey(), fp);
    }

    /// Placement by footprint (scheduler): true when `job`'s staged inputs fit
    /// beside the job this worker would stage it next to (the last submitted
    /// job, until it is enqueued). Always true without a policy. A job that does
    /// not fit is still correct on this worker (it serializes), just not overlapped.
    pub fn fits(self: *Worker, job: api.Job) bool {
        if (self.policy == null) return true;
        const r = self.resolve(job);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.tail_live) return true;
        return MP.pairFits(self.config.arena_words, self.tail_peak, r.staged_words);
    }

    /// Measured class plans + allocator state (STWO_RV64_M8_JOBS_PLAN_DIR).
    pub fn writePlanDir(self: *Worker, dir: []const u8) !void {
        const Row = struct { device: u32, class_key: [64]u8, stat: ClassStat };
        var rows: std.ArrayListUnmanaged(Row) = .empty;
        defer rows.deinit(self.a);
        {
            // The worker thread records class stats under the mutex.
            self.mutex.lock();
            defer self.mutex.unlock();
            var it = self.classes.iterator();
            while (it.next()) |e| try rows.append(self.a, .{ .device = self.device_ordinal, .class_key = std.fmt.bytesToHex(e.key_ptr.*, .lower), .stat = e.value_ptr.* });
        }
        var text: std.Io.Writer.Allocating = .init(self.a);
        defer text.deinit();
        try std.json.Stringify.value(.{
            .schema = "rv64-m8-jobs-class-plans/v2",
            .device = self.device_ordinal,
            .arena_words = self.config.arena_words,
            .allocator = if (self.config.reuse_frees) "reuse" else "lifo",
            .policy = self.policy != null,
            .persistent = .{ .budget_words = self.config.persistent_budget_words, .regions = self.regions.entries.items.len, .used_words = self.regions.used(), .high_water_words = self.regions.high_water, .evictions = self.regions.evictions, .evicted_words = self.regions.evicted_words, .unbudgeted_regions = if (self.shut_down) self.unbudgeted_regions else self.persistent_map.count() },
            .completed = self.completed,
            .retained = self.retained.stats,
            .service = .{ .parks = self.parks, .unparks = self.unparks, .arena_epoch = self.arena_epoch, .persistent_epoch = self.persistent_epoch, .pinned_allocated_bytes = self.pinned_allocated_bytes, .pinned_allocations = self.pinned_allocations, .pinned_lazy = self.config.pinned_lazy },
            .classes = rows.items,
        }, .{ .whitespace = .indent_1 }, &text.writer);
        std.fs.cwd().makePath(dir) catch {};
        var name_buf: [96]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "worker-d{d}-{d}-{x}.json", .{ self.device_ordinal, std.time.nanoTimestamp(), @intFromPtr(self) & 0xffffff });
        var d = try std.fs.cwd().openDir(dir, .{});
        defer d.close();
        try d.writeFile(.{ .sub_path = name, .data = text.written() });
    }

    /// True when the scheduler may submit another job to this worker.
    pub fn accepts(self: *Worker) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.fatal == null and !self.closing and !self.parked and !self.parking and self.mailbox == null and self.outstanding < self.config.max_outstanding;
    }
    /// Snapshot of the measured class plans (caller frees with `a`).
    pub const ClassEntry = struct { key: [32]u8, stat: ClassStat };
    pub fn classStats(self: *Worker, a: std.mem.Allocator) ![]ClassEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        const out = try a.alloc(ClassEntry, self.classes.count());
        var it = self.classes.iterator();
        var i: usize = 0;
        while (it.next()) |e| : (i += 1) out[i] = .{ .key = e.key_ptr.*, .stat = e.value_ptr.* };
        return out;
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
        self.arena = .{ .base = @intFromPtr(arena.?), .words = self.config.arena_words, .reuse = self.config.reuse_frees };
        if (self.config.persistent_budget_words != 0) {
            if (self.config.persistent_budget_words % Arena.granule != 0) return error.InvalidPersistentBudget;
            var pool: ?[*]u32 = null;
            try O.check(self.ops.exec.alloc_u32_long(self.context, self.config.persistent_budget_words, &pool));
            self.regions_buffer = pool orelse return error.CudaAllocationFailed;
            self.regions.words = self.config.persistent_budget_words;
        }
        for (&self.slots) |*slot| {
            try O.check(w.event_create(&slot.staged_event));
            try O.check(w.event_create(&slot.done_event));
            if (!self.config.pinned_lazy) slot.pinned = try self.pinnedSlotAlloc(self.config.pinned_slot_words);
        }
        self.arena_epoch = 1;
    }

    fn pinnedSlotAlloc(self: *Worker, words: usize) ![]u32 {
        var host: ?*anyopaque = null;
        try O.check(self.ops.wait.host_alloc(words * 4, &host));
        self.pinned_allocated_bytes += words * 4;
        self.pinned_allocations += 1;
        return @as([*]u32, @ptrCast(@alignCast(host orelse return error.PinnedAllocationFailed)))[0..words];
    }

    /// Lazy pinned slots: grow `slot` to hold `needed` words. Legal here: the
    /// slot's previous job completed (its event was waited) before this stage.
    fn ensurePinned(self: *Worker, slot: *Slot, needed: usize) !void {
        if (!self.config.pinned_lazy or needed <= slot.pinned.len) return;
        if (needed > self.config.pinned_slot_words) return error.JobFootprintExceedsPinned;
        const words = @min(self.config.pinned_slot_words, pinnedGrowth(needed));
        if (slot.pinned.len != 0) try self.pinned_retired.ensureUnusedCapacity(self.a, 1);
        const grown = try self.pinnedSlotAlloc(words);
        if (slot.pinned.len != 0) self.pinned_retired.appendAssumeCapacity(slot.pinned);
        slot.pinned = grown;
    }

    /// Lazy slot size for `needed` words: a power of two, at least one granule.
    pub fn pinnedGrowth(needed: usize) usize {
        return std.math.ceilPowerOfTwo(usize, @max(needed, pinned_granule_words)) catch std.math.maxInt(usize);
    }

    /// Pipeline idle only (no job reads the retired buffers any more).
    fn freeRetiredPinned(self: *Worker) void {
        for (self.pinned_retired.items) |p| _ = self.ops.wait.host_free(p.ptr);
        self.pinned_retired.clearRetainingCapacity();
    }

    // ---------------- park / unpark ----------------

    fn isClosing(self: *Worker) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.closing;
    }

    fn takeControl(self: *Worker) ?Control {
        self.mutex.lock();
        defer self.mutex.unlock();
        const c = self.control;
        self.control = null;
        return c;
    }

    fn serviceControl(self: *Worker, c: Control) void {
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
        self.freeRetiredPinned();
        if (c == .park and c.park.release_retained) self.releaseAllRetained();
        self.drainRetained();
        var result: anyerror!ParkReceipt = switch (c) {
            .park => |o| self.releaseArena(o),
            .unpark => |words| self.acquireArena(words),
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

    fn releaseArena(self: *Worker, o: ParkOptions) !ParkReceipt {
        var r = ParkReceipt{ .arena_words = self.arena.words };
        // Every job completed (its done event was waited): nothing on the
        // device still reads the arena, so the free needs no further wait.
        if (self.arena_buffer) |p| try O.check(self.ops.exec.free_u32(self.context, p));
        self.arena_buffer = null;
        self.last_base = self.arena.base;
        self.last_words = self.arena.words;
        self.arena = .{ .reuse = self.config.reuse_frees };
        self.last_enqueued = null;
        if (o.release_persistent) r.persistent_words = try self.releasePersistent();
        return r;
    }

    /// Best effort: every buffer is freed once and dropped from its container
    /// whatever the outcome (a failed free is never retried, so shutdown
    /// cannot free it twice); the first failure is reported.
    /// Worker thread, or quiesced install: exact live allocation words.
    /// Unlike class declarations this counts shared keys only once.
    pub fn persistentWords(self: *Worker) u64 {
        var words: u64 = if (self.regions_buffer != null) self.regions.words else 0;
        var it = self.persistent_map.valueIterator();
        while (it.next()) |buffer| words += buffer.words;
        return words;
    }

    fn releasePersistent(self: *Worker) !usize {
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

    fn acquireArena(self: *Worker, words_in: usize) !ParkReceipt {
        // Never overwrite (leak) a live static arena.
        if (self.arena_buffer != null) return error.WorkerNotParked;
        const words = if (words_in == 0) self.last_words else words_in;
        if (words == 0 or words % Arena.granule != 0) return error.InvalidArena;
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

    fn requestControl(self: *Worker, c: Control) !ParkReceipt {
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

    /// Release the static arena (back to the process-wide device arena, so
    /// the legacy owner may use it) and keep everything else: context,
    /// streams, events, pinned slots, class stats, persistent regions (unless
    /// `o.release_persistent`). Waits until every submitted job completed;
    /// `submit` refuses (error.WorkerParked) from the call on. Any thread.
    pub fn park(self: *Worker, o: ParkOptions) !ParkReceipt {
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
        const r = self.requestControl(.{ .park = o }) catch |err| {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.parking = false;
            return err;
        };
        return r;
    }

    /// Re-acquire a static arena of `arena_words` (0 = the size before the
    /// park). `same_base` / `arenaEpoch` tell graph caches whether device
    /// addresses they captured are still valid. Any thread.
    pub fn unpark(self: *Worker, arena_words: usize) !ParkReceipt {
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.fatal) |err| return err;
            if (!self.parked) return error.WorkerNotParked;
            // One control request at a time (the control slot is single).
            if (self.unparking or self.control != null) return error.WorkerBusy;
            self.unparking = true;
        }
        return self.requestControl(.{ .unpark = arena_words });
    }

    pub fn isParked(self: *Worker) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.parked;
    }

    /// Identity of the current arena's (base, words); a graph cache that
    /// captured device addresses keys or flushes on it.
    pub fn arenaEpoch(self: *Worker) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.arena_epoch;
    }

    /// Advances when persistent regions were released by a park.
    pub fn persistentEpoch(self: *Worker) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.persistent_epoch;
    }

    /// Current static arena size in words (0 while parked).
    pub fn arenaWords(self: *Worker) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return if (self.parked) 0 else self.config.arena_words;
    }

    /// Pinned host bytes currently held by the three slots.
    pub fn pinnedBytes(self: *Worker) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        var n: usize = 0;
        for (self.slots) |s| n += s.pinned.len * 4;
        return n;
    }

    fn shutdown(self: *Worker) void {
        const w = &self.ops.wait;
        for (&self.slots) |*slot| {
            if (slot.staged_event) |e| _ = w.event_destroy(e);
            if (slot.done_event) |e| _ = w.event_destroy(e);
            if (slot.pinned.len != 0) _ = w.host_free(slot.pinned.ptr);
        }
        self.releaseBatches();
        self.timing_pool.deinit(self.a, self.ops.wait.event_destroy);
        self.freeRetiredPinned();
        self.pinned_retired.deinit(self.a);
        self.drainRetained();
        {
            // Regions the request protocol never released: free and count
            // them (no job is left, so none is pinned).
            var leaked: std.ArrayListUnmanaged(api.DeviceBuffer) = .empty;
            defer leaked.deinit(self.a);
            self.mutex.lock();
            for (self.retained.entries.items) |e| leaked.append(self.a, e.buffer) catch {};
            self.retained.stats.leaked_at_shutdown += leaked.items.len;
            self.mutex.unlock();
            self.freeRetained(leaked.items);
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
    fn leaveTail(self: *Worker, slot: *Slot) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (slot.submit_index != std.math.maxInt(u64) and slot.submit_index + 1 == self.submitted) self.tail_live = false;
    }

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
    fn retainFor(self: *Worker, slot: *Slot, key: Retained.Key, words: usize, may_create: bool) !api.Retained {
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
        return self.retainFor(slot, .{ .request = request, .name = name }, words, may_create);
    }

    pub fn enqueueRetain(self: *Worker, request: u64, name: [32]u8, words: usize, may_create: bool) !api.Retained {
        const slot = self.enqueuing orelse return error.EnqueueOutsidePhaseTwo;
        return self.retainFor(slot, .{ .request = request, .name = name }, words, may_create);
    }

    fn isRetained(self: *Worker, dst: api.DeviceBuffer, words: usize) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.retained.contains(@intFromPtr(dst.ptr), words);
    }

    /// At report (worker thread): one unpin per region the job pinned. A
    /// region a FAILED job created is released (its contents are undefined).
    /// Regions whose last pin drops after a release are freed here.
    fn unpinRetained(self: *Worker, slot: *Slot, ok: bool) void {
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
                O.check(self.ops.exec.stream_wait(self.exec_stream, ev)) catch |err| self.markFatal(err);
            } else |err| self.markFatal(err);
        };
        self.freeRetained(free_now[0..n]);
    }

    /// Worker thread: free released, unpinned regions (stream-ordered free).
    /// A failed free is never retried (the region is dropped either way).
    fn freeRetained(self: *Worker, buffers: []const api.DeviceBuffer) void {
        for (buffers) |b| {
            O.check(self.ops.exec.free_u32(self.context, b.ptr)) catch |err| std.log.err("M8 retained region free failed: {s}", .{@errorName(err)});
        }
        self.mutex.lock();
        defer self.mutex.unlock();
        for (buffers) |b| self.retained.drop(b);
        self.cond.broadcast();
    }

    fn drainRetained(self: *Worker) void {
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
        self.freeRetained(pending);
    }

    fn releaseAllRetained(self: *Worker) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.retained.entries.items) |*e| if (!e.released) {
            e.released = true;
            if (e.pins == 0) self.retained_pending.append(self.a, e.buffer) catch {};
        };
    }

    /// Release one region (any thread, non-blocking). Freed on the worker
    /// thread once no job pins it. error.RetainedRegionNotLive on a second release.
    pub fn releaseRetained(self: *Worker, request: u64, name: [32]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.retained_pending.ensureUnusedCapacity(self.a, 1);
        if (try self.retained.release(.{ .request = request, .name = name })) |b| self.retained_pending.appendAssumeCapacity(b);
        self.cond.broadcast();
    }

    /// Release every live region of `request` (end of request or abort; any
    /// thread, non-blocking, idempotent). Returns how many were released.
    pub fn releaseRequest(self: *Worker, request: u64) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        const n = try self.retained.releaseRequest(self.a, request, &self.retained_pending);
        self.cond.broadcast();
        return n;
    }

    /// As `releaseRequest`, then wait until every region of `request` is
    /// freed (jobs that pin one finish first). Never from a Sink callback
    /// (those run on the worker thread).
    pub fn releaseRequestAndWait(self: *Worker, request: u64) !usize {
        if (self.thread_id == std.Thread.getCurrentId()) return error.ReleaseWaitOnWorkerThread;
        const n = try self.releaseRequest(request);
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.retained.liveWords(request) != 0 and !self.stopped) self.cond.wait(&self.mutex);
        return n;
    }

    /// Words held by retained regions (of `request`, or all), released-but-pinned included.
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

    // ---------------- phase 2 ----------------
    fn enqueue(self: *Worker, slot: *Slot, next: ?*Slot) ?*Slot {
        var timer = std.time.Timer.start() catch unreachable;
        self.arena.beginWork(slot.placement, next != null and next.?.placement != slot.placement);
        self.enqueuing = slot;
        defer self.enqueuing = null;
        if (self.fatal) |err| {
            slot.failed = err; // staged before a device fault: never enqueue it
        } else if (slot.failed != null) {
            // batch: a dependency failed host-side; never enqueue the body
        } else self.enqueueBody(slot) catch |err| {
            slot.failed = err;
        };
        // A skipped (or early-failed) body never made the exec stream wait
        // on its staged uploads: do it now, so this done event — and every
        // later quiesce/request wait on the exec stream — dominates every
        // copy the slot issued from the (parity-reused) pinned pool.
        if (slot.uploads and !slot.waited_staged) {
            O.check(self.ops.exec.stream_wait(self.exec_stream, slot.staged_event.?)) catch |err| {
                self.markFatal(err);
                slot.failed = slot.failed orelse err;
            };
            slot.waited_staged = true;
        }
        // The done event is recorded even after a failure so later h2d waits
        // and this job's completion are well defined.
        O.check(self.ops.exec.event_record(slot.done_event.?, self.exec_stream)) catch |err| {
            self.markFatal(err);
            slot.failed = slot.failed orelse err;
        };
        self.last_enqueued = slot;
        self.leaveTail(slot);
        slot.receipt.enqueue_ns = timer.read();
        slot.receipt.arena_peak_words = self.arena.peak;
        slot.live_peak = self.arena.live_peak;
        slot.peak_alloc = self.arena.peak_alloc;
        slot.peak_alloc_words = self.arena.peak_alloc_words;
        slot.allocs = self.arena.allocs;
        return slot;
    }

    fn enqueueBody(self: *Worker, slot: *Slot) !void {
        try self.enqueueWaitStaged();
        // Batch dependencies: device-side waits on the producers' done events
        // (any GPU). Their records were issued before this enqueue (host latch).
        for (slot.batch_deps) |d| if (d.event) |ev| try O.check(self.ops.exec.stream_wait(self.exec_stream, ev));
        const state = try self.enqueueAlloc(Channel.state_words);
        slot.channel = Channel.DeviceChannel.init(self.handle(), &self.ops.exec, self.context, self.exec_stream, state, slot.seq);
        const slab_device: api.DeviceBuffer = if (slot.footprint.slab_words == 0) .{ .ptr = state.ptr, .words = 0 } else try self.enqueueAlloc(slot.footprint.slab_words);
        slot.slab_host = try self.pinnedAlloc(slot, slot.footprint.hostSlabWords());
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

    fn markFatal(self: *Worker, err: anyerror) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.fatal == null) self.fatal = err;
    }

    fn report(self: *Worker, slot: *Slot, result: anyerror!void) void {
        self.settle(slot, result);
        slot.sink.done(slot.sink.ctx, .{ .job = slot.job, .result = result, .receipt = slot.receipt });
        self.mutex.lock();
        self.outstanding -= 1;
        self.completed += 1;
        self.cond.broadcast();
        self.mutex.unlock();
    }

    /// Pins, fresh-region retirement and class stats of a finished slot
    /// (shared by the pipeline's `report` and the batch's `finishBatch`).
    fn settle(self: *Worker, slot: *Slot, result: anyerror!void) void {
        self.settleKeyed(slot, result, null);
    }

    /// `known_key`: the class key read BEFORE `finish` (a job may free itself
    /// in finish; batch phase 3 never touches the job after it).
    fn settleKeyed(self: *Worker, slot: *Slot, result: anyerror!void, known_key: ?[32]u8) void {
        for (slot.pinned_keys[0..slot.pinned_count]) |key| self.regions.unpin(key);
        slot.pinned_count = 0;
        self.unpinRetained(slot, if (result) |_| true else |_| false);
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
    pub fn call(self: *Worker, c: Call) !void {
        if (self.thread_id == std.Thread.getCurrentId()) return c.run(c.ctx, self);
        var done = CallDone{};
        try self.post(c, &done);
        return self.awaitCall(&done);
    }

    /// Queue `c` for the worker thread and return without waiting for it
    /// (the driver dispatches one GPU's batch while it enqueues another's,
    /// with no per-request thread). `c.ctx` and `done` must stay valid until
    /// `awaitCall(done)` returned. Not from the worker thread itself.
    pub fn post(self: *Worker, c: Call, done: *CallDone) !void {
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

    /// The result of a `post`ed call (blocks until it ran).
    pub fn awaitCall(self: *Worker, done: *CallDone) anyerror!void {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (!done.done) self.cond.wait(&self.mutex);
        return done.result;
    }

    /// Install-only diagnostics, reserved on the owning GPU thread.
    pub fn reserveTimingPairs(self: *Worker, count: usize, create_event: JobTiming.Create) !void {
        try self.onWorkerThread();
        try self.timing_pool.reserve(self.a, count, create_event, self.ops.wait.event_destroy);
    }

    pub fn stageTimingPair(self: *Worker, parity: u1, index: usize) !JobTiming.Pair {
        const slot = self.staging orelse return error.StagerOutsidePhaseOne;
        const active = slot.request_parity orelse return error.JobTimingOutsideRequestBatch;
        if (active != parity) return error.JobTimingParityMismatch;
        return self.timing_pool.get(parity, index);
    }

    /// Install (worker thread, idle): `max_jobs` slots per parity with their
    /// events and a pinned pool of `pinned_words` per parity. Grow-only;
    /// never on the request path.
    pub fn reserveBatches(self: *Worker, max_jobs: usize, pinned_words: usize) !void {
        try self.onWorkerThread();
        for (0..2) |p| {
            if (self.batch_slots[p].len < max_jobs) {
                const grown = try self.a.alloc(Slot, max_jobs);
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
                const grown = try self.pinnedSlotAlloc(pinned_words);
                if (self.batch_pinned[p].len != 0) _ = self.ops.wait.host_free(self.batch_pinned[p].ptr);
                self.batch_pinned[p] = grown;
            }
        }
    }

    fn releaseBatches(self: *Worker) void {
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

    /// Install (worker thread, idle): replace the arena with ONE allocation
    /// of `phase_b_words`; phase A uses its first `phase_a_words`, and the
    /// rest is returned as the main_resident region (MAIN of every segment on
    /// this GPU, witness -> PCS). A batch job with `phase_b` grows the arena
    /// over it (stream-ordered: every earlier job on this exec stream is
    /// before it). The base is the same in both phases.
    pub fn installPlanArena(self: *Worker, phase_a_words: usize, phase_b_words: usize) !api.DeviceBuffer {
        try self.onWorkerThread();
        if (phase_a_words == 0 or phase_a_words % Arena.granule != 0 or phase_b_words < phase_a_words or phase_b_words % Arena.granule != 0) return error.InvalidArena;
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

    /// Teardown (worker thread, every batch finished or quiesced): free the
    /// plan block and leave the worker parked (no arena; `unpark` may
    /// acquire a plain one again). Without it the worker kept the block and
    /// could never park again (WorkerPlanArenaInstalled).
    pub fn uninstallPlanArena(self: *Worker) !void {
        try self.onWorkerThread();
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

    fn setPhase(self: *Worker, b: bool) void {
        if (self.plan_phase_words[1] == 0 or self.plan_phase_b == b) return;
        self.arena = .{ .base = self.arena.base, .words = self.plan_phase_words[@intFromBool(b)], .reuse = self.config.reuse_frees };
        self.plan_phase_b = b;
        self.mutex.lock();
        self.arena_epoch = self.plan_phase_epochs[@intFromBool(b)];
        self.mutex.unlock();
    }

    /// The arena epochs of plan phases A and B (install-time constants; 0
    /// before `installPlanArena`). Any thread.
    pub fn planPhaseEpochs(self: *Worker) [2]u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.plan_phase_epochs;
    }

    fn onWorkerThread(self: *Worker) !void {
        if (self.thread_id != std.Thread.getCurrentId()) return error.NotOnWorkerThread;
    }

    /// Exec stream and context for driver hooks (worker thread only).
    pub fn execStream(self: *Worker) *anyopaque {
        return self.exec_stream;
    }

    /// Stage and enqueue every job of `b` (worker thread, via `call`). Never
    /// waits on the device. Per-job failures are recorded in the job (and
    /// signalled to dependents); `b.result` reports hook/plan failures.
    pub fn runBatch(self: *Worker, b: *Batch) void {
        var timer = std.time.Timer.start() catch unreachable;
        defer b.enqueue_ns = timer.read();
        self.onWorkerThread() catch |err| return failBatch(b, err, 0);
        // Validate the complete batch before staging or waiting on any gate.
        for (b.jobs) |bj| bj.job.footprint().validateSizes() catch |err| return failBatch(b, err, 0);
        self.warm_persistent_only = b.require_warm_persistent;
        defer self.warm_persistent_only = false;
        const slots = self.batch_slots[b.parity];
        if (b.jobs.len > slots.len) return failBatch(b, error.BatchExceedsReservedSlots, 0);
        b.pinned_used = 0;
        b.memory_serializations = 0;
        b.slots = slots[0..b.jobs.len];
        self.setPhase(false);
        if (b.preamble) |h| h.run(h.ctx, self) catch |err| return failBatch(b, err, 0);
        var staged: ?*Slot = null;
        for (b.jobs, 0..) |*bj, i| {
            if (bj.phase_b and !self.plan_phase_b) {
                // Phase change: the new window must not be pre-staged into
                // the old one; enqueue the staged job alone first.
                if (staged) |s| self.batchEnqueue(b, s, null);
                staged = null;
                self.setPhase(true);
            }
            // A gated job (capture) is staged only after its gates latched
            // (its stage may read the sealed segment). Enqueue the staged
            // job first so it does not wait behind a later segment's capture.
            if (!gatesLatched(bj)) {
                if (staged) |s| self.batchEnqueue(b, s, null);
                staged = null;
            }
            if (staged) |s| {
                const next = self.resolveFootprint(bj.job, bj.job.footprint());
                if (!MP.pairFits(self.arena.words, s.resolved.peak_words, next.staged_words)) {
                    // The ordinary mailbox pipeline applies this same test.
                    // A batch must also enqueue the current job before staging
                    // a neighbour whose inputs would shrink its work window.
                    // The next upload is ordered by the done event on-device;
                    // this introduces no host/device join.
                    self.batchEnqueue(b, s, null);
                    staged = null;
                    b.memory_serializations += 1;
                }
            }
            const slot = self.batchStage(b, i);
            if (staged) |s| self.batchEnqueue(b, s, slot);
            staged = slot;
        }
        if (staged) |s| self.batchEnqueue(b, s, null);
        if (b.tail) |h| h.run(h.ctx, self) catch |err| {
            std.debug.print("GPU_M8_GN_BATCH_FAILED device={d} phase=tail error={s}\n", .{ self.device_ordinal, @errorName(err) });
            b.result = err;
        };
        b.slots_used = b.jobs.len;
    }

    fn gatesLatched(bj: *const BatchJob) bool {
        for (bj.gates) |g| if (!g.recorded.isSet()) return false;
        return true;
    }

    /// A job settled failed host-side: its `on_fail` hook (e.g. cancel the
    /// capture whose gates would otherwise never fire), once.
    fn notifyFailed(bj: *BatchJob) void {
        if (bj.on_fail) |f| {
            bj.on_fail = null;
            f.call(f.user);
        }
    }

    pub fn failBatch(b: *Batch, err: anyerror, first: usize) void {
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

    fn batchStage(self: *Worker, b: *Batch, i: usize) ?*Slot {
        const bj = &b.jobs[i];
        const slot = &b.slots[i];
        const seq = self.next_seq;
        self.next_seq += 1;
        const declared_fp = bj.job.footprint();
        const resolved = self.resolveFootprint(bj.job, declared_fp);
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
                ordered catch |e| self.markFatal(e);
            }
            notifyFailed(bj);
            bj.job.vtable.abort(bj.job.ctx);
            self.settle(slot, err);
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

    fn batchEnqueue(self: *Worker, b: *Batch, slot: *Slot, next: ?*Slot) void {
        const i = (@intFromPtr(slot) - @intFromPtr(b.slots.ptr)) / @sizeOf(Slot);
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
        _ = self.enqueue(slot, next);
        if (slot.failed) |err| {
            if (err != error.BatchDependencyFailed) std.debug.print("GPU_M8_GN_JOB_FAILED device={d} job={d} phase=enqueue error={s} arena_words={d} declared_peak_words={d} staged_words={any} high_words={d}\n", .{ self.device_ordinal, i, @errorName(err), self.arena.words, slot.resolved.peak_words, self.arena.staged, self.arena.peak });
        }
        // `after` (capture ring release) runs whatever the body's outcome,
        // after this slot's done record, as long as every gate succeeded (a
        // failed gate means the capture may still own its buffers; the
        // stream's detach returns them once the capture ended). A failed
        // Stage1 that never released its buffers wedged the capture ring.
        if (bj.after) |f| if (gatesSucceeded(bj)) self.enqueueHostFnRaw(slot, f) catch |err| {
            self.markFatal(err);
            slot.failed = slot.failed orelse err;
        };
        if (slot.failed != null) notifyFailed(bj);
        bj.done.signal(slot.done_event, slot.failed != null);
    }

    fn gatesSucceeded(bj: *const BatchJob) bool {
        for (bj.gates) |g| if (!g.recorded.isSet() or g.failed.load(.acquire)) return false;
        return true;
    }

    fn enqueueHostFnRaw(self: *Worker, slot: *Slot, f: api.HostFn) !void {
        try O.check(self.ops.exec.host_fn(self.exec_stream, f.call, f.user));
        slot.receipt.host_callbacks += 1;
        if (f.purpose == .capture_release) slot.receipt.capture_release_callbacks += 1;
    }

    /// The request's single host wait (driver thread): blocks until `event`
    /// (the root GPU's final event, recorded after it waited on every other
    /// GPU's batch tail) completed. Device faults are fatal for the worker.
    pub fn requestWait(self: *Worker, event: *anyopaque) !u64 {
        var timer = std.time.Timer.start() catch unreachable;
        // lint:host-wait-begin — the ONE host wait of a GPU-native request.
        const waited = self.ops.wait.event_sync(event);
        // lint:host-wait-end
        if (waited != 0) {
            self.markFatal(error.CudaDeviceFault);
            return error.CudaDeviceFault;
        }
        return timer.read();
    }

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

pub const Call = struct {
    ctx: *anyopaque,
    run: *const fn (*anyopaque, *Worker) anyerror!void,
};

/// Completion of one `Worker.post` (owned by the caller; guarded by the
/// worker's mutex).
pub const CallDone = struct {
    done: bool = false,
    result: anyerror!void = {},
};

/// A host-visible completion latch of one batch job (or a capture release):
/// `recorded` is set once the producer's done event was RECORDED (host side,
/// so a consumer's cudaStreamWaitEvent sees this request's record), `event`
/// is that done event (null for pure host gates), `failed` poisons dependents.
pub const BatchDep = struct {
    event: ?*anyopaque = null,
    recorded: std.Thread.ResetEvent = .{},
    failed: std.atomic.Value(bool) = .init(false),
    pub fn signal(self: *BatchDep, event: ?*anyopaque, failed: bool) void {
        self.event = event;
        self.failed.store(failed, .release);
        self.recorded.set();
    }
};

pub const BatchJob = struct {
    job: api.Job,
    /// Producers this job waits for (device-side). Latched before ENQUEUE
    /// only: a job's `stage` must not read a producer's (child's) data.
    deps: []const *BatchDep = &.{},
    /// Host gates (capture seal) latched before STAGE: the job is staged only
    /// once its segment is final, so its stage may read the sealed trace. A
    /// failed gate refuses the job (BatchDependencyFailed).
    gates: []const *BatchDep = &.{},
    /// Pure host step enqueued on the exec stream after the job's done
    /// record whenever every gate succeeded (also when the body failed).
    after: ?api.HostFn = null,
    /// Host call made once (worker thread) when the job settles failed on the
    /// host (refused, failed dependency, enqueue error, failed batch): e.g.
    /// cancel the capture so its blocked acquires and later gates fail closed.
    on_fail: ?api.HostAction = null,
    /// Two-phase plan: the arena grows over main_resident before this job.
    phase_b: bool = false,
    done: BatchDep = .{},
    result: anyerror!void = {},
    receipt: api.Receipt = .{},
    settled: bool = false,
};

pub const BatchHook = struct {
    ctx: *anyopaque,
    run: *const fn (*anyopaque, *Worker) anyerror!void,
};

pub const Batch = struct {
    jobs: []BatchJob,
    parity: u1 = 0,
    /// Request batches may only adopt class resources warmed at install.
    /// Refuse a miss before allocation, placement, eviction or host fill.
    require_warm_persistent: bool = false,
    /// Before the first job (slab prefix upload, unset memset, start event).
    preamble: ?BatchHook = null,
    /// After the last job (slab D2H, cross-GPU completion, final event).
    tail: ?BatchHook = null,
    result: anyerror!void = {},
    enqueue_ns: u64 = 0,
    /// Time the worker thread spent on host latches (capture/peer records).
    gate_wait_ns: u64 = 0,
    /// Neighbour staging deferred because its inputs do not fit beside the
    /// current class peak. Ordering is by device event, never a host wait.
    memory_serializations: u64 = 0,
    pinned_used: usize = 0,
    slots_used: usize = 0,
    slots: []Slot = &.{},
};

test {
    _ = @import("worker_test.zig");
    _ = @import("worker_service_test.zig");
}
