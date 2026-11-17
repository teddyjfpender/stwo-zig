//! Canonical worker records and per-slot/batch custody; callbacks retain stable Worker userdata.
const std = @import("std");
const api = @import("api.zig");
const Channel = @import("channel.zig");
const Slab = @import("slab.zig");
const MP = @import("plan.zig");

const Worker = @import("worker.zig").Worker;
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
pub const Slot = struct {
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
