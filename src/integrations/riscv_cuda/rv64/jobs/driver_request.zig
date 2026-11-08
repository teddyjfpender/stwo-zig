//! M8 GPU-native request driver (stream: driver; rv64-m8-gpu-native.md §1, §3.4-§3.8).
//!
//! Install (once per service, never per request):
//!   factories warm every class into the ClassCache, which is then sealed (a
//!   miss on a request fails closed); one two-phase MemoryPlan per GPU
//!   (driver_memory.zig) becomes ONE arena+main_resident block per GPU
//!   (worker.installPlanArena) plus two request-slab segments (pipelined
//!   parities) and their pinned mirrors; batch slots/events and peer events
//!   are created; peer access is enabled.
//!
//! Request (`begin` + `finish`):
//!   host plan (µs): classes -> DAG + placement (driver_dag.zig) -> slab layout
//!   (gpu_native.RequestLayout) -> per-GPU batches of factory jobs;
//!   preamble per GPU: header and directory h2d from the pinned mirror (two
//!   copies around the exchange), status words := unset, encoded lengths :=
//!   0 (device fills), start event. The exchange replica is NOT zeroed per
//!   request: a consumer GPU's fill is not ordered against a producer GPU's
//!   peer copy (with two requests in flight the fill runs after the
//!   consumer's previous request and would erase slots that already landed).
//!   Flags carry the request's Exchange.flagTag instead, and the exchange
//!   sits at a fixed offset with install-capacity offsets, so a flag word
//!   only ever holds a flag; install zeroes every slab once;
//!   every job enqueued back to back with device-side dependencies
//!   (cross-GPU done events; peer slots through driver_peer.zig); Stage1(seg)
//!   released by the capture stream as each segment seals;
//!   tail per GPU: the completion word := flagTag on the device, then one
//!   D2H of the whole slab segment into its pinned mirror;
//!   non-final GPUs record their done event; the final (seal) GPU waits for
//!   them on the device, runs Check.exchange_complete over its replica's
//!   flags, D2Hs its segment, records the final event;
//!   ONE host wait (the final event), phase 3 of every job without a wait,
//!   `gpu_native.publish` over the mirrors (status words + slicing).
//!
//! The host never reads a device value before the single wait, and never
//! calls cudaMalloc on the request path (D1, driver_test.zig).
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const W = @import("worker.zig");
const O = @import("ops.zig");
const D = @import("driver_dag.zig");
const M = @import("driver_memory.zig");
const Memory = @import("memory_plan.zig");
const P = @import("driver_peer.zig");
const C = @import("../m8_capture_stream.zig");

pub const Config = struct {
    /// Device capacity cap in words per driver device (index = worker
    /// index). The plan uses min(cap, memory measured at install: free +
    /// what the worker and the class cache already hold) when the base image
    /// exports memory_info.
    capacity_words: []const u64,
    /// Largest native segment count / truths / jobs per GPU per request.
    max_segments: u32,
    /// Largest truth count per request (two-stage truths' exchange slots).
    max_truths: u32 = 16,
    /// False only for a protocol whose seal consumes the full manifest
    /// directly. Every root/claim/receipt/truth/child/seal flag stays required.
    exchange_partials: bool = true,
    max_jobs_per_device: usize = 256,
    /// Pinned pool per parity for jobs that stage from pinned memory (GPU-native jobs: 0).
    batch_pinned_words: usize = 0,
    /// Request slab segment words per GPU (one parity), from the warm class mix.
    slab_words: u64,
    seal_device: u32 = 0,
    reserve_words: u64 = M.default_reserve_words,
    graph_exec_words: u64 = M.default_graph_exec_words,
    /// Cap the arena (0 = everything left in the plan).
    arena_cap_words: u64 = 0,
    /// Class arena peaks the plan must hold, at least (the plan always takes
    /// the max with the warmed classes' `arena_peak_words`: phase A over
    /// classes without `phase_b`, phase B over every class).
    phase_a_peak_words: u64 = 0,
    phase_b_peak_words: u64 = 0,
    /// main_resident capacity per GPU (0 = ceil(max_segments / devices) x
    /// the largest native class: what placement can put on one GPU).
    main_resident_words: u64 = 0,
    /// stwo_exec_context_pool_current (used, reserved bytes of the device
    /// arena / pool): its free part counts toward the plan capacity.
    pool_current: ?*const fn (*anyopaque, *usize, *usize) callconv(.c) c_int = null,
    /// A fixed device arena cannot grow into cudaMemGetInfo's free bytes.
    /// The plan's reserve also covers its small slab and chunk rounding.
    fixed_pool: bool = false,
    /// Materialize address-independent resources before planning, so shared
    /// persistent keys are charged once from their actual allocation census.
    prewarm_resources: bool = false,
    /// Fixed part of the request pseudo-proof's stage-one region (bytes),
    /// added when any native class declares `stage_one_bytes`.
    stage_one_base_bytes: usize = G.stage_one_base_bytes,
};

/// One request as the service hands it over (host shape; class keys come
/// from the factories).
pub const Request = struct {
    id: u64,
    /// Rows per native segment (geometry known at plan time; the capture
    /// stream must be `prepare`d with exactly these and checks every sealed
    /// segment against them, see m8_capture_stream).
    segment_rows: []const u64,
    truths: u32 = 0,
    truth_after_seal: bool = false,
    /// Recursion topology, children before parents, root last (ready_dag order).
    recursion: []const D.RecursionNode = &.{},
    root: u32 = 0,
    capture: ?*C.Stream = null,
    /// Service block number (handed to the publish hooks).
    block: u64 = 0,
    /// Output directory: when set, after the single wait the factories'
    /// `publish` hooks write their artifacts there (native, then recursion).
    out: ?std.fs.Dir = null,
};

pub const Published = struct { id: G.ProofId, bytes: []u8 };

pub const Receipt = struct {
    request: u64 = 0,
    generation: u64 = 0,
    host_waits: u32 = 0,
    d2h: u32 = 0,
    d2h_bytes: u64 = 0,
    /// Driver counters, not a CUDA census. Peer transport may stage via host.
    transfer_scope: []const u8 = "d2h counts final request slabs; job_slab_d2h counts private job readbacks; excludes peer transport",
    job_slab_d2h: u32 = 0,
    job_slab_d2h_bytes: u64 = 0,
    host_callbacks: u32 = 0,
    capture_release_callbacks: u32 = 0,
    job_receipts_complete: bool = false,
    h2d: u32 = 0,
    jobs: u32 = 0,
    plan_ns: u64 = 0,
    make_ns: u64 = 0,
    /// Host time to enqueue every batch (both GPUs in parallel; includes the
    /// capture gates, so it overlaps capture).
    enqueue_ns: u64 = 0,
    /// Per device: worker-thread enqueue time and time on host latches.
    device_enqueue_ns: [G.max_devices]u64 = @splat(0),
    device_gate_ns: [G.max_devices]u64 = @splat(0),
    device_memory_serializations: [G.max_devices]u64 = @splat(0),
    /// CUDA-event GPU span per device: preamble start -> slab D2H end [M].
    device_gpu_us: [G.max_devices]u64 = @splat(0),
    wait_ns: u64 = 0,
    finish_ns: u64 = 0,
    publish_ns: u64 = 0,
    /// Host time of the factories' publish hooks (artifact files) [M].
    publish_files_ns: u64 = 0,
    /// Stage-one bytes the seal job encoded (request pseudo-proof region).
    stage_one_bytes: u64 = 0,
    /// Truth jobs gated on the capture's end (needs_capture_end).
    capture_end_gated: u32 = 0,
    /// Host time spent after the device wait confirming the capture ended
    /// cleanly (Stream.awaitCaptured; normally ~0: capture ends first) [M].
    capture_wait_ns: u64 = 0,
    peer_publishes: u64 = 0,
    peer_copies: u64 = 0,
    slab_words: [G.max_devices]u64 = @splat(0),
    root_device: u32 = 0,
    final_device: u32 = 0,
    peer_direct: bool = false,
};

pub const Outcome = struct {
    a: std.mem.Allocator,
    proofs: []Published,
    receipt: Receipt,
    pub fn deinit(self: *Outcome) void {
        for (self.proofs) |p| self.a.free(p.bytes);
        self.a.free(self.proofs);
    }
};

const Lane = struct {
    worker: *W.Worker,
    plan: M.Planned = undefined,
    main: api.DeviceBuffer = undefined,
    slab: [2]api.DeviceBuffer = undefined,
    mirror: [2][]u32 = .{ &.{}, &.{} },
    done_event: [2]?*anyopaque = .{ null, null },
    start_event: [2]?*anyopaque = .{ null, null },
    end_event: [2]?*anyopaque = .{ null, null },
    slab_allocated: bool = false,
};

pub const Driver = struct {
    a: std.mem.Allocator,
    ops: *const O.Ops,
    peer_ops: *const O.Peer,
    native: G.NativeFactory,
    recursion: G.RecursionFactory,
    classes: G.ClassCache,
    config: Config,
    lanes: []Lane,
    peer: P.Peer,
    generation: u64 = 0,
    in_flight: [2]?*InFlight = .{ null, null },
    /// Next parity tried first (alternates; a failed begin never wastes one).
    next_parity: u1 = 0,
    installed: bool = false,
    resources_warmed: bool = false,
    resident_words: [G.max_devices]u64 = @splat(0),
    /// A device fault (sticky CUDA error) or a teardown: no request begins again.
    poisoned: bool = false,
    /// Install capacities of the exchange (fixed offsets for every request).
    exchange_cap: G.Exchange = .{ .segments = 0, .claims_per_segment = 0, .devices = 0 },
    /// Device allocations made by install (accounting for D1).
    install_allocations: usize = 0,
    /// Every GPU pair maps the other's memory (direct peer pointers). False on
    /// the M8 pod (5090s behind a chipset without P2P [M]): peer copies still
    /// work (staged through the host), direct cross-GPU reads do not.
    peer_direct: bool = false,

    /// Install over already-created workers (one per GPU, index = driver
    /// device). Warm both factories, seal the class cache, plan memory,
    /// allocate everything a request needs.
    pub fn install(a: std.mem.Allocator, ops: *const O.Ops, peer_ops: *const O.Peer, workers: []const *W.Worker, native: G.NativeFactory, recursion: G.RecursionFactory, config: Config) !*Driver {
        if (workers.len == 0 or workers.len > G.max_devices) return error.GpuNativeNoDevices;
        if (config.capacity_words.len != workers.len) return error.GpuNativeCapacityShape;
        if (config.seal_device >= workers.len) return error.GpuNativeSealDeviceOutOfRange;
        const self = try a.create(Driver);
        errdefer a.destroy(self);
        self.* = .{ .a = a, .ops = ops, .peer_ops = peer_ops, .native = native, .recursion = recursion, .classes = G.ClassCache.init(a), .config = config, .lanes = try a.alloc(Lane, workers.len), .peer = .{ .exec = &ops.exec, .peer = peer_ops, .devices = @intCast(workers.len) } };
        errdefer {
            self.classes.deinit();
            a.free(self.lanes);
        }
        for (self.lanes, workers) |*l, w| l.* = .{ .worker = w };
        // 1. classes (install time only). Sealed after the `installed` hooks
        // below: graphs that bake arena addresses are captured only once the
        // plan arena exists (warm runs on the worker's pre-plan arena, which
        // installPlanArena frees).
        try native.vtable.warm(native.ctx, &self.classes);
        try recursion.vtable.warm(recursion.ctx, &self.classes);
        if (native.vtable.batch_pinned_words) |h| self.config.batch_pinned_words = @max(self.config.batch_pinned_words, try h(native.ctx));
        var peaks = self.classPeaks();
        if (config.prewarm_resources) {
            errdefer for (workers) |w| {
                _ = w.park(.{}) catch {};
            };
            const nr = native.vtable.resources orelse return error.GpuNativeResourceWarmHookMissing;
            const rr = recursion.vtable.resources orelse return error.GpuNativeResourceWarmHookMissing;
            // Immutable warming owns a source-derived window, not an old
            // request arena. Its resources survive both control operations.
            const Census = struct {
                words: u64 = 0,
                fn run(raw: *anyopaque, worker: *W.Worker) anyerror!void {
                    const census: *@This() = @ptrCast(@alignCast(raw));
                    census.words = worker.persistentWords();
                }
                fn read(worker: *W.Worker) !u64 {
                    var census = @This(){};
                    try worker.call(.{ .ctx = &census, .run = run });
                    return census.words;
                }
            };
            var resource_words: u64 = 0;
            var entries = self.classes.map.valueIterator();
            while (entries.next()) |entry| resource_words = @max(resource_words, entry.*.resource_words orelse entry.*.arena_peak_words);
            const temporary = try Memory.alignedWords(@max(resource_words, 64));
            for (workers) |w| _ = try w.park(.{});
            for (workers, 0..) |w, d| {
                const resident = try Census.read(w);
                // Future class reservations may overlap existing resources;
                // count both conservatively until the final census deduplicates.
                const classes = try Memory.addWords(resident, try self.classCacheWords(@intCast(d)));
                const owned = try Memory.addWords(classes, try Memory.addWords(config.reserve_words, config.graph_exec_words));
                if (owned >= config.capacity_words[d] or temporary > config.capacity_words[d] - owned) return error.GpuNativeResourceWarmNoWorkspace;
            }
            for (workers) |w| _ = try w.unpark(@intCast(temporary));
            try nr(native.ctx, &self.classes, @intCast(workers.len));
            try rr(recursion.ctx, &self.classes, @intCast(workers.len));
            for (workers, 0..) |w, d| {
                self.resident_words[d] = try Census.read(w);
                _ = try w.park(.{});
                std.debug.print("GPU_M9_RESIDENT_CENSUS device={d} persistent_words={d} allocations_materialized=1\n", .{ d, self.resident_words[d] });
            }
            // Every temporary arena is retired before observing the shared
            // fixed pool. Resident class allocations are already charged.
            if (recursion.vtable.resource_probe) |probe| {
                var windows: [G.max_devices]usize = undefined;
                for (workers, 0..) |w, d| {
                    const Window = struct {
                        fixed: bool,
                        pool: @FieldType(Config, "pool_current"),
                        words: u64 = 0,
                        fn run(raw: *anyopaque, worker: *W.Worker) anyerror!void {
                            const out: *@This() = @ptrCast(@alignCast(raw));
                            if (!out.fixed) {
                                const info = worker.ops.exec.memory_info orelse return error.GpuNativePoolCapacityUnavailable;
                                var free: usize = 0;
                                var total: usize = 0;
                                try O.check(info(worker.context, &free, &total));
                                if (free > total) return error.InvalidPhysicalArenaSnapshot;
                                var used: usize = 0;
                                var reserved: usize = 0;
                                if (out.pool) |pool| try O.check(pool(worker.context, &used, &reserved));
                                if (used > reserved) return error.InvalidPhysicalArenaSnapshot;
                                out.words = try M.allocationCapacity(free / 4, (reserved - used) / 4, 0, false);
                                return;
                            }
                            const query = worker.ops.exec.arena_snapshot orelse return error.MissingWorkspaceArenaObservation;
                            var snapshot: O.RuntimeMemory.Snapshot = .{};
                            try O.check(query(worker.context, &snapshot));
                            if (snapshot.device != worker.device_ordinal) return error.InvalidPhysicalArenaSnapshot;
                            const available = try snapshot.available();
                            const bytes = @min(available.large, snapshot.largest_virtual_free);
                            if (bytes <= snapshot.chunk) return error.GpuNativeResourceProbeNoWorkspace;
                            // One physical chunk remains outside the probe;
                            // small-slab and cudaMemGetInfo are never credited.
                            out.words = (bytes - snapshot.chunk) / 4;
                            if (out.words == 0) return error.GpuNativeResourceProbeNoWorkspace;
                        }
                    };
                    var window = Window{ .fixed = config.fixed_pool, .pool = config.pool_current };
                    try w.call(.{ .ctx = &window, .run = Window.run });
                    const reserve = try Memory.addWords(config.reserve_words, config.graph_exec_words);
                    if (!config.fixed_pool) window.words = std.math.sub(u64, window.words, reserve) catch return error.GpuNativeResourceProbeNoWorkspace;
                    const owned = try Memory.addWords(self.resident_words[d], reserve);
                    if (owned >= config.capacity_words[d]) return error.GpuNativeResourceProbeNoWorkspace;
                    windows[d] = @intCast(std.mem.alignBackward(u64, @min(window.words, config.capacity_words[d] - owned), 64));
                    if (windows[d] == 0) return error.GpuNativeResourceProbeNoWorkspace;
                }
                for (workers, 0..) |w, d| {
                    _ = try w.unpark(windows[d]);
                    std.debug.print("GPU_M9_RESOURCE_PROBE device={d} arena_words={d} fixed_pool={}\n", .{ w.device_ordinal, windows[d], config.fixed_pool });
                }
                try probe(recursion.ctx, &self.classes);
                for (workers) |w| _ = try w.park(.{});
            }
            for (workers) |w| _ = try w.unpark(1 << 16);
            self.resources_warmed = true;
            // Resource hooks may replace estimated class bounds with install
            // measurements. Admission must use those updated cache entries.
            peaks = self.classPeaks();
        }
        // 2. peer access + per-GPU resources on each worker thread
        var ordinals: [G.max_devices]u32 = undefined;
        for (workers, 0..) |w, d| {
            ordinals[d] = w.device_ordinal;
            self.peer.ordinals[d] = w.device_ordinal;
        }
        var direct: u32 = 1;
        if (workers.len > 1) try O.check(peer_ops.peer_enable(&ordinals, @intCast(workers.len), &direct));
        self.peer_direct = direct == 1;
        const claims_cap = @max(1, self.maxClaims());
        const truth_cap: u32 = if (recursion.vtable.truth_stage2 != null) config.max_truths else 0;
        const wire_cap = self.maxLocalWire();
        self.exchange_cap = .{ .segments = config.max_segments, .claims_per_segment = claims_cap, .devices = @intCast(workers.len), .capacity_segments = config.max_segments, .capacity_claims = claims_cap, .partials_enabled = config.exchange_partials, .truths = truth_cap, .capacity_truths = truth_cap, .receipts = wire_cap != 0, .child_wire_words = wire_cap };
        try self.peer.reserve(a, self.exchange_cap.flagCapacity());
        errdefer self.peer.deinitHost(a);
        const largest_main = try Memory.alignedWords(self.largestNativeMain());
        // Placement puts at most ceil(S / devices) segments' MAIN on one GPU
        // when every GPU's region holds that many (LPT, capacity-bounded).
        const per_gpu_segments = std.math.divCeil(u64, config.max_segments, workers.len) catch unreachable;
        // Lanes whose Setup started (a failed Setup is released too: Release
        // frees exactly what was allocated).
        var attempted: usize = 0;
        errdefer for (self.lanes[0..attempted]) |*l| self.releaseLane(l);
        for (self.lanes, 0..) |*l, d| {
            const main_words = if (config.main_resident_words != 0) config.main_resident_words else std.math.mul(u64, largest_main, per_gpu_segments) catch return error.ResourceSizeOverflow;
            const class_words = try self.classCacheWords(@intCast(d));
            const capacity = try self.measuredCapacity(l.worker, config.capacity_words[d], d);
            const inputs = M.Inputs{ .device = @intCast(d), .capacity_words = capacity, .class_cache_words = class_words, .graph_exec_words = config.graph_exec_words, .main_resident_words = main_words, .phase_a_peak_words = @max(config.phase_a_peak_words, peaks[0]), .phase_b_peak_words = @max(config.phase_b_peak_words, peaks[1]), .slab_words = config.slab_words, .reserve_words = config.reserve_words, .arena_cap_words = config.arena_cap_words };
            l.plan = M.plan(inputs) catch |err| {
                std.log.warn("M8 GPU-native memory plan device {d}: {s} (capacity {d} words; class cache {d}, main_resident {d}, phase A/B peaks {d}/{d}, slab 2x{d}, graph {d}, reserve {d})", .{ d, @errorName(err), capacity, class_words, main_words, inputs.phase_a_peak_words, inputs.phase_b_peak_words, config.slab_words, config.graph_exec_words, config.reserve_words });
                return err;
            };
            var setup = Setup{ .driver = self, .lane = l, .device = @intCast(d) };
            attempted += 1;
            try l.worker.call(.{ .ctx = &setup, .run = Setup.run });
        }
        // 3. per-class captures over the installed plan, then seal.
        var info = G.Installed{ .devices = @intCast(workers.len) };
        for (self.lanes, 0..) |l, d| {
            info.main_resident[d] = l.main;
            info.arena_epochs[d] = l.worker.planPhaseEpochs();
        }
        if (native.vtable.installed) |hook| try hook(native.ctx, &self.classes, &info);
        if (recursion.vtable.installed) |hook| try hook(recursion.ctx, &self.classes, &info);
        self.classes.seal();
        self.installed = true;
        return self;
    }

    /// Teardown. A request still in flight (begun, never finished) is
    /// quiesced and aborted first: no slab, mirror or event is freed while a
    /// GPU still D2Hs into it or peer-copies into its replica.
    pub fn deinit(self: *Driver) void {
        self.poisoned = true;
        for (&self.in_flight) |*slot| if (slot.*) |f| {
            f.quiesce();
            f.abortAll();
            f.release();
            self.a.destroy(f);
            slot.* = null;
        };
        for (self.lanes) |*l| self.releaseLane(l);
        self.peer.deinitHost(self.a);
        self.classes.deinit();
        self.a.free(self.lanes);
        self.a.destroy(self);
    }

    fn largestNativeMain(self: *Driver) u64 {
        var best: u64 = 0;
        self.classes.mutex.lock();
        defer self.classes.mutex.unlock();
        var it = self.classes.map.valueIterator();
        while (it.next()) |e| best = @max(best, e.*.main_resident_words);
        return best;
    }
    fn maxLocalWire(self: *Driver) usize {
        var words: usize = 0;
        self.classes.mutex.lock();
        defer self.classes.mutex.unlock();
        var it = self.classes.map.valueIterator();
        while (it.next()) |entry| words = @max(words, entry.*.local_gkr_wire_words);
        return words;
    }
    fn maxClaims(self: *Driver) u32 {
        var best: u32 = 0;
        self.classes.mutex.lock();
        defer self.classes.mutex.unlock();
        var it = self.classes.map.valueIterator();
        while (it.next()) |e| best = @max(best, e.*.claims_per_segment);
        return best;
    }
    /// Arena peaks of the warmed classes: [phase A (classes without
    /// `phase_b`), phase B (every class)].
    fn classPeaks(self: *Driver) [2]u64 {
        var out: [2]u64 = .{ 0, 0 };
        self.classes.mutex.lock();
        defer self.classes.mutex.unlock();
        var it = self.classes.map.valueIterator();
        while (it.next()) |e| {
            out[0] = @max(out[0], e.*.phase_a_peak_words);
            if (!e.*.phase_b) out[0] = @max(out[0], e.*.arena_peak_words);
            out[1] = @max(out[1], e.*.arena_peak_words);
            // Install receipt: which class sets the plan's arena peaks.
            std.log.info("M8 GPU-native class {x} arena_peak_words={d} phase_b={} main_resident_words={d}", .{ e.*.key[0..6].*, e.*.arena_peak_words, e.*.phase_b, e.*.main_resident_words });
        }
        return out;
    }
    /// Every device word the class cache holds on `device`: the entries'
    /// `device` buffers, what the factories report holding outside them,
    /// and the worker's persistent pool.
    fn classCacheWords(self: *Driver, device: u32) !u64 {
        if (self.resources_warmed) return self.resident_words[device];
        var n: u64 = 0;
        self.classes.mutex.lock();
        defer self.classes.mutex.unlock();
        var it = self.classes.map.valueIterator();
        while (it.next()) |e| {
            if (e.*.device[device]) |b| n = try Memory.addWords(n, b.words);
            n = try Memory.addWords(n, e.*.held_words[device]);
        }
        return Memory.addWords(n, self.lanes[device].worker.config.persistent_budget_words);
    }
    /// Only the pre-plan arena is known to be reclaimable. held_words is a
    /// class's future reservation, not evidence of a live device allocation:
    /// installed() uploads those classes AFTER this plan is allocated.
    fn measuredCapacity(self: *Driver, w: *W.Worker, cap_words: u64, device_index: usize) !u64 {
        if (self.config.fixed_pool and (self.config.pool_current == null or self.ops.exec.memory_info == null)) return error.GpuNativePoolCapacityUnavailable;
        const info = self.ops.exec.memory_info orelse return cap_words;
        const Q = struct {
            info: *const fn (*anyopaque, *usize, *usize) callconv(.c) c_int,
            free: usize = 0,
            total: usize = 0,
            fn run(raw: *anyopaque, wk: *W.Worker) anyerror!void {
                const q: *@This() = @ptrCast(@alignCast(raw));
                try O.check(q.info(wk.context, &q.free, &q.total));
            }
        };
        var q = Q{ .info = info };
        try w.call(.{ .ctx = &q, .run = Q.run });
        // A device arena carved at context creation (STWO_RV64_DEVICE_ARENA
        // =auto, the M5 platform default) leaves cudaMemGetInfo ~0 free while
        // every allocation of this process is served from the carve: its
        // unused part is capacity too. [M] gn-bind rev4 26235156: free-only
        // measured 0.82G words on a 30 GB carve.
        var pooled: u64 = 0;
        if (self.config.pool_current) |pc| {
            const PoolQ = struct {
                f: *const fn (*anyopaque, *usize, *usize) callconv(.c) c_int,
                used: usize = 0,
                reserved: usize = 0,
                fn run(raw: *anyopaque, wk: *W.Worker) anyerror!void {
                    const pq: *@This() = @ptrCast(@alignCast(raw));
                    try O.check(pq.f(wk.context, &pq.used, &pq.reserved));
                }
            };
            var pq = PoolQ{ .f = pc };
            try w.call(.{ .ctx = &pq, .run = PoolQ.run });
            if (pq.reserved > pq.used) pooled = (pq.reserved - pq.used) / 4;
        }
        // Already-live persistent allocations belong to the class_cache
        // region. Add them back to capacity once, then plan() charges that
        // same census once; they are not reclaimable workspace.
        const resident = if (self.resources_warmed) self.resident_words[device_index] else 0;
        const owned = std.math.add(u64, w.arenaWords(), resident) catch return error.ResourceSizeOverflow;
        const measured = try M.allocationCapacity(q.free / 4, pooled, owned, self.config.fixed_pool);
        if (measured < cap_words) std.log.info("M8 GPU-native device {d}: plan capacity {d} words measured (cap {d})", .{ w.device_ordinal, measured, cap_words });
        return @min(cap_words, measured);
    }

    const Setup = struct {
        driver: *Driver,
        lane: *Lane,
        device: u32,
        fn run(raw: *anyopaque, w: *W.Worker) anyerror!void {
            const s: *Setup = @ptrCast(@alignCast(raw));
            const self = s.driver;
            const l = s.lane;
            const ex = &self.ops.exec;
            const wt = &self.ops.wait;
            // lint:install-begin — every device/pinned allocation and event of a request.
            try w.reserveTimingPairs(self.config.max_segments, self.peer_ops.event_create_timed);
            l.main = try w.installPlanArena(@intCast(l.plan.phase_a_words), @intCast(l.plan.phase_b_words));
            self.install_allocations += 1;
            var slab: ?[*]u32 = null;
            try O.check(ex.alloc_u32_long(w.context, @intCast(2 * l.plan.slab_words), &slab));
            self.install_allocations += 1;
            l.slab_allocated = true;
            const half: usize = @intCast(l.plan.slab_words);
            l.slab = .{ .{ .ptr = slab.?, .words = half }, .{ .ptr = slab.? + half, .words = half } };
            for (0..2) |p| {
                var host: ?*anyopaque = null;
                try O.check(wt.host_alloc(half * 4, &host));
                l.mirror[p] = @as([*]u32, @ptrCast(@alignCast(host.?)))[0..half];
                try O.check(wt.event_create(&l.done_event[p]));
                try O.check(self.peer_ops.event_create_timed(&l.start_event[p]));
                try O.check(self.peer_ops.event_create_timed(&l.end_event[p]));
            }
            try w.reserveBatches(self.config.max_jobs_per_device, self.config.batch_pinned_words);
            self.peer.streams[s.device] = w.execStream();
            for (self.peer.events[s.device]) |*e| try O.check(wt.event_create(e));
            // lint:install-end
            // Both slab parities zeroed once, and waited here (install, not a
            // request): no flag word ever holds cudaMalloc garbage, and no
            // peer copy of a first request can race this fill.
            try O.check(self.peer_ops.fill_u32(slab.?, 0, 2 * half, w.execStream()));
            try O.check(ex.event_record(l.done_event[0].?, w.execStream()));
            _ = try w.requestWait(l.done_event[0].?);
        }
    };

    fn releaseLane(self: *Driver, l: *Lane) void {
        var r = Release{ .driver = self, .lane = l };
        l.worker.call(.{ .ctx = &r, .run = Release.run }) catch {};
    }
    const Release = struct {
        driver: *Driver,
        lane: *Lane,
        fn run(raw: *anyopaque, w: *W.Worker) anyerror!void {
            const r: *Release = @ptrCast(@alignCast(raw));
            const l = r.lane;
            const wt = &r.driver.ops.wait;
            // Nothing enqueued on this GPU may still read what is freed below.
            if (l.done_event[0]) |ev| {
                if (r.driver.ops.exec.event_record(ev, w.execStream()) == 0) _ = w.requestWait(ev) catch {};
            }
            w.uninstallPlanArena() catch |err| std.log.err("M8 GPU-native teardown: plan arena free failed: {s}", .{@errorName(err)});
            if (l.slab_allocated) _ = r.driver.ops.exec.free_u32(w.context, l.slab[0].ptr);
            l.slab_allocated = false;
            for (0..2) |p| {
                if (l.mirror[p].len != 0) _ = wt.host_free(l.mirror[p].ptr);
                l.mirror[p] = &.{};
                inline for (.{ &l.done_event[p], &l.start_event[p], &l.end_event[p] }) |e| if (e.*) |ev| {
                    _ = wt.event_destroy(ev);
                    e.* = null;
                };
            }
            const d = std.mem.indexOfScalar(?*anyopaque, &r.driver.peer.streams, w.execStream()) orelse return;
            for (r.driver.peer.events[d]) |*e| if (e.*) |ev| {
                _ = wt.event_destroy(ev);
                e.* = null;
            };
        }
    };

    // ---------------------------------------------------------------------
    // Request
    // ---------------------------------------------------------------------

    pub fn serve(self: *Driver, req: *const Request) !Outcome {
        const f = try self.begin(req);
        return self.finish(f);
    }

    /// Plan, make every job and enqueue both GPUs' batches. Returns once
    /// everything is enqueued (it overlaps capture through the Stage1 gates);
    /// at most two requests are in flight (slab/mirror parities).
    pub fn begin(self: *Driver, req: *const Request) !*InFlight {
        if (!self.installed) return error.GpuNativeDriverNotInstalled;
        // A capture stream belongs to one in-flight request: its gates, ctx
        // attachment and ring buffers are per request (the service rotates
        // one stream per parity). Never touch a stream the other holds.
        if (req.capture) |cap| for (self.in_flight) |o| if (o) |other| if (other.req.capture == cap) return error.GpuNativeCaptureStreamInFlight;
        // Refused before planning: the request's capture (prepared by the
        // service, maybe already running) is cancelled and detached.
        errdefer if (req.capture) |cap| cap.detach();
        if (self.poisoned) return error.GpuNativeDriverPoisoned;
        // The parity is a free slot, independent of the generation: a begin
        // that fails never costs the pipeline its overlap.
        const parity: u1 = if (self.in_flight[self.next_parity] == null) self.next_parity else if (self.in_flight[self.next_parity ^ 1] == null) self.next_parity ^ 1 else return error.GpuNativePipelineFull;
        self.generation += 1;
        const f = try self.a.create(InFlight);
        errdefer self.a.destroy(f);
        f.* = .{ .driver = self, .parity = parity, .generation = self.generation, .req = req.* };
        f.receipt.request = req.id;
        f.receipt.generation = self.generation;
        // From here the capture belongs to `f`: release detaches it.
        f.owns_capture = true;
        errdefer f.release();
        if (self.native.vtable.begin_request) |h| try h(self.native.ctx, req.block, req.id, self.generation);
        try f.plan();
        if (self.native.vtable.planned) |h| try h(self.native.ctx, &f.ctx);
        try f.make();
        f.run() catch |err| {
            // Error path only: whatever this request enqueued (job kernels,
            // peer copies into other GPUs' slabs, mirror D2Hs, capture host
            // fns) completes BEFORE the jobs abort (an abort may free memory
            // that enqueued work still reads) and before this parity is reused.
            f.quiesce();
            f.abortAll();
            return err;
        };
        self.in_flight[parity] = f;
        self.next_parity = parity ^ 1;
        return f;
    }

    /// The request's ONE host wait, phase 3 of every job, publication.
    pub fn finish(self: *Driver, f: *InFlight) !Outcome {
        defer {
            self.in_flight[f.parity] = null;
            f.release();
            self.a.destroy(f);
        }
        return f.complete();
    }
};

pub const InFlight = struct {
    driver: *Driver,
    parity: u1,
    generation: u64,
    req: Request,
    arena: std.heap.ArenaAllocator = undefined,
    arena_live: bool = false,
    dag: ?D.Dag = null,
    layout: ?G.RequestLayout = null,
    exchange: G.Exchange = undefined,
    ctx: G.RequestContext = undefined,
    segment_buffers: []api.DeviceBuffer = &.{},
    main_views: []api.DeviceBuffer = &.{},
    segment_device: []u32 = &.{},
    /// Per node index: (device, position in that device's batch).
    where: []Where = &.{},
    batches: []W.Batch = &.{},
    hooks: []Hook = &.{},
    truth_classes: []*const G.ClassEntry = &.{},
    receipt: Receipt = .{},
    ran: bool = false,
    /// `release` detaches the capture (set once begin owns it).
    owns_capture: bool = false,
    /// Host latch per non-final GPU: its tail recorded its done event.
    tail_done: [G.max_devices]std.Thread.ResetEvent = @splat(.{}),
    /// Completion of each non-final GPU's posted batch (no per-request thread).
    posted: [G.max_devices]W.CallDone = @splat(.{}),

    const Hook = struct { f: *InFlight, device: u32 };
    const Where = struct { device: u32, pos: u32 };

    fn alloc(self: *InFlight) std.mem.Allocator {
        return self.arena.allocator();
    }

    fn release(self: *InFlight) void {
        if (self.owns_capture) if (self.req.capture) |cap| cap.detach();
        self.owns_capture = false;
        if (!self.arena_live) return;
        if (self.layout) |*l| l.deinit();
        self.layout = null;
        if (self.dag) |*d| d.deinit();
        self.dag = null;
        self.arena.deinit();
        self.arena_live = false;
    }

    fn plan(self: *InFlight) !void {
        var timer = std.time.Timer.start() catch unreachable;
        defer self.receipt.plan_ns = timer.read();
        const drv = self.driver;
        self.arena = std.heap.ArenaAllocator.init(drv.a);
        self.arena_live = true;
        const a = self.alloc();
        const req = &self.req;
        const S = req.segment_rows.len;
        if (S == 0 or S > drv.config.max_segments) return error.GpuNativeSegmentsExceedPlan;
        const devices: u32 = @intCast(drv.lanes.len);
        // classes (fail closed on a miss: never built on the request path)
        const native_cls = try a.alloc(*const G.ClassEntry, S);
        const native_keys = try a.alloc(G.ClassKey, S);
        var claims: u32 = 1;
        const segs = try a.alloc(D.Segment, S);
        const ring_words: ?u64 = if (req.capture) |cap| if (cap.ring) |r| r.capacityWords() else null else null;
        for (req.segment_rows, 0..) |rows, s| {
            native_keys[s] = if (drv.native.vtable.class_of_block) |cob| try cob(drv.native.ctx, self.req.block, @intCast(s), rows) else try drv.native.vtable.class_of(drv.native.ctx, @intCast(s), rows);
            native_cls[s] = try drv.classes.get(native_keys[s]);
            claims = @max(claims, native_cls[s].claims_per_segment);
            // A segment the ring cannot hold would deadlock its own capture
            // (its buffers return only after its Stage1, gated on its seal).
            if (ring_words) |rw| if (native_cls[s].capture_words > rw) return error.GpuNativeCaptureRingTooSmall;
            segs[s] = .{ .main_words = native_cls[s].main_resident_words, .stage1_cost = native_cls[s].cost_us, .stage2_cost = native_cls[s].cost_us };
        }
        const truths = try a.alloc(D.Truth, req.truths);
        const truth_cls = try a.alloc(*const G.ClassEntry, req.truths);
        const truth_keys = try a.alloc(G.ClassKey, req.truths);
        for (truths, 0..) |*t, i| {
            truth_keys[i] = try drv.recursion.vtable.class_of(drv.recursion.ctx, .{ .kind = .truth, .ordinal = @intCast(i) }, &.{});
            truth_cls[i] = try drv.classes.get(truth_keys[i]);
            t.* = .{ .cost = truth_cls[i].cost_us };
        }
        const rec = try a.dupe(D.RecursionNode, req.recursion);
        const shape_probe = D.Shape{ .devices = devices, .segments = segs, .recursion = rec, .root = req.root };
        const node_cls = try a.alloc(*const G.ClassEntry, rec.len);
        const node_keys = try a.alloc(G.ClassKey, rec.len);
        for (rec, 0..) |*rn, id| {
            const kind = D.recursionKind(shape_probe, @intCast(id));
            // The node's authority: the classes of what it verifies (children
            // before parents, so every child key is known here).
            const children = try a.alloc(G.ClassKey, rn.segments.len + rn.truths.len + rn.children.len);
            for (rn.segments, 0..) |sg, k| {
                if (sg >= S) return error.GpuNativeTopologySegment;
                children[k] = native_keys[sg];
            }
            for (rn.truths, rn.segments.len..) |t, k| {
                if (t >= req.truths) return error.GpuNativeTopologyTruth;
                children[k] = truth_keys[t];
            }
            for (rn.children, rn.segments.len + rn.truths.len..) |c, k| {
                if (c >= id) return error.GpuNativeTopologyOrder;
                children[k] = node_keys[c];
            }
            node_keys[id] = try drv.recursion.vtable.class_of(drv.recursion.ctx, .{ .kind = kind, .ordinal = @intCast(id) }, children);
            node_cls[id] = try drv.classes.get(node_keys[id]);
            rn.cost = node_cls[id].cost_us;
        }
        const main_cap = try a.alloc(u64, devices);
        for (drv.lanes, main_cap) |l, *m| m.* = l.main.words;
        const two_stage = drv.recursion.vtable.truth_stage2 != null;
        if (two_stage and req.truths > drv.exchange_cap.capacity_truths) return error.GpuNativeTruthsExceedPlan;
        self.dag = try D.build(drv.a, .{ .devices = devices, .seal_device = drv.config.seal_device, .segments = segs, .truths = truths, .truth_after_seal = req.truth_after_seal, .truth_two_stage = two_stage, .recursion = rec, .root = req.root, .main_capacity = main_cap });
        const dag = &self.dag.?;
        for (dag.recursion, node_cls) |id, class| {
            if (class.phase_b and !dag.nodes[id].phase_b) return error.GpuNativeClassRequiresPhaseB;
        }
        // slab layout from class constants
        const placed = try dag.proofIds(a);
        const specs = try a.alloc(G.ProofSpec, placed.len);
        // The request pseudo-proof carries the stage-one bytes (native seal
        // job): fixed base + each segment class's share, when any is declared.
        var stage_one: usize = 0;
        for (native_cls) |e| stage_one += @max(e.stage_one_bytes, if (drv.exchange_cap.child_wire_words != 0) 76 + 4 * drv.exchange_cap.child_wire_words else 0);
        if (stage_one != 0) stage_one += drv.config.stage_one_base_bytes;
        for (placed, specs) |p, *spec| {
            const entry: ?*const G.ClassEntry = switch (p.id.kind) {
                .native_segment => native_cls[p.id.ordinal],
                .truth => truth_cls[p.id.ordinal],
                .leaf, .fold, .root => node_cls[p.id.ordinal],
                .request => null,
            };
            spec.* = .{ .id = p.id, .device = p.device, .max_encoded_bytes = if (entry) |e| e.max_encoded_bytes else stage_one, .extra_checks = if (entry) |e| e.extra_checks else &.{} };
        }
        // Install capacities fix every exchange offset; only GPUs that host a
        // segment own a partial slot (a GPU without one could never publish it).
        var partial_mask: u8 = 0;
        for (0..S) |s| partial_mask |= @as(u8, 1) << @intCast(dag.nodes[dag.stage1[s]].device);
        self.exchange = .{ .segments = @intCast(S), .claims_per_segment = claims, .devices = devices, .capacity_segments = drv.exchange_cap.capacity_segments, .capacity_claims = drv.exchange_cap.capacity_claims, .partial_mask = partial_mask, .partials_enabled = drv.exchange_cap.partials_enabled, .truths = if (two_stage) req.truths else 0, .capacity_truths = drv.exchange_cap.capacity_truths, .receipts = drv.exchange_cap.receipts, .child_wire_words = drv.exchange_cap.child_wire_words };
        self.exchange.validate() catch |err| return if (err == error.GpuNativeExchangeExceedsCapacity) error.GpuNativeClaimsExceedPlan else err;
        self.layout = try G.RequestLayout.build(drv.a, devices, specs, self.exchange);
        const layout = &self.layout.?;
        self.segment_buffers = try a.alloc(api.DeviceBuffer, devices);
        const replicas = try a.alloc([*]u32, devices);
        for (layout.segments, drv.lanes, 0..) |sl, l, d| {
            if (sl.words > l.slab[self.parity].words) return error.GpuNativeSlabExceedsPlan;
            self.segment_buffers[d] = try l.slab[self.parity].slice(0, sl.words);
            replicas[d] = l.slab[self.parity].ptr + sl.exchange_offset;
            self.receipt.slab_words[d] = sl.words;
        }
        // MAIN views per segment, sequential per GPU
        self.main_views = try a.alloc(api.DeviceBuffer, S);
        self.segment_device = try a.alloc(u32, S);
        const cursors = try a.alloc(Memory.MainCursor, devices);
        @memset(cursors, .{});
        for (0..S) |s| {
            const d = dag.nodes[dag.stage1[s]].device;
            self.segment_device[s] = d;
            const view = try cursors[d].take(drv.lanes[d].main.words, segs[s].main_words);
            self.main_views[s] = try drv.lanes[d].main.slice(@intCast(view.offset), @intCast(view.words));
        }
        try drv.peer.begin(self.generation, self.exchange, replicas);
        const truth_devices = try a.alloc(u32, req.truths);
        for (truth_devices, 0..) |*d, t| d.* = dag.nodes[dag.truth[t]].device;
        self.ctx = .{ .request = self.req.id, .parity = self.parity, .block = self.req.block, .native_classes = native_keys, .truth_devices = truth_devices, .layout = layout, .exchange = self.exchange, .peer = drv.peer.exchangeOf(), .classes = &drv.classes, .segments = self.segment_buffers, .main_resident = self.main_views, .segment_device = self.segment_device, .generation = self.generation };
        self.truth_classes = truth_cls;
        self.receipt.root_device = if (rec.len != 0) dag.nodes[dag.recursion[req.root]].device else dag.final_device;
        self.receipt.final_device = dag.final_device;
        self.receipt.peer_direct = drv.peer_direct;
    }

    fn make(self: *InFlight) !void {
        var timer = std.time.Timer.start() catch unreachable;
        defer self.receipt.make_ns = timer.read();
        const drv = self.driver;
        const a = self.alloc();
        const dag = &self.dag.?;
        const devices = drv.lanes.len;
        self.where = try a.alloc(Where, dag.nodes.len);
        self.batches = try a.alloc(W.Batch, devices);
        self.hooks = try a.alloc(Hook, devices);
        for (dag.device_order, 0..) |order, d| {
            if (order.len > drv.config.max_jobs_per_device) return error.GpuNativeJobsExceedPlan;
            self.batches[d] = .{ .jobs = try a.alloc(W.BatchJob, order.len), .parity = self.parity, .require_warm_persistent = true };
            self.hooks[d] = .{ .f = self, .device = @intCast(d) };
            self.batches[d].preamble = .{ .ctx = &self.hooks[d], .run = preamble };
            self.batches[d].tail = .{ .ctx = &self.hooks[d], .run = tail };
            for (order, 0..) |n, pos| self.where[n] = .{ .device = @intCast(d), .pos = @intCast(pos) };
        }
        // The service prepared the stream (before starting its capture
        // thread) with this request's geometry; bind it to the context.
        if (self.req.capture) |cap| try cap.bind(self.req.segment_rows, &self.ctx);
        var made: usize = 0;
        errdefer for (dag.order[0..made]) |n| {
            const w = self.where[n];
            const bj = &self.batches[w.device].jobs[w.pos];
            bj.job.vtable.abort(bj.job.ctx);
        };
        for (dag.order) |n| {
            const nd = dag.nodes[n];
            const w = self.where[n];
            const job: api.Job = switch (nd.kind) {
                .stage1 => try drv.native.vtable.stage1(drv.native.ctx, &self.ctx, nd.ordinal, nd.device),
                .seal => try drv.native.vtable.seal(drv.native.ctx, &self.ctx, nd.device),
                .stage2 => try drv.native.vtable.stage2(drv.native.ctx, &self.ctx, nd.ordinal, nd.device),
                .truth => try drv.recursion.vtable.truth(drv.recursion.ctx, &self.ctx, nd.ordinal, nd.device),
                .truth2 => try drv.recursion.vtable.truth_stage2.?(drv.recursion.ctx, &self.ctx, nd.ordinal, nd.device),
                .node => try drv.recursion.vtable.node(drv.recursion.ctx, &self.ctx, nd.proof.?, nd.children, nd.device),
            };
            const deps = try a.alloc(*W.BatchDep, nd.deps.len);
            for (nd.deps, 0..) |dep, k| {
                const dw = self.where[dep];
                deps[k] = &self.batches[dw.device].jobs[dw.pos].done;
            }
            var bj = W.BatchJob{ .job = job, .deps = deps, .phase_b = nd.phase_b };
            if (nd.kind == .stage1) if (self.req.capture) |cap| {
                // Staged only once its segment sealed; returns its ring
                // buffers after it; a failed Stage1 cancels the capture.
                const gates = try a.alloc(*W.BatchDep, 1);
                gates[0] = cap.gate(nd.ordinal);
                bj.gates = gates;
                bj.after = cap.releaseFn(nd.ordinal);
                bj.on_fail = cap.failFn();
            };
            // A truth whose inputs are final only at the capture's end is
            // staged after it (Stage1s are ordered first on every GPU, so this
            // gate never holds a segment's release back).
            if (nd.kind == .truth and self.truth_classes[nd.ordinal].needs_capture_end) if (self.req.capture) |cap| {
                const gates = try a.alloc(*W.BatchDep, 1);
                gates[0] = cap.endGate();
                bj.gates = gates;
                bj.on_fail = cap.failFn();
                self.receipt.capture_end_gated += 1;
            };
            self.batches[w.device].jobs[w.pos] = bj;
            made += 1;
        }
        self.receipt.jobs = @intCast(made);
    }

    fn run(self: *InFlight) !void {
        var timer = std.time.Timer.start() catch unreachable;
        defer self.receipt.enqueue_ns = timer.read();
        const drv = self.driver;
        const final = self.dag.?.final_device;
        const Runner = struct {
            /// Worker thread of GPU `h.device`: its whole batch, then release
            /// the final GPU's device-side join whatever happened.
            fn runBatch(raw: *anyopaque, w: *W.Worker) anyerror!void {
                const h: *Hook = @ptrCast(@alignCast(raw));
                w.runBatch(&h.f.batches[h.device]);
                h.f.tail_done[h.device].set();
            }
        };
        // Non-final GPUs: posted to their own worker threads (no thread is
        // created on the request path); the final GPU's batch runs on its
        // worker while they enqueue.
        var was_posted: [G.max_devices]bool = @splat(false);
        for (0..drv.lanes.len) |d| {
            if (d == final) continue;
            drv.lanes[d].worker.post(.{ .ctx = &self.hooks[d], .run = Runner.runBatch }, &self.posted[d]) catch |err| {
                // Never ran: poison its jobs so no consumer latch blocks.
                W.Worker.failBatch(&self.batches[d], err, 0);
                self.tail_done[d].set();
                continue;
            };
            was_posted[d] = true;
        }
        drv.lanes[final].worker.call(.{ .ctx = &self.hooks[final], .run = Runner.runBatch }) catch |err| {
            W.Worker.failBatch(&self.batches[final], err, 0);
        };
        for (0..drv.lanes.len) |d| if (was_posted[d]) drv.lanes[d].worker.awaitCall(&self.posted[d]) catch {};
        self.ran = true;
        for (self.batches, 0..) |b, d| {
            self.receipt.device_enqueue_ns[d] = b.enqueue_ns;
            self.receipt.device_gate_ns[d] = b.gate_wait_ns;
            self.receipt.device_memory_serializations[d] = b.memory_serializations;
        }
        // Snapshot now: the next request's begin resets the peer counters
        // before this request's finish runs.
        self.receipt.peer_publishes = drv.peer.publishes.load(.monotonic);
        self.receipt.peer_copies = drv.peer.peer_copies.load(.monotonic);
        // A batch whose preamble/tail failed cannot be trusted to have
        // recorded its completion: the final event may never fire. Fail
        // closed before the wait (jobs already enqueued complete on the
        // device; the next request's stream order follows them).
        for (self.batches) |b| try b.result;
    }

    fn preamble(raw: *anyopaque, w: *W.Worker) anyerror!void {
        const h: *Hook = @ptrCast(@alignCast(raw));
        const f = h.f;
        const drv = f.driver;
        const l = &drv.lanes[h.device];
        const sl = &f.layout.?.segments[h.device];
        const stream = w.execStream();
        const slab = l.slab[f.parity];
        try O.check(drv.ops.exec.event_record(l.start_event[f.parity].?, stream));
        // Header + directory: host-written prefix (class geometry), two h2d
        // around the exchange (other GPUs peer-copy into it, unordered with
        // this stream: the host never writes it).
        const mirror = l.mirror[f.parity];
        try sl.prefix(mirror, f.req.id);
        // The mirror's status words read `unset` until this request's D2H
        // lands (a missing D2H can never publish an earlier request's words).
        @memset(mirror[sl.status_offset..][0..sl.status_words], G.Verdict.unset);
        try O.check(drv.ops.exec.copy_async(slab.ptr, mirror.ptr, G.header_words * 4, @intFromEnum(O.CopyKind.h2d), stream));
        try O.check(drv.ops.exec.copy_async(slab.ptr + sl.directory_offset, mirror.ptr + sl.directory_offset, (sl.status_offset - sl.directory_offset) * 4, @intFromEnum(O.CopyKind.h2d), stream));
        // Status words unset (a check that never runs rejects). The exchange
        // is left alone: other GPUs peer-copy into it with no order against
        // this stream; flag tags make stale words harmless (gpu_native.Exchange).
        try O.check(drv.peer_ops.fill_u32(slab.ptr + sl.status_offset, G.Verdict.unset, sl.status_words, stream));
        // Every encoded length word := 0 (an encoder that never runs publishes nothing).
        for (sl.entries) |e| try O.check(drv.peer_ops.fill_u32(slab.ptr + e.encoded_offset, 0, 1, stream));
    }

    fn tail(raw: *anyopaque, w: *W.Worker) anyerror!void {
        const h: *Hook = @ptrCast(@alignCast(raw));
        const f = h.f;
        const drv = f.driver;
        const l = &drv.lanes[h.device];
        const sl = &f.layout.?.segments[h.device];
        const stream = w.execStream();
        const slab = l.slab[f.parity];
        const final = f.dag.?.final_device;
        if (h.device == final) {
            // Device-side join of every other GPU (their tails RECORDED
            // first: host latch on the batch completion of each).
            for (drv.lanes, 0..) |*other, d| {
                if (d == final) continue;
                f.tail_done[d].wait();
                try O.check(drv.ops.exec.stream_wait(stream, other.done_event[f.parity].?));
            }
            // Check.exchange_complete over this replica's flag words (the
            // request's flags are the contiguous prefix of the flag region).
            const flags = slab.ptr + sl.exchange_offset + G.Exchange.flag_offset;
            const word = try sl.statusWord(.{ .kind = .request, .ordinal = 0 }, .exchange_complete);
            try O.check(drv.peer_ops.flags_verdict(flags, @intCast(f.exchange.flagWords()), G.Exchange.flagTag(f.generation), slab.ptr + word, G.Verdict.reject(.exchange_complete, 1), stream));
        }
        // Device-written completion word (publish requires it): only a D2H
        // that ran after every job of this batch carries this request's tag.
        try O.check(drv.peer_ops.fill_u32(slab.ptr + G.header_completion_word, G.Exchange.flagTag(f.generation), 1, stream));
        try O.check(drv.ops.exec.copy_async(l.mirror[f.parity].ptr, slab.ptr, sl.words * 4, @intFromEnum(O.CopyKind.d2h), stream));
        try O.check(drv.ops.exec.event_record(l.end_event[f.parity].?, stream));
        try O.check(drv.ops.exec.event_record(l.done_event[f.parity].?, stream));
        if (h.device != final) f.tail_done[h.device].set();
    }

    /// A request that failed before its single wait: abort every job. The
    /// caller quiesced the devices first.
    fn abortAll(self: *InFlight) void {
        const Fin = struct {
            batch: *W.Batch,
            fn run(raw: *anyopaque, w: *W.Worker) anyerror!void {
                const s: *@This() = @ptrCast(@alignCast(raw));
                w.finishBatch(s.batch, false);
            }
        };
        for (self.driver.lanes, self.batches) |l, *b| {
            var fin = Fin{ .batch = b };
            l.worker.call(.{ .ctx = &fin, .run = Fin.run }) catch {};
        }
    }

    /// Error paths only (a failed `begin`, a faulted request wait, teardown;
    /// never a successful request): one device wait per GPU on a fresh
    /// record of its exec stream. A faulted GPU's wait fails and is logged;
    /// every other GPU is still drained.
    fn quiesce(self: *InFlight) void {
        const Q = struct {
            f: *InFlight,
            device: usize,
            fn run(raw: *anyopaque, w: *W.Worker) anyerror!void {
                const q: *@This() = @ptrCast(@alignCast(raw));
                const ev = q.f.driver.lanes[q.device].done_event[q.f.parity].?;
                try O.check(q.f.driver.ops.exec.event_record(ev, w.execStream()));
                _ = try w.requestWait(ev);
            }
        };
        for (self.driver.lanes, 0..) |l, d| {
            var q = Q{ .f = self, .device = d };
            l.worker.call(.{ .ctx = &q, .run = Q.run }) catch |err| std.log.err("M8 GPU-native quiesce of device {d} failed: {s}", .{ d, @errorName(err) });
        }
    }

    /// Failed runs only. Copies already-landed mirrors without a device read
    /// or a publication hook; the filename and metadata retain rejection.
    fn dumpRejected(self: *InFlight, mirrors: []const []const u32) !void {
        const path = std.posix.getenv("STWO_RV64_M8_NATIVE_REJECT_DUMP") orelse return;
        try std.fs.cwd().makePath(path);
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        for (self.layout.?.segments, mirrors) |segment, mirror| {
            var name_buf: [128]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buf, "rejected-{d}-{d}-{d}.bin", .{ self.req.block, self.req.id, segment.device });
            try dir.writeFile(.{ .sub_path = name, .data = std.mem.sliceAsBytes(mirror) });
            const metadata = try std.json.Stringify.valueAlloc(self.alloc(), .{ .accepted = false, .block = self.req.block, .request = self.req.id, .device = segment.device, .words = segment.words, .entries = segment.entries, .ids = segment.ids, .checks = segment.checks }, .{});
            defer self.alloc().free(metadata);
            const meta_name = try std.fmt.bufPrint(&name_buf, "rejected-{d}-{d}-{d}.json", .{ self.req.block, self.req.id, segment.device });
            try dir.writeFile(.{ .sub_path = meta_name, .data = metadata });
        }
    }

    fn complete(self: *InFlight) !Outcome {
        const drv = self.driver;
        const final = self.dag.?.final_device;
        // ---- the ONE host wait of the request ----
        var device_ok = true;
        self.receipt.wait_ns = drv.lanes[final].worker.requestWait(drv.lanes[final].done_event[self.parity].?) catch blk: {
            device_ok = false;
            break :blk 0;
        };
        self.receipt.host_waits = 1;
        if (!device_ok) {
            // The final GPU faulted (its wait may return at once): the other
            // GPUs may still run this request's kernels, peer copies, capture
            // host fns and mirror D2H. Drain them before any job aborts or
            // the arena is freed, and never reuse this driver (sticky fault).
            self.quiesce();
            drv.poisoned = true;
        }
        var timer = std.time.Timer.start() catch unreachable;
        const Fin = struct {
            batch: *W.Batch,
            ok: bool,
            fn run(raw: *anyopaque, w: *W.Worker) anyerror!void {
                const s: *@This() = @ptrCast(@alignCast(raw));
                w.finishBatch(s.batch, s.ok);
            }
        };
        // Every lane's phase 3 runs even if one lane's call fails, so no job
        // is left neither finished nor aborted.
        var call_err: ?anyerror = null;
        for (drv.lanes, self.batches) |l, *b| {
            var fin = Fin{ .batch = b, .ok = device_ok };
            l.worker.call(.{ .ctx = &fin, .run = Fin.run }) catch |err| {
                call_err = call_err orelse err;
            };
        }
        self.receipt.finish_ns = timer.read();
        if (call_err) |err| return err;
        if (!device_ok) return error.CudaDeviceFault;
        var job_err: ?anyerror = null;
        for (self.batches) |b| for (b.jobs) |bj| {
            self.receipt.job_slab_d2h += bj.receipt.d2h_copies;
            self.receipt.job_slab_d2h_bytes += bj.receipt.d2h_bytes;
            self.receipt.host_callbacks += bj.receipt.host_callbacks;
            self.receipt.capture_release_callbacks += bj.receipt.capture_release_callbacks;
            bj.result catch |err| {
                job_err = job_err orelse err;
            };
        };
        self.receipt.job_receipts_complete = true;
        if (job_err) |err| return err;
        // A capture that failed after its last seal (GE terminal/collector
        // checks, a `captured` hook) fails no device job: refuse it here,
        // before anything is published.
        if (self.req.capture) |cap| {
            timer.reset();
            try cap.awaitCaptured();
            self.receipt.capture_wait_ns = timer.read();
        }
        for (drv.lanes, 0..) |l, d| {
            var us: u64 = 0;
            if (drv.peer_ops.event_elapsed_us(l.start_event[self.parity].?, l.end_event[self.parity].?, &us) == 0) self.receipt.device_gpu_us[d] = us;
            self.receipt.d2h += 1;
            self.receipt.h2d += 2;
            self.receipt.d2h_bytes += self.receipt.slab_words[d] * 4;
        }
        // ---- publication: status words + slicing (host's only per-request computation) ----
        timer.reset();
        const mirrors = try self.alloc().alloc([]const u32, drv.lanes.len);
        for (drv.lanes, mirrors) |l, *m| m.* = l.mirror[self.parity];
        var rejection: G.Rejection = undefined;
        const views = G.publish(self.alloc(), &self.layout.?, self.req.id, G.Exchange.flagTag(self.generation), mirrors, &rejection) catch |err| {
            if (err == error.GpuNativeProofRejected) std.log.warn("M8 GPU-native request {d} rejected: {s} {d} check {s} word 0x{x:0>8}", .{ self.req.id, @tagName(rejection.id.kind), rejection.id.ordinal, @tagName(rejection.check), rejection.word });
            for (self.layout.?.segments, mirrors) |segment, mirror| {
                if (mirror.len < segment.words) continue;
                for (segment.entries, segment.ids) |entry, id| for (0..entry.status_count) |k| {
                    const word = mirror[entry.status_first + k];
                    if (word != G.Verdict.accepted) std.log.warn("M8 GPU-native verdict request={d} device={d} kind={s} ordinal={d} check={s} word=0x{x:0>8}", .{ self.req.id, segment.device, @tagName(id.kind), id.ordinal, @tagName(segment.checks[entry.first_check + k]), word });
                };
            }
            self.dumpRejected(mirrors) catch |dump_err| std.log.err("M8 rejected mirror dump failed: {s}", .{@errorName(dump_err)});
            return err;
        };
        var n: usize = 0;
        for (views) |v| if (v.id.kind != .request) {
            n += 1;
        } else {
            self.receipt.stage_one_bytes = v.bytes.len;
        };
        const out = try drv.a.alloc(Published, n);
        var i: usize = 0;
        errdefer {
            for (out[0..i]) |p| drv.a.free(p.bytes);
            drv.a.free(out);
        }
        for (views) |v| if (v.id.kind != .request) {
            out[i] = .{ .id = v.id, .bytes = try drv.a.dupe(u8, v.bytes) };
            i += 1;
        };
        self.receipt.publish_ns = timer.read();
        // Artifact files: each stream writes its own legacy formats from the
        // views (the mirrors stay valid until this request's parity is reused,
        // which is after `finish` returns).
        if (self.req.out) |dir| {
            timer.reset();
            const sl = &self.layout.?.segments[final];
            const pub_view = G.Publication{ .block = self.req.block, .proofs = views, .exchange = drv.lanes[final].mirror[self.parity][sl.exchange_offset..][0..sl.exchange_words], .dir = dir };
            if (drv.native.vtable.publish) |hook| try hook(drv.native.ctx, &self.ctx, pub_view);
            if (drv.recursion.vtable.publish) |hook| try hook(drv.recursion.ctx, &self.ctx, pub_view);
            self.receipt.publish_files_ns = timer.read();
        }
        return .{ .a = drv.a, .proofs = out, .receipt = self.receipt };
    }
};

test {
    _ = @import("driver_test.zig");
}
