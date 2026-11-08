//! Installed resource lifetime for the GPU-native request driver.
//! Driver initializes this owner in final storage, so captured cache/peer
//! addresses remain stable. Workers/factories are borrowed; Driver drains
//! request jobs before retiring these plans, slabs, mirrors and events.
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const W = @import("worker.zig");
const O = @import("ops.zig");
const M = @import("driver_memory.zig");
const Memory = @import("memory_plan.zig");
const P = @import("driver_peer.zig");

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

pub const Owner = struct {
    a: std.mem.Allocator,
    ops: *const O.Ops,
    peer_ops: *const O.Peer,
    native: G.NativeFactory,
    recursion: G.RecursionFactory,
    classes: G.ClassCache,
    config: Config,
    lanes: []Lane,
    peer: P.Peer,
    installed: bool = false,
    resources_warmed: bool = false,
    resident_words: [G.max_devices]u64 = @splat(0),
    exchange_cap: G.Exchange = .{ .segments = 0, .claims_per_segment = 0, .devices = 0 },
    install_allocations: usize = 0,
    peer_direct: bool = false,

    /// Driver validates configuration before allocation and initializes here
    /// without moving the cache or addresses retained by factory hooks.
    pub fn init(self: *Owner, a: std.mem.Allocator, ops: *const O.Ops, peer_ops: *const O.Peer, workers: []const *W.Worker, native: G.NativeFactory, recursion: G.RecursionFactory, config: Config) !void {
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
            const nr = native.vtable.resources orelse return error.GpuNativeResourceWarmHookMissing;
            const rr = recursion.vtable.resources orelse return error.GpuNativeResourceWarmHookMissing;
            // The largest declared request job is a conservative installation
            // window. It is released before the one final plan is allocated.
            // No request exists here, and persistent regions survive both
            // control operations. Nothing on the request path parks a worker.
            // Class footprints need not end on a worker allocation granule.
            const temporary = try Memory.alignedWords(@max(peaks[0], peaks[1]));
            for (workers) |w| {
                _ = try w.park(.{});
                _ = try w.unpark(@intCast(@max(temporary, w.config.arena_words)));
            }
            try nr(native.ctx, &self.classes, @intCast(workers.len));
            try rr(recursion.ctx, &self.classes, @intCast(workers.len));
            for (workers, 0..) |w, d| {
                const Census = struct {
                    words: u64 = 0,
                    fn run(raw: *anyopaque, worker: *W.Worker) anyerror!void {
                        const census: *@This() = @ptrCast(@alignCast(raw));
                        census.words = worker.persistentWords();
                    }
                };
                var census = Census{};
                try w.call(.{ .ctx = &census, .run = Census.run });
                self.resident_words[d] = census.words;
                _ = try w.park(.{});
                _ = try w.unpark(1 << 16);
                std.debug.print("GPU_M9_RESIDENT_CENSUS device={d} persistent_words={d} allocations_materialized=1\n", .{ d, census.words });
            }
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
        errdefer self.peer.deinitHost(a);
        try self.peer.reserve(a, self.exchange_cap.flagCapacity());
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
            var setup = Setup{ .owner = self, .lane = l, .device = @intCast(d) };
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
    }

    /// Every request borrow must have been drained before this call.
    pub fn deinit(self: *Owner) void {
        for (self.lanes) |*l| self.releaseLane(l);
        self.peer.deinitHost(self.a);
        self.classes.deinit();
        self.a.free(self.lanes);
    }

    fn largestNativeMain(self: *Owner) u64 {
        var best: u64 = 0;
        self.classes.mutex.lock();
        defer self.classes.mutex.unlock();
        var it = self.classes.map.valueIterator();
        while (it.next()) |e| best = @max(best, e.*.main_resident_words);
        return best;
    }
    fn maxLocalWire(self: *Owner) usize {
        var words: usize = 0;
        self.classes.mutex.lock();
        defer self.classes.mutex.unlock();
        var it = self.classes.map.valueIterator();
        while (it.next()) |entry| words = @max(words, entry.*.local_gkr_wire_words);
        return words;
    }
    fn maxClaims(self: *Owner) u32 {
        var best: u32 = 0;
        self.classes.mutex.lock();
        defer self.classes.mutex.unlock();
        var it = self.classes.map.valueIterator();
        while (it.next()) |e| best = @max(best, e.*.claims_per_segment);
        return best;
    }
    /// Arena peaks of the warmed classes: [phase A (classes without
    /// `phase_b`), phase B (every class)].
    fn classPeaks(self: *Owner) [2]u64 {
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
    fn classCacheWords(self: *Owner, device: u32) !u64 {
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
    fn measuredCapacity(self: *Owner, w: *W.Worker, cap_words: u64, device_index: usize) !u64 {
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
        owner: *Owner,
        lane: *Lane,
        device: u32,
        fn run(raw: *anyopaque, w: *W.Worker) anyerror!void {
            const s: *Setup = @ptrCast(@alignCast(raw));
            const self = s.owner;
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

    fn releaseLane(self: *Owner, l: *Lane) void {
        var r = Release{ .owner = self, .lane = l };
        l.worker.call(.{ .ctx = &r, .run = Release.run }) catch {};
    }
    const Release = struct {
        owner: *Owner,
        lane: *Lane,
        fn run(raw: *anyopaque, w: *W.Worker) anyerror!void {
            const r: *Release = @ptrCast(@alignCast(raw));
            const l = r.lane;
            const wt = &r.owner.ops.wait;
            // Nothing enqueued on this GPU may still read what is freed below.
            if (l.done_event[0]) |ev| {
                if (r.owner.ops.exec.event_record(ev, w.execStream()) == 0) _ = w.requestWait(ev) catch {};
            }
            w.uninstallPlanArena() catch |err| std.log.err("M8 GPU-native teardown: plan arena free failed: {s}", .{@errorName(err)});
            if (l.slab_allocated) _ = r.owner.ops.exec.free_u32(w.context, l.slab[0].ptr);
            l.slab_allocated = false;
            for (0..2) |p| {
                if (l.mirror[p].len != 0) _ = wt.host_free(l.mirror[p].ptr);
                l.mirror[p] = &.{};
                inline for (.{ &l.done_event[p], &l.start_event[p], &l.end_event[p] }) |e| if (e.*) |ev| {
                    _ = wt.event_destroy(ev);
                    e.* = null;
                };
            }
            const d = std.mem.indexOfScalar(?*anyopaque, &r.owner.peer.streams, w.execStream()) orelse return;
            for (r.owner.peer.events[d]) |*e| if (e.*) |ev| {
                _ = wt.event_destroy(ev);
                e.* = null;
            };
        }
    };
};
