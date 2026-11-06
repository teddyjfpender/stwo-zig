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
//!   preamble per GPU: header/directory h2d from the pinned mirror, status
//!   words := unset, encoded lengths := 0 (device fills), start event. The
//!   exchange replica is NOT zeroed per request: a consumer GPU's fill is
//!   not ordered against a producer GPU's peer copy (with two requests in
//!   flight the fill runs after the consumer's previous request and would
//!   erase slots that already landed). Flags carry the request's
//!   Exchange.flagTag instead; install zeroes every slab once;
//!   every job enqueued back to back with device-side dependencies
//!   (cross-GPU done events; peer slots through driver_peer.zig); Stage1(seg)
//!   released by the capture stream as each segment seals;
//!   tail per GPU: one D2H of the whole slab segment into its pinned mirror;
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
const P = @import("driver_peer.zig");
const C = @import("../m8_capture_stream.zig");

pub const Config = struct {
    /// Device capacity in words per driver device (index = worker index).
    capacity_words: []const u64,
    /// Largest native segment count / truths / jobs per GPU per request.
    max_segments: u32,
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
    /// Expected class peaks (0 = from the warmed class entries).
    phase_a_peak_words: u64 = 0,
    phase_b_peak_words: u64 = 0,
    /// main_resident capacity per GPU (0 = from max_segments x the largest native class).
    main_resident_words: u64 = 0,
};

/// One request as the service hands it over (host shape; class keys come
/// from the factories).
pub const Request = struct {
    id: u64,
    /// Rows per native segment (geometry known at plan time; see m8_capture_stream).
    segment_rows: []const u64,
    truths: u32 = 0,
    truth_after_seal: bool = false,
    /// Recursion topology, children before parents, root last (ready_dag order).
    recursion: []const D.RecursionNode = &.{},
    root: u32 = 0,
    capture: ?*C.Stream = null,
};

pub const Published = struct { id: G.ProofId, bytes: []u8 };

pub const Receipt = struct {
    request: u64 = 0,
    generation: u64 = 0,
    host_waits: u32 = 0,
    d2h: u32 = 0,
    d2h_bytes: u64 = 0,
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
    /// CUDA-event GPU span per device: preamble start -> slab D2H end [M].
    device_gpu_us: [G.max_devices]u64 = @splat(0),
    wait_ns: u64 = 0,
    finish_ns: u64 = 0,
    publish_ns: u64 = 0,
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
    installed: bool = false,
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
        // 2. peer access + per-GPU resources on each worker thread
        var ordinals: [G.max_devices]u32 = undefined;
        for (workers, 0..) |w, d| {
            ordinals[d] = w.device_ordinal;
            self.peer.ordinals[d] = w.device_ordinal;
        }
        var direct: u32 = 1;
        if (workers.len > 1) try O.check(peer_ops.peer_enable(&ordinals, @intCast(workers.len), &direct));
        self.peer_direct = direct == 1;
        const exchange_cap = G.Exchange{ .segments = config.max_segments, .claims_per_segment = 1, .devices = @intCast(workers.len) };
        try self.peer.reserve(a, exchange_cap.flagWords());
        errdefer self.peer.deinitHost(a);
        const largest_main = self.largestNativeMain();
        var made: usize = 0;
        errdefer for (self.lanes[0..made]) |*l| self.releaseLane(l);
        for (self.lanes, 0..) |*l, d| {
            const main_words = if (config.main_resident_words != 0) config.main_resident_words else largest_main * config.max_segments;
            l.plan = try M.plan(.{ .device = @intCast(d), .capacity_words = config.capacity_words[d], .class_cache_words = self.classCacheWords(@intCast(d)), .graph_exec_words = config.graph_exec_words, .main_resident_words = main_words, .phase_a_peak_words = config.phase_a_peak_words, .phase_b_peak_words = config.phase_b_peak_words, .slab_words = config.slab_words, .reserve_words = config.reserve_words, .arena_cap_words = config.arena_cap_words });
            var setup = Setup{ .driver = self, .lane = l, .device = @intCast(d) };
            try l.worker.call(.{ .ctx = &setup, .run = Setup.run });
            made += 1;
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

    pub fn deinit(self: *Driver) void {
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
    fn classCacheWords(self: *Driver, device: u32) u64 {
        var n: u64 = 0;
        self.classes.mutex.lock();
        defer self.classes.mutex.unlock();
        var it = self.classes.map.valueIterator();
        while (it.next()) |e| if (e.*.device[device]) |b| {
            n += b.words;
        };
        return n + self.lanes[device].worker.config.persistent_budget_words;
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
        const parity: u1 = @truncate(self.generation);
        if (self.in_flight[parity] != null) return error.GpuNativePipelineFull;
        // A capture stream belongs to one in-flight request: its gates, ctx
        // attachment and ring buffers are per request (the service rotates
        // one stream per parity).
        if (req.capture) |cap| if (self.in_flight[parity ^ 1]) |other| if (other.req.capture == cap) return error.GpuNativeCaptureStreamInFlight;
        self.generation += 1;
        const f = try self.a.create(InFlight);
        errdefer self.a.destroy(f);
        f.* = .{ .driver = self, .parity = parity, .generation = self.generation, .req = req.* };
        f.receipt.request = req.id;
        f.receipt.generation = self.generation;
        errdefer f.release();
        try f.plan();
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
    receipt: Receipt = .{},
    ran: bool = false,
    /// Host latch per non-final GPU: its tail recorded its done event.
    tail_done: [G.max_devices]std.Thread.ResetEvent = @splat(.{}),

    const Hook = struct { f: *InFlight, device: u32 };
    const Where = struct { device: u32, pos: u32 };

    fn alloc(self: *InFlight) std.mem.Allocator {
        return self.arena.allocator();
    }

    fn release(self: *InFlight) void {
        if (self.req.capture) |cap| cap.detach();
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
        var claims: u32 = 1;
        const segs = try a.alloc(D.Segment, S);
        for (req.segment_rows, 0..) |rows, s| {
            const key = try drv.native.vtable.class_of(drv.native.ctx, @intCast(s), rows);
            native_cls[s] = try drv.classes.get(key);
            claims = @max(claims, native_cls[s].claims_per_segment);
            segs[s] = .{ .main_words = native_cls[s].main_resident_words, .stage1_cost = native_cls[s].cost_us, .stage2_cost = native_cls[s].cost_us };
        }
        const truths = try a.alloc(D.Truth, req.truths);
        const truth_cls = try a.alloc(*const G.ClassEntry, req.truths);
        for (truths, 0..) |*t, i| {
            truth_cls[i] = try drv.classes.get(try drv.recursion.vtable.class_of(drv.recursion.ctx, .{ .kind = .truth, .ordinal = @intCast(i) }));
            t.* = .{ .cost = truth_cls[i].cost_us };
        }
        const rec = try a.dupe(D.RecursionNode, req.recursion);
        const shape_probe = D.Shape{ .devices = devices, .segments = segs, .recursion = rec, .root = req.root };
        const node_cls = try a.alloc(*const G.ClassEntry, rec.len);
        for (rec, 0..) |*rn, id| {
            const kind = D.recursionKind(shape_probe, @intCast(id));
            node_cls[id] = try drv.classes.get(try drv.recursion.vtable.class_of(drv.recursion.ctx, .{ .kind = kind, .ordinal = @intCast(id) }));
            rn.cost = node_cls[id].cost_us;
        }
        const main_cap = try a.alloc(u64, devices);
        for (drv.lanes, main_cap) |l, *m| m.* = l.main.words;
        self.dag = try D.build(drv.a, .{ .devices = devices, .seal_device = drv.config.seal_device, .segments = segs, .truths = truths, .truth_after_seal = req.truth_after_seal, .recursion = rec, .root = req.root, .main_capacity = main_cap });
        const dag = &self.dag.?;
        // slab layout from class constants
        const placed = try dag.proofIds(a);
        const specs = try a.alloc(G.ProofSpec, placed.len);
        for (placed, specs) |p, *spec| {
            const entry: ?*const G.ClassEntry = switch (p.id.kind) {
                .native_segment => native_cls[p.id.ordinal],
                .truth => truth_cls[p.id.ordinal],
                .leaf, .fold, .root => node_cls[p.id.ordinal],
                .request => null,
            };
            spec.* = .{ .id = p.id, .device = p.device, .max_encoded_bytes = if (entry) |e| e.max_encoded_bytes else 0, .extra_checks = if (entry) |e| e.extra_checks else &.{} };
        }
        self.exchange = .{ .segments = @intCast(S), .claims_per_segment = claims, .devices = devices };
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
        const at = try a.alloc(u64, devices);
        @memset(at, 0);
        for (0..S) |s| {
            const d = dag.nodes[dag.stage1[s]].device;
            self.segment_device[s] = d;
            const words = std.mem.alignForward(u64, segs[s].main_words, M.granule);
            if (at[d] + words > drv.lanes[d].main.words) return error.GpuNativeMainResidentOverflow;
            self.main_views[s] = try drv.lanes[d].main.slice(@intCast(at[d]), @intCast(words));
            at[d] += words;
        }
        try drv.peer.begin(self.generation, self.exchange, replicas);
        self.ctx = .{ .request = self.req.id, .layout = layout, .exchange = self.exchange, .peer = drv.peer.exchangeOf(), .classes = &drv.classes, .segments = self.segment_buffers, .main_resident = self.main_views, .segment_device = self.segment_device, .generation = self.generation };
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
            self.batches[d] = .{ .jobs = try a.alloc(W.BatchJob, order.len), .parity = self.parity };
            self.hooks[d] = .{ .f = self, .device = @intCast(d) };
            self.batches[d].preamble = .{ .ctx = &self.hooks[d], .run = preamble };
            self.batches[d].tail = .{ .ctx = &self.hooks[d], .run = tail };
            for (order, 0..) |n, pos| self.where[n] = .{ .device = @intCast(d), .pos = @intCast(pos) };
        }
        if (self.req.capture) |cap| {
            try cap.begin(@intCast(self.req.segment_rows.len));
            cap.attach(&self.ctx);
        }
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
                .node => try drv.recursion.vtable.node(drv.recursion.ctx, &self.ctx, nd.proof.?, nd.children, nd.device),
            };
            const gate_count: usize = if (nd.kind == .stage1 and self.req.capture != null) 1 else 0;
            const deps = try a.alloc(*W.BatchDep, nd.deps.len + gate_count);
            for (nd.deps, 0..) |dep, k| {
                const dw = self.where[dep];
                deps[k] = &self.batches[dw.device].jobs[dw.pos].done;
            }
            var after: ?api.HostFn = null;
            if (gate_count == 1) {
                deps[nd.deps.len] = self.req.capture.?.gate(nd.ordinal);
                after = self.req.capture.?.releaseFn(nd.ordinal);
            }
            self.batches[w.device].jobs[w.pos] = .{ .job = job, .deps = deps, .after = after, .phase_b = nd.phase_b };
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
            fn go(f: *InFlight, d: usize) void {
                f.driver.lanes[d].worker.call(.{ .ctx = &f.batches[d], .run = runBatch }) catch |err| {
                    // Never ran: poison its jobs so no consumer latch blocks.
                    W.Worker.failBatch(&f.batches[d], err, 0);
                };
                // Whatever happened, the final GPU's tail must not block on it.
                f.tail_done[d].set();
            }
            fn runBatch(raw: *anyopaque, w: *W.Worker) anyerror!void {
                w.runBatch(@ptrCast(@alignCast(raw)));
            }
        };
        var threads: [G.max_devices]?std.Thread = @splat(null);
        for (0..drv.lanes.len) |d| {
            if (d == final) continue;
            threads[d] = std.Thread.spawn(.{}, Runner.go, .{ self, d }) catch |err| blk: {
                W.Worker.failBatch(&self.batches[d], err, 0);
                self.tail_done[d].set();
                break :blk null;
            };
        }
        Runner.go(self, final);
        for (threads) |t| if (t) |th| th.join();
        self.ran = true;
        for (self.batches, 0..) |b, d| {
            self.receipt.device_enqueue_ns[d] = b.enqueue_ns;
            self.receipt.device_gate_ns[d] = b.gate_wait_ns;
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
        // Header + directory: host-written prefix (class geometry), one h2d.
        try sl.prefix(l.mirror[f.parity], f.req.id);
        try O.check(drv.ops.exec.copy_async(slab.ptr, l.mirror[f.parity].ptr, sl.status_offset * 4, @intFromEnum(O.CopyKind.h2d), stream));
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
            // Check.exchange_complete over this replica's flag words.
            const flags = slab.ptr + sl.exchange_offset + (f.exchange.words() - f.exchange.flagWords());
            const word = try sl.statusWord(.{ .kind = .request, .ordinal = 0 }, .exchange_complete);
            try O.check(drv.peer_ops.flags_verdict(flags, @intCast(f.exchange.flagWords()), G.Exchange.flagTag(f.generation), slab.ptr + word, G.Verdict.reject(.exchange_complete, 1), stream));
        }
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

    /// Error path of `begin` only (never a successful request): one
    /// device wait per GPU on a fresh record of its exec stream.
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
        for (self.batches) |b| for (b.jobs) |bj| try bj.result;
        for (drv.lanes, 0..) |l, d| {
            var us: u64 = 0;
            if (drv.peer_ops.event_elapsed_us(l.start_event[self.parity].?, l.end_event[self.parity].?, &us) == 0) self.receipt.device_gpu_us[d] = us;
            self.receipt.d2h += 1;
            self.receipt.h2d += 1;
            self.receipt.d2h_bytes += self.receipt.slab_words[d] * 4;
        }
        // ---- publication: status words + slicing (host's only per-request computation) ----
        timer.reset();
        const mirrors = try self.alloc().alloc([]const u32, drv.lanes.len);
        for (drv.lanes, mirrors) |l, *m| m.* = l.mirror[self.parity];
        var rejection: G.Rejection = undefined;
        const views = G.publish(self.alloc(), &self.layout.?, self.req.id, mirrors, &rejection) catch |err| {
            if (err == error.GpuNativeProofRejected) std.log.warn("M8 GPU-native request {d} rejected: {s} {d} check {s} word 0x{x:0>8}", .{ self.req.id, @tagName(rejection.id.kind), rejection.id.ordinal, @tagName(rejection.check), rejection.word });
            return err;
        };
        var n: usize = 0;
        for (views) |v| if (v.id.kind != .request) {
            n += 1;
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
        return .{ .a = drv.a, .proofs = out, .receipt = self.receipt };
    }
};

test {
    _ = @import("driver_test.zig");
}
