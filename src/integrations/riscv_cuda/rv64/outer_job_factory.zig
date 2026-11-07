//! OuterNodeJob request-layer adapter (M8 outer-job; runtime Stage A seam).
//! Outside rv64/jobs/ like outer_job_prestage.zig. One `Shared` per service
//! (resolved symbols), one `Prover` per DeviceWorker (its graph cache).
//!
//!   prove(node) = prestage (calling thread / host pool)
//!              -> OuterNodeJob submitted to the lane's worker
//!              -> completion (the worker's single event wait)
//!              -> assemble (calling thread) -> om31 prove.Produced
//!
//! The proof is the legacy controller's proof byte for byte
//! (vectors/reports/rv64-m8-20261106/outer-job/fixture-parity-01.json).
const std = @import("std");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Prestage = @import("outer_job_prestage.zig");
const K = @import("jobs/outer_kernels.zig");
const Comp = @import("jobs/outer_composition.zig");
const NativePcs = @import("jobs/native_pcs.zig");
const Graphs = @import("jobs/outer_graph_cache.zig");
const Job = @import("jobs/outer_job.zig");
const FixedJob = @import("jobs/outer_fixed_job.zig");
const Worker = @import("jobs/worker.zig");
const api = @import("jobs/api.zig");
const Q = Outer.protocol.Q;
const Events = @import("cuda_events.zig");
const Heap = @import("jobs/outer_heap.zig");
const Env = @import("jobs/outer_env.zig");
const OuterWindow = @import("jobs/outer_window.zig");

pub const Shared = struct {
    kernels: K.Kernels,
    composition: Comp.Kernels,
    pcs: NativePcs.Symbols,
    wide: bool,
    graph_api: Graphs.Api,
    fs: std.DynLib,
    /// Base-image CUDA event symbols (cuda_events.zig); null: no GPU timing.
    events: ?Events.Api = null,
    /// `base` = frozen base image, `addon` = libstwo-rv64-jobs.so, both owned by
    /// the caller (ops.Libraries); `fs_path` = libstwo-rv64-outer-fs-ops.so.
    pub fn init(base: *std.DynLib, addon: *std.DynLib, fs_path: []const u8) !Shared {
        var fs = try std.DynLib.open(fs_path);
        errdefer fs.close();
        const Version = *const fn () callconv(.c) u32;
        return .{
            .kernels = try K.Kernels.load(base, &fs),
            .composition = try Comp.Kernels.load(base, addon),
            .pcs = try NativePcs.Symbols.load(addon),
            .wide = if (base.lookup(Version, "stwo_rv64_pcs_request_version")) |version| version() >= 3 else false,
            .graph_api = try Graphs.Api.load(addon),
            .fs = fs,
            .events = Events.Api.load(base) catch null,
        };
    }
    pub fn deinit(self: *Shared) void {
        self.fs.close();
        self.* = undefined;
    }
    pub fn whole(self: *const Shared) Job.Whole {
        return .{ .composition = &self.composition, .pcs = self.pcs, .wide = self.wide };
    }
};

/// GPU time of one job body: two CUDA events on the worker's exec stream,
/// created and recorded on the worker thread (its device is current there)
/// outside any graph capture, resolved in finish after the completion wait.
/// Never synchronizes. 0 when the events are unavailable.
const GpuTimer = struct {
    api: *const Events.Api,
    events: [2]?*anyopaque = .{ null, null },
    ns: u64 = 0,
    fn timing(self: *GpuTimer) K.Timing {
        return .{ .ctx = self, .mark = mark, .resolve = resolve };
    }
    fn mark(raw: *anyopaque, end: bool, stream: *anyopaque) void {
        const self: *GpuTimer = @ptrCast(@alignCast(raw));
        const slot = &self.events[@intFromBool(end)];
        if (slot.* == null and self.api.create(slot, 0) != 0) slot.* = null;
        if (slot.*) |event| if (self.api.record(event, stream) != 0) {
            _ = self.api.destroy(event);
            slot.* = null;
        };
    }
    fn resolve(raw: *anyopaque) void {
        const self: *GpuTimer = @ptrCast(@alignCast(raw));
        const begin = self.events[0] orelse return;
        const end = self.events[1] orelse return;
        var ms: f32 = 0;
        if (self.api.elapsed(&ms, begin, end) == 0 and std.math.isFinite(ms) and ms >= 0) self.ns = @intFromFloat(@as(f64, ms) * 1e6);
    }
    fn deinit(self: *GpuTimer) void {
        for (self.events) |event| if (event) |e| {
            _ = self.api.destroy(e);
        };
        self.events = .{ null, null };
    }
};

pub const Report = struct {
    outcome: Graphs.Outcome = .direct,
    launches: u32 = 0,
    /// GPU time of the node body (CUDA events), 0 if unavailable.
    gpu_ns: u64 = 0,
    kernel_nodes: u64 = 0,
    prestage_ns: u64 = 0,
    /// initWhole + footprint (stream plans, placeholder PCS framing), lane thread.
    init_ns: u64 = 0,
    /// Submit to completion (includes stage/enqueue/wait and finish).
    job_ns: u64 = 0,
    /// finish on the worker thread; deferred PCS proof decode on the lane thread.
    finish_ns: u64 = 0,
    decode_ns: u64 = 0,
    assemble_ns: u64 = 0,
    receipt: api.Receipt = .{},
    /// Class plan sizes (words): MAIN/INTER coefficients, evaluations, trees;
    /// composition coefficients and tree; FIXED coefficients and tree.
    plan_words: [10]u64 = @splat(0),
    heap_words: u64 = 0,
    heap_peak_words: u64 = 0,
    heap_allocations: u64 = 0,
    heap_high_words: u64 = 0,
    phase_peak_words: [Heap.Heap.n_phases]u64 = @splat(0),
    phase_high_words: [Heap.Heap.n_phases]u64 = @splat(0),
    staged_regions: [3]u64 = .{ 0, 0, 0 },
    max_alloc_words: u64 = 0,
    max_unguarded_alloc_words: u64 = 0,
    streamed: bool = false,
    fixed_handoff: bool = false,
    /// The job's declared footprint (class plan).
    footprint: api.Footprint = .{ .device_words = 0 },
};

pub const Prover = struct {
    shared: *const Shared,
    worker: *Worker.Worker,
    graphs: Graphs.Cache,
    /// Fold class regions in worker-persistent memory (outside the arena).
    /// The hybrid window clears it (see OuterNodeJob.persistent_classes).
    persistent_classes: bool = true,

    /// FIXED tree root of `pp`, committed by a FixedJob on this worker.
    /// `handoff`: also leave the coefficients in that persistent region
    /// (FixedReport.handoff_written says whether it happened).
    pub const FixedReport = struct { receipt: api.Receipt = .{}, launches: u32 = 0, body_launches: u32 = 0, outcome: Graphs.Outcome = .direct, gpu_ns: u64 = 0, coefficient_words: u64 = 0, handoff_written: bool = false };
    pub fn fixedRoot(self: *Prover, a: std.mem.Allocator, pp: *const @import("stwo_circuit_frontend").common.preprocessed.PreprocessedCircuit, handoff: ?FixedJob.Handoff, report: ?*FixedReport) ![32]u8 {
        var host = try Prestage.FixedPrecommit.init(a, pp);
        defer host.deinit();
        var job = try FixedJob.FixedJob.init(try host.inputs(), &self.shared.kernels);
        job.graphs = &self.graphs;
        if (handoff) |h| if (h.words >= host.plan.coefficient_words) {
            job.handoff = h;
        };
        var timer: ?GpuTimer = if (self.shared.events) |*ev| GpuTimer{ .api = ev } else null;
        defer if (timer) |*t| t.deinit();
        if (timer) |*t| job.timing = t.timing();
        var done = Done{};
        try self.submitWait(job.job(), &done);
        try done.result;
        if (report) |out| out.* = .{ .receipt = done.receipt, .launches = job.launches, .body_launches = job.body_launches, .outcome = job.outcome, .gpu_ns = if (timer) |t| t.ns else 0, .coefficient_words = host.plan.coefficient_words, .handoff_written = job.handoff_written };
        return job.root orelse error.OuterFixedJobNoRoot;
    }
    fn submitWait(self: *Prover, job: api.Job, done: *Done) !void {
        while (true) {
            self.worker.submit(job, .{ .ctx = done, .done = Done.done }) catch |err| switch (err) {
                error.WorkerBusy => {
                    std.Thread.sleep(50 * std.time.ns_per_us);
                    continue;
                },
                else => return err,
            };
            break;
        }
        done.event.wait();
    }

    pub fn init(a: std.mem.Allocator, shared: *const Shared, worker: *Worker.Worker, policy: Graphs.Policy) Prover {
        return .{ .shared = shared, .worker = worker, .graphs = Graphs.Cache.init(a, shared.graph_api, policy) };
    }
    pub fn deinit(self: *Prover) void {
        self.graphs.deinit();
    }

    const Done = struct {
        event: std.Thread.ResetEvent = .{},
        result: anyerror!void = {},
        receipt: api.Receipt = .{},
        fn done(raw: *anyopaque, c: api.Completion) void {
            const self: *Done = @ptrCast(@alignCast(raw));
            self.result = c.result;
            self.receipt = c.receipt;
            self.event.set();
        }
    };

    /// One node. Reentrant: concurrent callers (one per recursion lane) run
    /// their pre-stage and assembly on their own threads while the worker
    /// pipelines up to `max_outstanding` jobs, so node k+1's host preparation
    /// overlaps node k's GPU work. The graph cache is touched only by the
    /// worker thread (inside enqueue); every other shared table is locked.
    /// `fixed`: the lane's FIXED precommit handoff for this node, used only
    /// when its root is this node's FIXED root (else the node recommits).
    pub fn prove(self: *Prover, a: std.mem.Allocator, input: Prestage.Input, fixed: ?FixedHandoff, report: ?*Report) !Outer.prove.Produced {
        var timer = try std.time.Timer.start();
        const staged = try Prestage.prestage(a, input);
        defer staged.deinit();
        var r = Report{ .prestage_ns = timer.lap() };
        var job = try Job.OuterNodeJob.initWhole(staged, &self.shared.kernels, self.shared.whole());
        defer job.deinit();
        job.graphs = &self.graphs;
        job.persistent_classes = self.persistent_classes;
        job.defer_decode = true;
        if (fixed) |h| if (std.mem.eql(u8, &h.root, &staged.fixed_root)) if (staged.statics.fixed_plan) |fp| if (h.coefficient_words == fp.coefficient_words) {
            job.fixed_handoff = .{ .key = h.region.key, .words = h.region.words };
        };
        // The PCS proof is decoded on the worker and moved into the Produced
        // this function returns, which the caller frees with `a`.
        job.proof_allocator = a;
        var gpu: ?GpuTimer = if (self.shared.events) |*ev| GpuTimer{ .api = ev } else null;
        defer if (gpu) |*t| t.deinit();
        if (gpu) |*t| job.timing = t.timing();
        r.footprint = job.footprint();
        r.init_ns = timer.lap();
        {
            const p = staged.plan();
            const cs = &staged.statics.composition.?;
            const fp = staged.statics.fixed_plan.?;
            r.plan_words = .{ p.main.coefficient_words, p.main.evaluation_words, p.main.tree_words, p.inter.coefficient_words + p.inter_tail_words, p.inter.evaluation_words, p.inter.tree_words, cs.coefficientWords(), cs.treeWords(), fp.coefficient_words, fp.tree_words };
        }
        // Partial report on failure (e.g. a footprint refusal) for diagnostics.
        errdefer if (report) |out| {
            out.* = r;
        };
        var done = Done{};
        while (true) {
            self.worker.submit(job.job(), .{ .ctx = &done, .done = Done.done }) catch |err| switch (err) {
                // Mailbox occupied: the pipeline is full; back off briefly.
                error.WorkerBusy => {
                    std.Thread.sleep(50 * std.time.ns_per_us);
                    continue;
                },
                else => return err,
            };
            break;
        }
        done.event.wait();
        r.job_ns = timer.lap();
        r.receipt = done.receipt;
        if (gpu) |t| r.gpu_ns = t.ns;
        r.outcome = job.report.outcome;
        r.launches = job.report.launches;
        r.kernel_nodes = job.report.kernel_nodes;
        r.heap_words = job.report.heap_words;
        r.heap_peak_words = job.report.heap_peak_words;
        r.heap_allocations = job.report.heap_allocations;
        r.heap_high_words = job.report.heap_high_words;
        r.phase_peak_words = job.report.phase_peak_words;
        r.phase_high_words = job.report.phase_high_words;
        r.staged_regions = job.report.staged_words;
        r.max_alloc_words = job.report.max_alloc_words;
        r.max_unguarded_alloc_words = job.report.max_unguarded_alloc_words;
        r.streamed = job.report.streamed;
        r.fixed_handoff = job.report.fixed_handoff;
        r.finish_ns = job.report.finish_ns;
        try done.result;
        try job.decodeProof();
        r.decode_ns = job.report.decode_ns;
        const produced = try Prestage.assemble(a, input.key, staged, &job);
        r.assemble_ns = timer.read();
        if (report) |out| out.* = r;
        return produced;
    }
};

// ---------------------------------------------------------------------------
// Hybrid mode (M8 Stage A, STWO_RV64_M8_OUTER_JOBS=1): the legacy request
// orchestration and native proving stay as they are; every leaf/fold/root
// node prove reaches device_prove.zig's default-null WholeNode hook and runs
// as an OuterNodeJob on the DeviceWorker of its lane's physical device.
//
// Memory: the legacy native pipeline needs most of each GPU's process arena
// during the native window, and DeviceWorker arenas are static. The worker
// set boots once (`startParked`) and holds an arena only during the
// recursion window of a request: the first node prove (the lanes start after
// native completion, `requires_native_complete`) unparks it, after the legacy
// owners trimmed their unused PCS cache, at a size from the measured free
// arena; `endRequest` (request tail) parks it, returning the arena before
// the next request's native window. Contexts, pinned slots, Provers and their
// graph caches (LRU, aged by request) stay; worker-persistent regions are
// released at park when the FIXED handoff used them.
// STWO_RV64_M8_OUTER_PERSIST_WINDOW=0 starts and stops the workers per request.
//
// One `Hybrid` per service, one `Lane` per recursion lane. A Lane wraps the
// lane's legacy om31 Factory: host plan preparation, tape readiness,
// admission and the FIXED precommit are the legacy ones; the node proof is
// the job.
const Dev = Outer.device_prove;
const Assignment = @import("outer_assignment.zig");
const Jobs = @import("jobs/mod.zig");
const Circuit = @import("stwo_circuit_frontend");
const Service = @import("pcs_native.zig");
const Memory = @import("runtime_memory.zig");
const NativeAbi = @import("pcs_native_abi.zig");

/// STWO_RV64_M8_OUTER_JOBS: unset or "0" → legacy; "1" → hybrid; else fail closed.
pub fn hybridSelected() !bool {
    const value = std.posix.getenv("STWO_RV64_M8_OUTER_JOBS") orelse return false;
    if (std.mem.eql(u8, value, "0")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    return error.InvalidM8OuterJobsSelection;
}

/// The FIXED precommit's coefficients for the node of `ordinal` on this
/// lane, left in `region` by the FixedJob that computed `root`.
pub const FixedHandoff = struct {
    ordinal: u32,
    root: [32]u8,
    coefficient_words: u64,
    region: FixedJob.Handoff,
};
/// Stager.persistent key of a lane's handoff region of `words` words.
fn handoffKey(lane: usize, words: usize) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64/m8/outer-job/fixed-handoff/v1\x00");
    var buf: [16]u8 = undefined;
    std.mem.writeInt(u64, buf[0..8], lane, .little);
    std.mem.writeInt(u64, buf[8..16], words, .little);
    h.update(&buf);
    return h.finalResult();
}

/// A host-prepared assignment plan plus the producer hints that were live
/// when it was built (they are threadlocals of the prep thread, not of the
/// device lane that later proves the node).
const HostBox = struct {
    allocator: std.mem.Allocator,
    prepared: Assignment.Prepared,
    class: ?[32]u8,
    is_leaf: bool,
    fn destroy(raw: *anyopaque) void {
        const self: *HostBox = @ptrCast(@alignCast(raw));
        self.prepared.deinit();
        self.allocator.destroy(self);
    }
};

/// Owner of a job-precommitted FIXED tree descriptor (no device storage).
const FixedOwner = struct {
    allocator: std.mem.Allocator,
    columns: []@import("stwo_prover_api").device_pcs.Column,
    const token: u64 = 0x4d38_4f55_5452_4658; // "M8OUTRFX"
    var no_storage: u32 = 0;
    fn release(raw: *anyopaque) void {
        const self: *FixedOwner = @ptrCast(@alignCast(raw));
        self.allocator.free(self.columns);
        self.allocator.destroy(self);
    }
};

pub const Lane = struct {
    hybrid: *Hybrid,
    index: usize,
    physical_device: u32,
    legacy: Dev.Factory,
    mutex: std.Thread.Mutex = .{},
    staged: ?*HostBox = null,
    staged_graph: ?*const anyopaque = null,
    nodes: u64 = 0,
    /// FIXED precommit handoff of the node this lane proves next.
    handoff: ?FixedHandoff = null,
    /// Words of this lane's handoff region in the open window (0: none; set
    /// by Hybrid.open from `fixed_max_words`, which the window reserved).
    fixed_cap_words: usize = 0,
    /// Largest FIXED coefficient image this lane has precommitted.
    fixed_max_words: std.atomic.Value(u64) = .init(0),

    pub fn factory(self: *Lane) Dev.Factory {
        const l = self.legacy;
        return .{
            .extension = l.extension,
            .controller = null,
            .whole_node = .{ .context = self, .prove = wholeNode },
            .requires_native_complete = l.requires_native_complete,
            .context = self,
            .prepare_host = prepareHost,
            .memory_admission_enabled = if (l.memory_admission_enabled != null) memoryAdmission else null,
            .tape_ready = if (l.tape_ready != null) tapeReady else null,
            .stage_host = stageHost,
            .unstage_host = unstageHost,
            .precommit_fixed = if (l.precommit_fixed != null) precommitFixed else null,
            .prepare = refuseValues,
            .prepare_from_circuit = bypassed,
        };
    }
    fn of(raw: *anyopaque) *Lane {
        return @ptrCast(@alignCast(raw));
    }
    fn memoryAdmission(raw: *anyopaque) bool {
        const self = of(raw);
        return self.legacy.memory_admission_enabled.?(self.legacy.context);
    }
    fn tapeReady(raw: *anyopaque, class: [32]u8) bool {
        const self = of(raw);
        return self.legacy.tape_ready.?(self.legacy.context, class);
    }
    /// Same plan the legacy prepare_host builds (outer_source.zig prepareHost).
    fn prepareHost(raw: *anyopaque, a: std.mem.Allocator, graph: *const Circuit.builder.Context(Q)) !Dev.HostPrepared {
        const self = of(raw);
        if (!graph.trace_only or !graph.finalized or !graph.record_gates) return error.TraceOnlyGraphRequired;
        const box = try a.create(HostBox);
        errdefer a.destroy(box);
        box.* = .{ .allocator = a, .prepared = try Assignment.Prepared.init(a, graph, &self.hybrid.base), .class = Dev.class_hint, .is_leaf = Dev.class_is_leaf };
        return .{ .context = box, .graph = graph, .destroy = HostBox.destroy };
    }
    fn stageHost(raw: *anyopaque, host: Dev.HostPrepared) !void {
        const self = of(raw);
        if (host.destroy != HostBox.destroy) {
            host.destroy(host.context);
            return error.ForeignHostPreparedAssignment;
        }
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.staged != null) {
            host.destroy(host.context);
            return error.OuterProofAlreadyActive;
        }
        self.staged = @ptrCast(@alignCast(host.context));
        self.staged_graph = host.graph;
    }
    fn unstageHost(raw: *anyopaque) void {
        const self = of(raw);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.staged) |box| HostBox.destroy(box);
        self.staged = null;
        self.staged_graph = null;
    }
    fn takeStaged(self: *Lane, graph: *const anyopaque) ?*HostBox {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.staged_graph != graph) return null;
        const box = self.staged;
        self.staged = null;
        self.staged_graph = null;
        return box;
    }
    /// FIXED precommit. Default (hybrid): a FixedJob on this lane's worker
    /// computes the root and leaves the coefficients in the lane's handoff
    /// region when the window has one (the node binds them, matched by
    /// ordinal and root); otherwise the node job recommits FIXED in its own
    /// memory and checks that root. The returned tree names no device
    /// storage: its column descriptors only satisfy device_prove's structural
    /// entry validation (validateTree) and are never dereferenced, because the
    /// WholeNode hook consumes the node. STWO_RV64_M8_OUTER_FIXED_JOB=0 keeps
    /// the legacy owner's device precommit (root + legacy tree).
    fn precommitFixed(raw: *anyopaque, a: std.mem.Allocator, pp: *const Circuit.common.preprocessed.PreprocessedCircuit, ordinal: u32) !Dev.PrecommittedFixed {
        const self = of(raw);
        self.handoff = null;
        if (!self.hybrid.knobs.fixed_job) {
            var fixed = try self.legacy.precommit_fixed.?(self.legacy.context, a, pp, ordinal);
            fixed.whole_node = .{ .context = self, .prove = wholeNode };
            return fixed;
        }
        var timer = try std.time.Timer.start();
        const prover = try self.hybrid.prover(self.index);
        var fr: Prover.FixedReport = .{};
        // The coefficients go to this lane's persistent handoff region when
        // the window reserved one large enough (Hybrid.open); the node then
        // binds it instead of packing, uploading and committing FIXED again.
        const region: ?FixedJob.Handoff = if (self.fixed_cap_words != 0) .{ .key = handoffKey(self.index, self.fixed_cap_words), .words = self.fixed_cap_words } else null;
        const root = try prover.fixedRoot(a, pp, region, &fr);
        _ = self.fixed_max_words.fetchMax(fr.coefficient_words, .monotonic);
        if (fr.handoff_written) {
            self.handoff = .{ .ordinal = ordinal, .root = root, .coefficient_words = fr.coefficient_words, .region = region.? };
            self.hybrid.handoff_live.store(true, .release);
        }
        const receipt = fr.receipt;
        const owner = try a.create(FixedOwner);
        errdefer a.destroy(owner);
        const columns = try a.alloc(@import("stwo_prover_api").device_pcs.Column, pp.columns.len);
        for (columns, pp.columns) |*out, column| out.* = .{ .log_size = column.logSize(), .device = .{ .words = @ptrCast(&FixedOwner.no_storage), .count = column.values.len, .context_token = FixedOwner.token, .generation = 1 } };
        owner.* = .{ .allocator = a, .columns = columns };
        var statement: [32]u8 = undefined;
        {
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update("rv64/m8/outer-job/fixed-precommit-scope/v1\x00");
            h.update(&root);
            statement = h.finalResult();
        }
        std.debug.print("GPU_M8_OUTER_FIXED ordinal={d} device={d} columns={d} outcome={s} launches={d} body_launches={d} stage_ns={d} enqueue_ns={d} wait_ns={d} gpu_ns={d} host_waits={d} coefficient_words={d} handoff_words={d} handoff={} wall_ns={d}\n", .{ ordinal, self.physical_device, columns.len, @tagName(fr.outcome), fr.launches, fr.body_launches, receipt.stage_ns, receipt.enqueue_ns, receipt.wait_ns, fr.gpu_ns, receipt.host_waits, fr.coefficient_words, self.fixed_cap_words, fr.handoff_written, timer.read() });
        return .{ .context = owner, .whole_node = .{ .context = self, .prove = wholeNode }, .tree = .{ .root = root, .columns = columns }, .scope = .{ .statement = statement, .fixed = @splat(0), .main = @splat(0), .ordinal = ordinal }, .prepare_from_circuit = bypassed, .release = FixedOwner.release };
    }
    fn refuseValues(_: *anyopaque, _: std.mem.Allocator, _: *const Outer.prove.Authority, _: []const Q, _: @import("stwo_prover_api").device_pcs.Scope) !Dev.Source {
        return error.M8OuterJobsRequireTraceOnlyNode;
    }
    fn bypassed(_: *anyopaque, _: std.mem.Allocator, _: *const Outer.prove.Authority, _: *const Circuit.builder.Context(Q), _: @import("stwo_prover_api").device_pcs.Scope) !Dev.Source {
        return error.M8OuterWholeNodeBypassed;
    }

    fn wholeNode(raw: *anyopaque, a: std.mem.Allocator, key: *const Outer.prove.Authority, graph: *const Circuit.builder.Context(Q), expected: []const Q, ordinal: u32) !Outer.prove.Produced {
        const self = of(raw);
        var input = Prestage.Input{ .key = key, .graph = graph, .expected = expected, .ordinal = ordinal, .library = &self.hybrid.base, .class = Dev.class_hint, .is_leaf = Dev.class_is_leaf, .seed_tape = Dev.seed_tape, .blake_sample_inputs = Dev.blake_sample_inputs };
        if (self.takeStaged(graph)) |box| {
            input.prepared = box.prepared;
            input.class = box.class;
            input.is_leaf = box.is_leaf;
            box.allocator.destroy(box);
        }
        const prover = self.hybrid.prover(self.index) catch |err| {
            if (input.prepared) |*p| p.deinit();
            return err;
        };
        // Negative-path test hook (default unset): STWO_RV64_M8_OUTER_FAULT_ORDINAL=n
        // fails node n before its job, exactly where a footprint refusal
        // returns, so the request error path and teardown can be exercised.
        if (self.hybrid.knobs.fault_ordinal == ordinal) {
            if (input.prepared) |*p| p.deinit();
            std.debug.print("GPU_M8_OUTER_NODE ordinal={d} device={d} error=M8OuterInjectedFault\n", .{ ordinal, self.physical_device });
            return error.M8OuterInjectedFault;
        }
        var r: Report = .{};
        var timer = try std.time.Timer.start();
        const handoff = if (self.handoff) |h| (if (h.ordinal == ordinal) h else null) else null;
        self.handoff = null;
        const produced = prover.prove(a, input, handoff, &r) catch |err| {
            std.debug.print("GPU_M8_OUTER_NODE ordinal={d} device={d} error={s} declared_device_words={d} declared_staged_words={d} slab_words={d} pinned_words={d} plan_words={any} streamed={} heap_high_words={d} phase_peak_words={any} phase_high_words={any}\n", .{ ordinal, self.physical_device, @errorName(err), r.footprint.device_words, r.footprint.staged_words, r.footprint.slab_words, r.footprint.pinned_words, r.plan_words, r.streamed, r.heap_high_words, r.phase_peak_words, r.phase_high_words });
            return err;
        };
        self.nodes += 1;
        const fp = r.footprint;
        std.debug.print("GPU_M8_OUTER_NODE ordinal={d} device={d} leaf={} adopted_plan={} outcome={s} launches={d} kernel_nodes={d} host_waits={d} d2h_bytes={d} stage_ns={d} enqueue_ns={d} wait_ns={d} gpu_ns={d} prestage_ns={d} job_ns={d} assemble_ns={d} wall_ns={d} declared_device_words={d} declared_staged_words={d} slab_words={d} pinned_words={d} staged_words={d} arena_peak_words={d} heap_words={d} heap_peak_words={d} heap_allocations={d} plan_words={any} sequence={d} placement={s}\n", .{ ordinal, r.receipt.device, input.is_leaf, input.prepared != null, @tagName(r.outcome), r.launches, r.kernel_nodes, r.receipt.host_waits, r.receipt.d2h_bytes, r.receipt.stage_ns, r.receipt.enqueue_ns, r.receipt.wait_ns, r.gpu_ns, r.prestage_ns, r.job_ns, r.assemble_ns, timer.read(), fp.device_words, fp.staged_words, fp.slab_words, fp.pinned_words, r.receipt.staged_words, r.receipt.arena_peak_words, r.heap_words, r.heap_peak_words, r.heap_allocations, r.plan_words, r.receipt.sequence, @tagName(r.receipt.placement) });
        std.debug.print("GPU_M8_OUTER_NODE_HOST ordinal={d} device={d} prestage_ns={d} init_ns={d} job_ns={d} stage_ns={d} enqueue_ns={d} wait_ns={d} finish_ns={d} decode_ns={d} assemble_ns={d} fixed_handoff={}\n", .{ ordinal, r.receipt.device, r.prestage_ns, r.init_ns, r.job_ns, r.receipt.stage_ns, r.receipt.enqueue_ns, r.receipt.wait_ns, r.finish_ns, r.decode_ns, r.assemble_ns, r.fixed_handoff });
        std.debug.print("GPU_M8_OUTER_NODE_MEM ordinal={d} device={d} streamed={} heap_high_words={d} max_alloc_words={d} max_unguarded_alloc_words={d} phase_peak_words={any} phase_high_words={any} staged_regions={any}\n", .{ ordinal, r.receipt.device, r.streamed, r.heap_high_words, r.max_alloc_words, r.max_unguarded_alloc_words, r.phase_peak_words, r.phase_high_words, r.staged_regions });
        return produced;
    }
};

/// The recursion window's devices: booted workers, resolved symbols and one
/// Prover (graph cache) per physical device, shared by every lane on it.
/// With STWO_RV64_RECURSION_LANES_PER_DEVICE=2 two lane threads prestage and
/// assemble concurrently against one worker, so the worker's 3-stage loop
/// stages node k+1 while node k runs (the pair serializes if it does not fit).
const Window = struct {
    set: *Jobs.WorkerSet,
    shared: Shared,
    provers: []Prover,
    /// Prover index of each lane.
    lane_prover: [4]usize = @splat(0),
    started_ns: u64,
};

pub const Hybrid = struct {
    allocator: std.mem.Allocator,
    /// Base image handle for host-side plan preparation (prepare_host runs
    /// before the window exists; Prepared.rebind moves it onto the window's).
    base: std.DynLib,
    library: []const u8,
    fs_path: []const u8,
    services: []const *Service.Context = &.{},
    lanes: []Lane = &.{},
    mutex: std.Thread.Mutex = .{},
    window: ?Window = null,
    windows: u64 = 0,
    /// The window's arena is live (between the request's first node and
    /// endRequest). With a persistent window the WorkerSet, Shared symbols
    /// and Provers (graph caches) outlive requests: endRequest parks the
    /// workers (frees only their static arenas), the next request unparks.
    open_now: bool = false,
    /// STWO_RV64_M8_OUTER_PERSIST_WINDOW: unset/"1" -> persistent (boot once,
    /// park/unpark per request); "0" -> create/destroy the workers per request.
    persist: bool = true,
    knobs: Knobs = .{},
    /// A FIXED handoff region was acquired in the open window: park releases
    /// worker-persistent regions so the native window gets the memory back.
    handoff_live: std.atomic.Value(bool) = .init(false),

    /// Every hybrid knob, parsed strictly once at create (outer_env.zig;
    /// jobs/README.md "Outer job environment").
    pub const Knobs = struct {
        /// STWO_RV64_M8_OUTER_FIXED_JOB: "1"/unset -> FIXED precommit as a
        /// FixedJob; "0" -> the legacy owner's device precommit.
        fixed_job: bool = true,
        /// STWO_RV64_M8_OUTER_FIXED_HANDOFF: "1"/unset -> the FixedJob leaves
        /// the coefficients for the node (from the second window on, once the
        /// lane's FIXED size is known and reserved); "0" -> the node recommits.
        fixed_handoff: bool = true,
        /// STWO_RV64_M8_OUTER_PERSISTENT_CLASSES=1: fold class regions in
        /// worker-persistent memory (default off in the hybrid window).
        persistent_classes: bool = false,
        /// STWO_RV64_M8_OUTER_FAULT_ORDINAL=n: fail node n (negative test).
        fault_ordinal: ?u32 = null,
        /// STWO_RV64_M8_OUTER_RESERVE_BYTES (default 1 GiB).
        reserve_bytes: u64 = 1 << 30,
        graphs: Graphs.Policy = .{},
        pub fn fromEnv() !Knobs {
            var k = Knobs{};
            k.fixed_job = try Env.flag("STWO_RV64_M8_OUTER_FIXED_JOB", k.fixed_job);
            k.fixed_handoff = try Env.flag("STWO_RV64_M8_OUTER_FIXED_HANDOFF", k.fixed_handoff) and k.fixed_job;
            k.persistent_classes = try Env.flag("STWO_RV64_M8_OUTER_PERSISTENT_CLASSES", k.persistent_classes);
            k.fault_ordinal = try Env.optionalUnsigned(u32, "STWO_RV64_M8_OUTER_FAULT_ORDINAL");
            k.reserve_bytes = try Env.unsigned(u64, "STWO_RV64_M8_OUTER_RESERVE_BYTES", k.reserve_bytes);
            k.graphs = try Graphs.Policy.fromEnv();
            // Node-job knobs are parsed per job; check them here so a bad
            // value fails the service at create, not at the first node.
            _ = try Env.flag("STWO_RV64_M8_OUTER_STREAM", true);
            _ = try Env.unsigned(usize, "STWO_RV64_M8_OUTER_STREAM_CHUNK_WORDS", 0);
            _ = try Env.unsigned(u64, "STWO_RV64_M8_OUTER_PCS_RESERVE_TREES", 0);
            _ = try Env.optionalUnsigned(u64, "STWO_RV64_M8_OUTER_DECLARE_WORDS");
            _ = try Env.flag("STWO_RV64_M8_OUTER_LEAF_PERSISTENT", false);
            return k;
        }
    };

    pub fn create(a: std.mem.Allocator, library: []const u8) !*Hybrid {
        const fs_path = std.posix.getenv("STWO_RV64_M8_OUTER_FS_LIBRARY") orelse return error.MissingM8OuterFsLibrary;
        _ = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return error.MissingM8JobsLibrary;
        const knobs = try Knobs.fromEnv();
        const persist = try Env.flag("STWO_RV64_M8_OUTER_PERSIST_WINDOW", true);
        const self = try a.create(Hybrid);
        errdefer a.destroy(self);
        self.* = .{ .allocator = a, .base = try std.DynLib.open(library), .library = library, .fs_path = fs_path, .persist = persist, .knobs = knobs };
        return self;
    }
    /// Replaces each lane's factory with a job-backed one. `lanes`: a slice of
    /// execution_wrap.Lane (`physical_device`, `factory`); `services`: the
    /// legacy native owner of every physical device (trimmed before a window).
    pub fn install(self: *Hybrid, lanes: anytype, services: []const *Service.Context) !void {
        if (self.lanes.len != 0) return error.M8OuterLanesAlreadyInstalled;
        if (lanes.len == 0 or lanes.len > 4) return error.M8OuterJobsUnsupportedLaneFactory;
        if (@import("stwo_riscv_cpu_integration").rv64_om31_outer_wrap.hybridProfileActive()) return error.M8OuterJobsUnsupportedHybridProfile;
        const made = try self.allocator.alloc(Lane, lanes.len);
        errdefer self.allocator.free(made);
        for (lanes, made, 0..) |*lane, *out, i| {
            if (lane.factory.whole_node != null or lane.factory.extension != null) return error.M8OuterJobsUnsupportedLaneFactory;
            out.* = .{ .hybrid = self, .index = i, .physical_device = lane.physical_device, .legacy = lane.factory };
        }
        self.services = try self.allocator.dupe(*Service.Context, services);
        self.lanes = made;
        for (lanes, made) |*lane, *out| lane.factory = out.factory();
        std.debug.print("GPU_M8_OUTER_JOBS hybrid lanes={d} devices={d}\n", .{ made.len, services.len });
    }

    fn prover(self: *Hybrid, lane: usize) !*Prover {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.open_now) try self.open();
        const w = &self.window.?;
        return &w.provers[w.lane_prover[lane]];
    }

    const Trim = struct {
        service: *Service.Context,
        released: u64 = 0,
        available: u64 = 0,
        failure: ?anyerror = null,
        fn run(raw: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
            const job: *Trim = @ptrCast(@alignCast(data.?));
            job.released = (Memory.trimUnused(&job.service.library, job.service.session) catch |err| {
                job.failure = err;
                return 1;
            }) orelse 0;
            const snapshot = Memory.query(&job.service.library, raw) catch |err| {
                job.failure = err;
                return 1;
            };
            job.available = @min((snapshot.available() catch unreachable).large, snapshot.largest_virtual_free);
            return 0;
        }
    };

    /// Arena of the window: STWO_RV64_M8_JOBS_ARENA_BYTES caps it; the
    /// smallest free large arena range after trimming, less
    /// STWO_RV64_M8_OUTER_RESERVE_BYTES (default 1 GiB: worker-persistent
    /// twiddle/class regions live outside the worker arena; with
    /// STWO_RV64_M8_OUTER_FIXED_JOB=0 the legacy FIXED precommit needs ~4 GiB),
    /// less the FIXED handoff regions of the device's lanes (sized from the
    /// largest FIXED image each lane precommitted in earlier windows).
    /// Boot arena of a persistent window (words): enough for the workers'
    /// boot self-test; every request unparks at its measured size.
    const boot_arena_words: usize = 1 << 26;
    /// Per-device handoff words of this window; sets every lane's cap.
    fn planHandoff(self: *Hybrid) u64 {
        var per_device: [8]u64 = @splat(0);
        for (self.lanes) |*lane| {
            const max = lane.fixed_max_words.load(.monotonic);
            lane.fixed_cap_words = if (self.knobs.fixed_handoff and max != 0) std.mem.alignForward(usize, @intCast(max), Worker.Arena.granule) else 0;
            lane.handoff = null;
            per_device[lane.physical_device % per_device.len] += lane.fixed_cap_words;
        }
        var worst: u64 = 0;
        for (per_device) |w| worst = @max(worst, w);
        return worst;
    }
    fn open(self: *Hybrid) !void {
        var timer = try std.time.Timer.start();
        var config = try Jobs.Config.fromEnv();
        const handoff_words = self.planHandoff();
        const reserve: u64 = self.knobs.reserve_bytes + 4 * handoff_words;
        var available: u64 = std.math.maxInt(u64);
        var released: u64 = 0;
        for (self.services) |service| {
            var job = Trim{ .service = service };
            const status = service.submit(service.session, Trim.run, &job);
            if (job.failure) |err| return err;
            if (status != 0) return error.M8OuterLegacyTrimFailed;
            available = @min(available, job.available);
            released += job.released;
        }
        const usable = if (available > reserve) available - reserve else 0;
        // Unset STWO_RV64_M8_JOBS_ARENA_BYTES: no cap beyond the headroom.
        const cap: usize = if (std.posix.getenv("STWO_RV64_M8_JOBS_ARENA_BYTES") != null) config.arena_words else std.math.maxInt(usize);
        const words = std.mem.alignBackward(usize, @min(cap, @as(usize, @intCast(usable / 4))), Jobs.worker.Arena.granule);
        if (words == 0) return error.M8OuterNoArenaHeadroom;
        const trim_ns = timer.lap();
        if (self.persist) if (self.window) |*w| {
            // Parked window from an earlier request: re-acquire the arenas
            // only, all or none (a partial unpark parks the others again; a
            // window that cannot be restored is torn down and rebooted).
            const r = OuterWindow.unparkAll(w.set, words) catch |err| {
                std.debug.print("GPU_M8_OUTER_WINDOW unpark_failed error={s} arena_words={d} parked={}\n", .{ @errorName(err), words, w.set.parked() });
                if (!w.set.parked()) self.teardown(0, timer);
                return err;
            };
            self.open_now = true;
            self.windows += 1;
            for (w.provers) |*p| p.graphs.noteRequest();
            var moved = false;
            for (r.same_base[0..r.workers]) |same| moved = moved or !same;
            std.debug.print("GPU_M8_OUTER_WINDOW open window={d} arena_words={d} available_bytes={d} reserve_bytes={d} handoff_words={d} trimmed_bytes={d} trim_ns={d} start_ns={d} unpark_ns={d} moved={} persistent=true lanes={d} provers={d}\n", .{ self.windows, words, available, reserve, handoff_words, released, trim_ns, timer.read(), r.ns, moved, self.lanes.len, w.provers.len });
            return;
        };
        // Persistent: boot on a small arena, park, then unpark at the
        // request's size (the same path every later request takes).
        config.arena_words = if (self.persist) @min(words, boot_arena_words) else words;
        const set = if (self.persist) try Jobs.WorkerSet.startParked(self.allocator, self.library, config) else try Jobs.WorkerSet.startWith(self.allocator, self.library, config);
        errdefer set.stop(self.allocator);
        const unpark_ns: u64 = if (self.persist) (try set.unpark(words)).ns else 0;
        var shared = try Shared.init(&set.libs.base, &set.libs.addon, self.fs_path);
        errdefer shared.deinit();
        var workers: [4]*Worker.Worker = undefined;
        var lane_prover: [4]usize = @splat(0);
        var unique: usize = 0;
        for (self.lanes, 0..) |lane, i| {
            const worker = for (set.slice()) |candidate| {
                if (candidate.device_ordinal == lane.physical_device) break candidate;
            } else return error.M8OuterJobsMissingLaneWorker;
            lane_prover[i] = for (workers[0..unique], 0..) |seen, j| {
                if (seen == worker) break j;
            } else blk: {
                workers[unique] = worker;
                unique += 1;
                break :blk unique - 1;
            };
        }
        const provers = try self.allocator.alloc(Prover, unique);
        self.window = .{ .set = set, .shared = shared, .provers = provers, .lane_prover = lane_prover, .started_ns = 0 };
        const w = &self.window.?;
        self.open_now = true;
        for (provers, workers[0..provers.len]) |*p, worker| {
            p.* = Prover.init(self.allocator, &w.shared, worker, self.knobs.graphs);
            p.persistent_classes = self.knobs.persistent_classes;
        }
        self.windows += 1;
        std.debug.print("GPU_M8_OUTER_WINDOW open window={d} arena_words={d} available_bytes={d} reserve_bytes={d} handoff_words={d} trimmed_bytes={d} trim_ns={d} start_ns={d} unpark_ns={d} moved=false persistent={} lanes={d} provers={d}\n", .{ self.windows, words, available, reserve, handoff_words, released, trim_ns, timer.read(), unpark_ns, self.persist, self.lanes.len, unique });
    }

    /// Request tail (every lane is idle): park the window's workers (their
    /// static arenas return to the legacy owner; the persistent regions too
    /// when a FIXED handoff used them), or stop them when the window is not
    /// persistent or the park failed.
    pub fn endRequest(self: *Hybrid) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.open_now) return;
        self.open_now = false;
        var timer = std.time.Timer.start() catch unreachable;
        var nodes: u64 = 0;
        for (self.lanes) |*lane| {
            nodes += lane.nodes;
            lane.nodes = 0;
            lane.handoff = null;
            lane.fixed_cap_words = 0;
        }
        const release = self.handoff_live.swap(false, .acq_rel);
        if (self.persist) {
            // Park: free the static arenas (legacy native window of the next
            // request needs them) and, if a FIXED handoff region was used,
            // the persistent regions; contexts, pinned slots and graph caches
            // stay. A failed park tears down.
            if (self.window.?.set.park(.{ .release_persistent = release })) |r| {
                std.debug.print("GPU_M8_OUTER_WINDOW close window={d} nodes={d} close_ns={d} park_ns={d} released_persistent={} persistent=true\n", .{ self.windows, nodes, timer.read(), r.ns, release });
                return;
            } else |err| std.debug.print("GPU_M8_OUTER_WINDOW park_failed error={s}; stopping workers\n", .{@errorName(err)});
        }
        self.teardown(nodes, timer);
    }
    fn teardown(self: *Hybrid, nodes: u64, timer_in: std.time.Timer) void {
        var timer = timer_in;
        var w = self.window orelse return;
        self.window = null;
        self.open_now = false;
        self.handoff_live.store(false, .release);
        for (w.provers) |*p| p.deinit();
        self.allocator.free(w.provers);
        w.shared.deinit();
        w.set.stop(self.allocator);
        std.debug.print("GPU_M8_OUTER_WINDOW close window={d} nodes={d} close_ns={d} stopped=true\n", .{ self.windows, nodes, timer.read() });
    }

    pub fn destroy(self: *Hybrid) void {
        self.endRequest();
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.teardown(0, std.time.Timer.start() catch unreachable);
        }
        const a = self.allocator;
        for (self.lanes) |*lane| Lane.unstageHost(lane);
        a.free(self.lanes);
        a.free(self.services);
        self.base.close();
        a.destroy(self);
    }
};
