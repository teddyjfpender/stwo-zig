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

pub const Shared = struct {
    kernels: K.Kernels,
    composition: Comp.Kernels,
    pcs: NativePcs.Symbols,
    wide: bool,
    graph_api: Graphs.Api,
    fs: std.DynLib,
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

pub const Report = struct {
    outcome: Graphs.Outcome = .direct,
    launches: u32 = 0,
    kernel_nodes: u64 = 0,
    prestage_ns: u64 = 0,
    job_ns: u64 = 0,
    assemble_ns: u64 = 0,
    receipt: api.Receipt = .{},
    /// Class plan sizes (words): MAIN/INTER coefficients, evaluations, trees;
    /// composition coefficients and tree; FIXED coefficients and tree.
    plan_words: [10]u64 = @splat(0),
    heap_words: u64 = 0,
    heap_peak_words: u64 = 0,
    heap_allocations: u64 = 0,
    /// The job's declared footprint (class plan).
    footprint: api.Footprint = .{ .device_words = 0 },
};

pub const Prover = struct {
    shared: *const Shared,
    worker: *Worker.Worker,
    graphs: Graphs.Cache,

    /// FIXED tree root of `pp`, committed by a FixedJob on this worker.
    pub fn fixedRoot(self: *Prover, a: std.mem.Allocator, pp: *const @import("stwo_circuit_frontend").common.preprocessed.PreprocessedCircuit, receipt: ?*api.Receipt) ![32]u8 {
        var host = try Prestage.FixedPrecommit.init(a, pp);
        defer host.deinit();
        var job = try FixedJob.FixedJob.init(try host.inputs(), &self.shared.kernels);
        var done = Done{};
        try self.submitWait(job.job(), &done);
        try done.result;
        if (receipt) |out| out.* = done.receipt;
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

    pub fn init(a: std.mem.Allocator, shared: *const Shared, worker: *Worker.Worker) Prover {
        return .{ .shared = shared, .worker = worker, .graphs = Graphs.Cache.init(a, shared.graph_api, Graphs.Policy.fromEnv()) };
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
    pub fn prove(self: *Prover, a: std.mem.Allocator, input: Prestage.Input, report: ?*Report) !Outer.prove.Produced {
        var timer = try std.time.Timer.start();
        const staged = try Prestage.prestage(a, input);
        defer staged.deinit();
        var r = Report{ .prestage_ns = timer.lap() };
        var job = try Job.OuterNodeJob.initWhole(staged, &self.shared.kernels, self.shared.whole());
        defer job.deinit();
        job.graphs = &self.graphs;
        r.footprint = job.footprint();
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
        try done.result;
        r.job_ns = timer.lap();
        r.receipt = done.receipt;
        r.outcome = job.report.outcome;
        r.launches = job.report.launches;
        r.kernel_nodes = job.report.kernel_nodes;
        r.heap_words = job.report.heap_words;
        r.heap_peak_words = job.report.heap_peak_words;
        r.heap_allocations = job.report.heap_allocations;
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
// set therefore lives for the recursion window of one request only: it is
// started by the first node prove (the lanes start after native completion,
// `requires_native_complete`), after the legacy owners trimmed their unused
// PCS cache, with an arena sized from the measured free arena; and stopped
// by `endRequest` (request tail), returning the memory before the next
// request's native window. (Persistent class regions and captured graphs
// are rebuilt per request; a worker arena park/unpark in runtime would keep
// them across requests: M8-INTERFACES wire-outer.)
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
    /// The legacy device FIXED precommit, unchanged (root + legacy tree, which
    /// outer_wrap releases after the proof); the node itself goes to the job.
    /// FIXED precommit. Default (hybrid): a FixedJob on this lane's worker
    /// computes the root and nothing else; the node job recommits FIXED in its
    /// own memory and checks that root. The returned tree names no device
    /// storage: its column descriptors only satisfy device_prove's structural
    /// entry validation (validateTree) and are never dereferenced, because the
    /// WholeNode hook consumes the node. STWO_RV64_M8_OUTER_FIXED_JOB=0 keeps
    /// the legacy owner's device precommit (root + legacy tree).
    fn precommitFixed(raw: *anyopaque, a: std.mem.Allocator, pp: *const Circuit.common.preprocessed.PreprocessedCircuit, ordinal: u32) !Dev.PrecommittedFixed {
        const self = of(raw);
        const legacy = if (std.posix.getenv("STWO_RV64_M8_OUTER_FIXED_JOB")) |v| std.mem.eql(u8, v, "0") else false;
        if (legacy) {
            var fixed = try self.legacy.precommit_fixed.?(self.legacy.context, a, pp, ordinal);
            fixed.whole_node = .{ .context = self, .prove = wholeNode };
            return fixed;
        }
        var timer = try std.time.Timer.start();
        const prover = try self.hybrid.prover(self.index);
        var receipt: api.Receipt = .{};
        const root = try prover.fixedRoot(a, pp, &receipt);
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
        std.debug.print("GPU_M8_OUTER_FIXED ordinal={d} device={d} columns={d} stage_ns={d} enqueue_ns={d} wait_ns={d} host_waits={d} wall_ns={d}\n", .{ ordinal, self.physical_device, columns.len, receipt.stage_ns, receipt.enqueue_ns, receipt.wait_ns, receipt.host_waits, timer.read() });
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
        var r: Report = .{};
        var timer = try std.time.Timer.start();
        const produced = prover.prove(a, input, &r) catch |err| {
            std.debug.print("GPU_M8_OUTER_NODE ordinal={d} device={d} error={s} declared_device_words={d} declared_staged_words={d} slab_words={d} pinned_words={d} plan_words={any}\n", .{ ordinal, self.physical_device, @errorName(err), r.footprint.device_words, r.footprint.staged_words, r.footprint.slab_words, r.footprint.pinned_words, r.plan_words });
            return err;
        };
        self.nodes += 1;
        const fp = r.footprint;
        std.debug.print("GPU_M8_OUTER_NODE ordinal={d} device={d} leaf={} adopted_plan={} outcome={s} launches={d} kernel_nodes={d} host_waits={d} d2h_bytes={d} stage_ns={d} enqueue_ns={d} wait_ns={d} prestage_ns={d} job_ns={d} assemble_ns={d} wall_ns={d} declared_device_words={d} declared_staged_words={d} slab_words={d} pinned_words={d} staged_words={d} arena_peak_words={d} heap_words={d} heap_peak_words={d} heap_allocations={d} plan_words={any} sequence={d} placement={s}\n", .{ ordinal, r.receipt.device, input.is_leaf, input.prepared != null, @tagName(r.outcome), r.launches, r.kernel_nodes, r.receipt.host_waits, r.receipt.d2h_bytes, r.receipt.stage_ns, r.receipt.enqueue_ns, r.receipt.wait_ns, r.prestage_ns, r.job_ns, r.assemble_ns, timer.read(), fp.device_words, fp.staged_words, fp.slab_words, fp.pinned_words, r.receipt.staged_words, r.receipt.arena_peak_words, r.heap_words, r.heap_peak_words, r.heap_allocations, r.plan_words, r.receipt.sequence, @tagName(r.receipt.placement) });
        return produced;
    }
};

/// The recursion window's devices: booted workers, resolved symbols and one
/// Prover (graph cache) per lane.
const Window = struct {
    set: *Jobs.WorkerSet,
    shared: Shared,
    provers: []Prover,
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

    pub fn create(a: std.mem.Allocator, library: []const u8) !*Hybrid {
        const fs_path = std.posix.getenv("STWO_RV64_M8_OUTER_FS_LIBRARY") orelse return error.MissingM8OuterFsLibrary;
        _ = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return error.MissingM8JobsLibrary;
        const self = try a.create(Hybrid);
        errdefer a.destroy(self);
        self.* = .{ .allocator = a, .base = try std.DynLib.open(library), .library = library, .fs_path = fs_path };
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
        if (self.window == null) try self.open();
        return &self.window.?.provers[lane];
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
    /// STWO_RV64_M8_OUTER_RESERVE_BYTES (default 2 GiB: the legacy FIXED
    /// precommit and immutable setup keep allocating during recursion).
    fn open(self: *Hybrid) !void {
        var timer = try std.time.Timer.start();
        var config = try Jobs.Config.fromEnv();
        const reserve: u64 = if (std.posix.getenv("STWO_RV64_M8_OUTER_RESERVE_BYTES")) |v| std.fmt.parseUnsigned(u64, v, 10) catch return error.InvalidM8JobsEnvironment else 2 << 30;
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
        config.arena_words = words;
        const trim_ns = timer.lap();
        const set = try Jobs.WorkerSet.startWith(self.allocator, self.library, config);
        errdefer set.stop(self.allocator);
        var shared = try Shared.init(&set.libs.base, &set.libs.addon, self.fs_path);
        errdefer shared.deinit();
        var workers: [4]*Worker.Worker = undefined;
        for (self.lanes, 0..) |lane, i| workers[i] = for (set.slice()) |candidate| {
            if (candidate.device_ordinal == lane.physical_device) break candidate;
        } else return error.M8OuterJobsMissingLaneWorker;
        const provers = try self.allocator.alloc(Prover, self.lanes.len);
        self.window = .{ .set = set, .shared = shared, .provers = provers, .started_ns = 0 };
        const w = &self.window.?;
        for (provers, workers[0..provers.len]) |*p, worker| p.* = Prover.init(self.allocator, &w.shared, worker);
        self.windows += 1;
        std.debug.print("GPU_M8_OUTER_WINDOW open window={d} arena_words={d} available_bytes={d} reserve_bytes={d} trimmed_bytes={d} trim_ns={d} start_ns={d}\n", .{ self.windows, words, available, reserve, released, trim_ns, timer.read() });
    }

    /// Request tail: stop the window's workers (every lane is idle).
    pub fn endRequest(self: *Hybrid) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var w = self.window orelse return;
        self.window = null;
        var timer = std.time.Timer.start() catch unreachable;
        var nodes: u64 = 0;
        for (self.lanes) |*lane| {
            nodes += lane.nodes;
            lane.nodes = 0;
        }
        for (w.provers) |*p| p.deinit();
        self.allocator.free(w.provers);
        w.shared.deinit();
        w.set.stop(self.allocator);
        std.debug.print("GPU_M8_OUTER_WINDOW close window={d} nodes={d} stop_ns={d}\n", .{ self.windows, nodes, timer.read() });
    }

    pub fn destroy(self: *Hybrid) void {
        self.endRequest();
        const a = self.allocator;
        for (self.lanes) |*lane| Lane.unstageHost(lane);
        a.free(self.lanes);
        a.free(self.services);
        self.base.close();
        a.destroy(self);
    }
};
