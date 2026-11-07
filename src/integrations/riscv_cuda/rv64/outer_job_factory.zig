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
const CP = @import("jobs/outer_class_plan.zig");
const Checks = @import("jobs/outer_checks.zig");
const Enc = @import("jobs/outer_encode.zig");
const EncJob = @import("jobs/outer_encode_job.zig");
const OodsAbi = @import("jobs/outer_encode_oods.zig");
const Seed = @import("jobs/outer_seed_device.zig");
const GnRecord = @import("outer_seed_record.zig");
const OuterDevice = @import("jobs/outer_device.zig");

pub const Shared = struct {
    kernels: K.Kernels,
    composition: Comp.Kernels,
    pcs: NativePcs.Symbols,
    wide: bool,
    graph_api: Graphs.Api,
    fs: std.DynLib,
    /// Base-image CUDA event symbols (cuda_events.zig); null: no GPU timing.
    events: ?Events.Api = null,
    /// Device acceptance checks from the addon (STWO_RV64_M8_OUTER_DEVICE_CHECKS=1).
    checks: ?Checks.Symbols = null,
    /// Device proof encoder (STWO_RV64_M8_OUTER_DEVICE_ENCODE=check|1).
    encode: ?Enc.Symbols = null,
    encode_mode: Enc.Mode = .off,
    /// Device node_oods_constraint check (with the encoder, check mode).
    oods: ?OodsAbi.Symbols = null,
    /// gn-node device seed fill (STWO_RV64_M8_GN_NODE=check|job).
    seed: ?Seed.Symbols = null,
    /// gn-node job mode: the addon's peer / verdict ops (NodeJob channel_order).
    peer: ?@import("jobs/ops.zig").Peer = null,
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
            .checks = if (try Checks.selected()) try Checks.Symbols.load(addon) else null,
            .encode = if (try Enc.mode() != .off or try GnRecord.liveSelected()) try Enc.Symbols.load(addon) else null,
            .encode_mode = try Enc.mode(),
            .oods = if (try Enc.mode() != .off or try GnRecord.liveSelected()) try OodsAbi.Symbols.load(addon) else null,
            .seed = if (try GnRecord.liveSelected()) try Seed.Symbols.load(addon) else null,
            .peer = if (GnRecord.jobSelected()) try @import("jobs/ops.zig").Peer.open(addon) else null,
        };
    }
    pub fn deinit(self: *Shared) void {
        self.fs.close();
        self.* = undefined;
    }
    pub fn whole(self: *const Shared) Job.Whole {
        return .{ .composition = &self.composition, .pcs = self.pcs, .wide = self.wide, .checks = self.checks };
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
    /// initWhole borrowed the class's cached WholePlan (STWO_RV64_M8_OUTER_CLASS_PLAN=1).
    borrowed_plan: bool = false,
    /// Device encoding (STWO_RV64_M8_OUTER_DEVICE_ENCODE=check): bytes, GPU
    /// time of the encoder launch (CUDA events), host mirror time.
    encoded_bytes: u64 = 0,
    encode_gpu_ns: u64 = 0,
    encode_mirror_ns: u64 = 0,
    encode_launches: u32 = 0,
    encode_identical: bool = false,
    /// gn-node check: device seed fill + statement (GnCheck).
    gn: GnReport = .{},
};
pub const GnReport = struct {
    ran: bool = false,
    children: u32 = 0,
    seeds: u64 = 0,
    gpu_ns: u64 = 0,
    host_ns: u64 = 0,
    warm_ns: u64 = 0,
    launches: u32 = 0,
    source_words: u64 = 0,
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

    /// STWO_RV64_M8_GN_NODE=job: prove the node again through the production
    /// GPU-native node job (outer_device.NodeJob over its NodeClasses
    /// template, children from a node-local stand-in of the request slab) and
    /// require its device-encoded bytes == the published host bytes.
    fn gnJob(self: *Prover, a: std.mem.Allocator, input: Prestage.Input, class_key: [32]u8, g: *const GnCheck, wire: []const u8, image: []const u32) !void {
        const entry = NodeClasses.get(class_key) orelse return error.GnNodeClassNotHarvested;
        var timer = try std.time.Timer.start();
        // Children regions in the slab convention: image in the last words.
        var region_words: [Seed.max_children]u32 = undefined;
        const nk = g.regions.len;
        for (g.regions, 0..) |x, k| {
            var at: usize = 0;
            const sh = try Seed.Shape.parse(std.heap.c_allocator, entry.shapes[k], &at);
            defer std.heap.c_allocator.free(sh.trees);
            region_words[k] = GnCheck.wire_words + @as(u32, @intCast((try Seed.Layout.of(sh)).words));
            _ = x;
        }
        {
            NodeClasses.mutex.lock();
            defer NodeClasses.mutex.unlock();
            if (entry.program.len == 0) try entry.programFor(region_words[0..nk]);
        }
        const program_ns = timer.lap();
        // This worker's graph cache: every node of the class replays the
        // class's captured body (STWO_RV64_M8_OUTER_GRAPH_THRESHOLD=1: from
        // the second node of the class on this GPU).
        const dev = self.worker.device_ordinal;
        if (dev < entry.graphs.len and entry.graphs[dev] == null) entry.graphs[dev] = &self.graphs;
        var w = try GnJob.init(a, entry, g, region_words[0..nk], self.shared, image, dev);
        defer w.deinit(a);
        var done = Done{};
        try self.submitWait(w.job(), &done);
        try done.result;
        const job_ns = timer.lap();
        const eq = std.mem.eql(u8, w.bytes orelse &.{}, wire);
        std.debug.print("GN_NODE_JOB ordinal={d} leaf={} children={d} device_bytes={d} host_bytes={d} bytes_identical={} seed_tape=0x{x} child_binding=0x{x} lookup_sum=0x{x} channel_order=0x{x} node_pcs_status=0x{x} encode_bounds=0x{x} node_oods=0x{x} image_tail_identical={} outcome={s} launches={d} nodejob_launches={d} nodejob_host_ns={d} stage_ns={d} enqueue_ns={d} wait_ns={d} job_ns={d} program_ns={d}\n", .{ input.ordinal, input.is_leaf, nk, if (w.bytes) |b| b.len else 0, wire.len, eq, w.verdicts[0], w.verdicts[1], w.verdicts[2], w.verdicts[3], w.verdicts[4], w.verdicts[5], w.verdicts[6], w.image_eq, @tagName(w.outcome), w.launches, w.node.launches, w.node.host_ns, done.receipt.stage_ns, done.receipt.enqueue_ns, done.receipt.wait_ns, job_ns, program_ns });
        for (w.verdicts) |v| if (v != 0) return error.GnNodeJobRejected;
        if (!eq or !w.image_eq) return error.GnNodeJobBytesMismatch;
    }

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
        // gn-node: the first node of a class leaves its Staged as the class
        // template of the GPU-native node job (NodeClasses).
        var keep_staged = false;
        defer if (!keep_staged) staged.deinit();
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
        // Device encoding (check mode): the encoder runs after the body on the
        // same stream; its bytes are compared with the host's below.
        var encode: ?EncodeCheck = null;
        defer if (encode) |*c| c.deinit(a);
        if (self.shared.encode_mode != .off) {
            if (self.shared.encode_mode != .check) return error.M8OuterDeviceEncodePublishNotLanded;
            encode = try EncodeCheck.init(a, &job, self.shared, input.key, staged);
            encode.?.arm();
            encode.?.node.fault = if (try Enc.faultOrdinal()) |n| n == input.ordinal else false;
            encode.?.node.oods_fault = if (try Enc.oodsFaultOrdinal()) |n| n == input.ordinal else false;
            encode.?.node.oods_point_fault = if (try Enc.oodsPointFaultOrdinal()) |n| n == input.ordinal else false;
        }
        var gn: ?GnCheck = null;
        defer if (gn) |*g| g.deinit(a);
        if (self.shared.seed) |sym| {
            gn = try GnCheck.init(a, input, staged, &job, sym, if (self.shared.events) |*ev| ev else null);
            gn.?.arm();
        }
        const inner_job = if (encode) |*c| c.node.job() else job.job();
        if (gn) |*g| g.next = inner_job;
        const submitted = if (gn) |*g| g.job() else inner_job;
        r.footprint = submitted.footprint();
        r.borrowed_plan = job.borrowed;
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
            self.worker.submit(submitted, .{ .ctx = &done, .done = Done.done }) catch |err| switch (err) {
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
        // The host mirror reads the PCS image decodeProof releases.
        if (encode) |*c| try c.mirror(a, &job, staged);
        // gn-node recorder (STWO_RV64_M8_GN_NODE_RECORD=<dir>): keep the PCS
        // image decodeProof releases; written with the node's proof below.
        const record_image: ?[]u32 = if ((Recorder.dir() != null or gn != null) and job.pcs_words.len != 0) try a.dupe(u32, job.pcs_words) else null;
        defer if (record_image) |w| a.free(w);
        try job.decodeProof();
        r.decode_ns = job.report.decode_ns;
        var produced = try Prestage.assembleWithOods(a, input.key, staged, &job, if (encode) |*c| &c.host_oods else null);
        errdefer produced.deinit();
        r.assemble_ns = timer.read();
        if (encode) |*c| {
            try c.compare(a, input.key, &produced, input.ordinal);
            r.encoded_bytes = c.host_bytes;
            r.encode_gpu_ns = if (c.timer) |t| t.ns else 0;
            r.encode_mirror_ns = c.mirror_ns;
            r.encode_launches = c.node.launches;
            r.encode_identical = true;
        }
        if (report) |out| out.* = r;
        if (gn) |*g| {
            try g.verify(input.ordinal, staged);
            r.gn = g.report;
            const image = record_image orelse return error.GnNodeImageMissing;
            const wire = try Outer.wire.encode(a, input.key.identity, produced.outputs, produced.claims, &produced.proof.proof);
            defer a.free(wire);
            try GnRecord.Live.putNode(job.pcs.?.prepared.metadata.shape, image, wire, Recorder.words8(input.key.identity), Recorder.words8(staged.fixed_root), @intCast(staged.expected.len / 4));
            keep_staged = NodeClasses.harvest(self.shared, input, staged, &job, g) catch |err| blk: {
                std.debug.print("GN_NODE_CLASS ordinal={d} harvest_error={s}\n", .{ input.ordinal, @errorName(err) });
                break :blk false;
            };
            if (GnRecord.jobSelected()) try self.gnJob(a, input, staged.class_key, g, wire, image);
            if (report) |out| out.* = r;
        }
        if (record_image) |image| if (Recorder.dir() != null) Recorder.write(a, input, staged, &job, &produced, image) catch |err| {
            std.debug.print("GN_NODE_RECORD ordinal={d} error={s}\n", .{ input.ordinal, @errorName(err) });
            return err;
        };
        return produced;
    }
};

/// gn-node piece harness recorder (STWO_RV64_M8_GN_NODE_RECORD=<dir>, default
/// off, diagnostics only: never changes a proof). One file per proved node,
/// `node-<ordinal>-<sha256(wire)[0..8]>.gnr`: the legacy path's inputs and
/// outputs the GPU-native node job must reproduce on the device (host seeds,
/// host transcript checkpoint, expected outputs) and the node's own products
/// a parent's device seed fill reads (PCS readback image + its shape, claims,
/// the om31 wire bytes). Format (u32 LE): see jobs/outer_seed_device.zig
/// Record.parse.
pub const Recorder = struct {
    const Rec = @import("outer_seed_record.zig");
    pub const magic = Rec.node_magic;
    pub const dir = Rec.dir;
    pub fn words8(bytes: [32]u8) [8]u32 {
        var w: [8]u32 = undefined;
        for (&w, 0..) |*x, i| x.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
        return w;
    }
    fn write(a: std.mem.Allocator, input: Prestage.Input, staged: *const @import("jobs/outer_staged.zig").Staged, job: *Job.OuterNodeJob, produced: *const Outer.prove.Produced, image: []const u32) !void {
        const path = dir() orelse return;
        const wire = try Outer.wire.encode(a, input.key.identity, produced.outputs, produced.claims, &produced.proof.proof);
        defer a.free(wire);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(wire, &digest, .{});
        var out: std.ArrayListUnmanaged(u32) = .empty;
        defer out.deinit(a);
        try out.appendSlice(a, &.{ magic, 2, input.ordinal, @intFromBool(input.is_leaf) });
        try out.appendSlice(a, &words8(input.key.identity));
        try out.appendSlice(a, &words8(staged.fixed_root));
        try out.appendSlice(a, &words8(input.class orelse @splat(0)));
        try out.appendSlice(a, &staged.checkpoint);
        try out.append(a, @intCast(staged.expected.len));
        try out.appendSlice(a, staged.expected);
        try out.append(a, @intCast(staged.assignment.seeds.len));
        try out.appendSlice(a, staged.assignment.seeds);
        try Rec.appendShape(a, &out, job.pcs.?.prepared.metadata.shape);
        try out.append(a, @intCast(image.len));
        try out.appendSlice(a, image);
        const claims = produced.claims.toArray();
        try out.append(a, @intCast(claims.len * 8));
        for (claims) |cl| for (cl.toM31Array()) |m| try out.append(a, m.v);
        try out.append(a, @intCast(wire.len));
        const at = out.items.len;
        try out.appendNTimes(a, 0, (wire.len + 3) / 4);
        @memcpy(std.mem.sliceAsBytes(out.items[at..])[0..wire.len], wire);
        // Class transcript prefix (om31 prove.begin before the statement
        // words): the digest after the config and profile mixes, draws.
        {
            var channel = Outer.protocol.Channel.init();
            (try Outer.protocol.targetConfig()).mixInto(&channel);
            Outer.protocol.mixProfile(&channel);
            const cp = @import("stwo_core").channel.raw_mod_m31.om31Checkpoint(&channel);
            for (0..8) |i| try out.append(a, std.mem.readInt(u32, cp.digest[4 * i ..][0..4], .little));
            try out.append(a, cp.draws);
        }
        var name_buf: [96]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "node-{d:0>4}-{x}.gnr", .{ input.ordinal, digest[0..8].* });
        if (try Rec.writeOnce(path, name, out.items)) std.debug.print("GN_NODE_RECORD ordinal={d} leaf={} seeds={d} image_words={d} wire_bytes={d} file={s}\n", .{ input.ordinal, input.is_leaf, staged.assignment.seeds.len / 5, image.len, wire.len, name });
    }
};

/// STWO_RV64_M8_OUTER_DEVICE_ENCODE=check: one node's device encoding next
/// to the host bytes. Three byte strings must be identical: the device
/// encoder's (outer_encode.cu, in-stream after the body), the host mirror's
/// (outer_encode.encodeHost over the same PCS image words) and the host
/// serialisation of the assembled proof (om31 wire.encode, the bytes the
/// request publishes and the pipeline writes as the node file). Any
/// difference or a non-accepted device verdict fails the node closed.
const EncodeCheck = struct {
    desc: []u32,
    program: ?[]u32 = null,
    oods_timer: ?GpuTimer = null,
    host_oods: [16]u32 = @splat(0),
    node: EncJob.EncodedNode,
    timer: ?GpuTimer = null,
    mirror_bytes: ?[]u8 = null,
    mirror_ns: u64 = 0,
    host_bytes: u64 = 0,
    fn init(a: std.mem.Allocator, job: *Job.OuterNodeJob, shared: *const Shared, key: *const Prestage.Authority, staged: *const @import("jobs/outer_staged.zig").Staged) !EncodeCheck {
        const shape = job.pcs.?.prepared.metadata.shape;
        const desc = try EncJob.descriptorFor(a, shape, try EncJob.envelopeFor(key.identity, staged.expected.len / 4), staged.fixed_root);
        errdefer a.free(desc);
        var out = EncodeCheck{ .desc = desc, .node = try EncJob.EncodedNode.init(a, job, shared.encode.?, desc), .timer = if (shared.events) |*ev| GpuTimer{ .api = ev } else null, .oods_timer = if (shared.events) |*ev| GpuTimer{ .api = ev } else null };
        errdefer out.node.deinit();
        if (shared.oods) |sym| {
            const counts = try a.alloc([]const u32, shape.trees.len);
            defer a.free(counts);
            for (counts, shape.trees) |*c, t| c.* = t.sample_counts;
            const program = try Prestage.oodsProgram(a, key, counts);
            errdefer a.free(program);
            try out.node.withOods(sym, program);
            out.program = program;
        }
        return out;
    }
    /// After init has been moved to its final address (the timer pointer).
    fn arm(self: *EncodeCheck) void {
        if (self.timer) |*t| self.node.timing = t.timing();
        if (self.oods_timer) |*t| self.node.oods_timing = t.timing();
    }
    fn deinit(self: *EncodeCheck, a: std.mem.Allocator) void {
        self.node.deinit();
        if (self.timer) |*t| t.deinit();
        if (self.oods_timer) |*t| t.deinit();
        if (self.program) |p| a.free(p);
        if (self.mirror_bytes) |b| a.free(b);
        a.free(self.desc);
    }
    fn words8(root: [32]u8) [8]u32 {
        var w: [8]u32 = undefined;
        for (&w, 0..) |*x, i| x.* = std.mem.readInt(u32, root[4 * i ..][0..4], .little);
        return w;
    }
    fn mirror(self: *EncodeCheck, a: std.mem.Allocator, job: *Job.OuterNodeJob, staged: anytype) !void {
        if (self.node.pcs_verdict != 0 or self.node.bounds_verdict != 0) {
            std.debug.print("GPU_M8_OUTER_ENCODE rejected ordinal={d} pcs=0x{x} bounds=0x{x}\n", .{ staged.ordinal, self.node.pcs_verdict, self.node.bounds_verdict });
            return error.OuterDeviceEncodeRejected;
        }
        if (self.node.oods) |o| if (o.verdict != 0) {
            std.debug.print("GPU_M8_OUTER_OODS rejected ordinal={d} verdict=0x{x}\n", .{ staged.ordinal, o.verdict });
            return error.OuterDeviceOodsRejected;
        };
        var timer = try std.time.Timer.start();
        const d = job.decoded orelse return error.OuterJobNotDecoded;
        const fixed = words8(staged.fixed_root);
        const main = words8(d.main_root);
        const inter = words8(d.inter_root);
        const comp = words8(job.composition_root);
        var claims: [8 * @import("jobs/outer_plan.zig").n_components]u32 = undefined;
        for (d.claims.toArray(), 0..) |c, i| for (c.toM31Array(), 0..) |m, k| {
            claims[8 * i + k] = m.v;
        };
        const latches: [4]u32 = @splat(0);
        const out = try a.alloc(u32, self.desc[Enc.D.max_payload_words] + 1);
        defer a.free(out);
        const v = try Enc.encodeHost(a, self.desc, job.pcs_words, .{ .roots = .{ &fixed, &main, &inter, &comp }, .claims = &claims, .latches = &latches, .outputs = staged.expected }, out);
        if (v.pcs != 0 or v.bounds != 0) {
            std.debug.print("GPU_M8_OUTER_ENCODE mirror_rejected ordinal={d} pcs=0x{x} bounds=0x{x}\n", .{ staged.ordinal, v.pcs, v.bounds });
            return error.OuterHostEncodeRejected;
        }
        const bytes = try a.alloc(u8, out[0]);
        for (0..out[0] / 4) |i| std.mem.writeInt(u32, bytes[4 * i ..][0..4], out[1 + i], .little);
        self.mirror_bytes = bytes;
        self.mirror_ns = timer.read();
    }
    fn compare(self: *EncodeCheck, a: std.mem.Allocator, key: *const Prestage.Authority, produced: *const Outer.prove.Produced, ordinal: u32) !void {
        const host = try Outer.wire.encode(a, key.identity, produced.outputs, produced.claims, &produced.proof.proof);
        defer a.free(host);
        self.host_bytes = host.len;
        const device = self.node.bytes orelse return error.OuterDeviceEncodeMissing;
        const mirror_bytes = self.mirror_bytes orelse return error.OuterDeviceEncodeMissing;
        const dev_eq = std.mem.eql(u8, device, host);
        const mir_eq = std.mem.eql(u8, mirror_bytes, host);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(host, &digest, .{});
        std.debug.print("GPU_M8_OUTER_ENCODE ordinal={d} host_bytes={d} device_bytes={d} mirror_bytes={d} device_identical={} mirror_identical={} sha256={x} encode_gpu_ns={d} mirror_ns={d} launches={d}\n", .{ ordinal, host.len, device.len, mirror_bytes.len, dev_eq, mir_eq, digest[0..8].*, if (self.timer) |t| t.ns else 0, self.mirror_ns, self.node.launches });
        if (self.node.oods) |o| {
            const values_eq = std.mem.eql(u32, &o.diag, &self.host_oods);
            std.debug.print("GPU_M8_OUTER_OODS ordinal={d} verdict=0x{x} values_identical={} oods_gpu_ns={d} parts={d}\n", .{ ordinal, o.verdict, values_eq, if (self.oods_timer) |t| t.ns else 0, if (self.program) |p| p[OodsAbi.H.parts] else 0 });
            if (o.verdict != 0 or !values_eq) return error.OuterDeviceOodsMismatch;
        }
        if (!dev_eq or !mir_eq) {
            const n = @min(@min(device.len, host.len), mirror_bytes.len);
            var first: usize = n;
            for (0..n) |i| if (device[i] != host[i] or mirror_bytes[i] != host[i]) {
                first = i;
                break;
            };
            std.debug.print("GPU_M8_OUTER_ENCODE mismatch ordinal={d} first_byte={d}\n", .{ ordinal, first });
            return error.OuterDeviceEncodeMismatch;
        }
    }
};

/// STWO_RV64_M8_GN_NODE=check (default off): the node's assignment seeds,
/// transcript checkpoint and (with device checks) expected outputs come from
/// the DEVICE seed fill + statement kernel (jobs/outer_seed_device.zig,
/// NAT/rv64/jobs/outer_seed.cu) over its children's seed sources, not from
/// the host. The host values are erased before staging (seed limbs and the
/// checkpoint are zeroed), so a node proof that passes the gate's byte
/// identity was proved from device-filled inputs. Children are found in
/// GnRecord.Live (stand-in for the request slab: their wire bytes + PCS
/// image are uploaded as this node's child regions). A leaf's native child
/// supplies its PCS image; its statement tail (ordinal, digests, GKR values,
/// request words) and outputs are the native producer's words, taken here
/// from the host seeds / expected outputs before they are erased.
/// Verdicts seed_tape / child_binding and the device outputs/checkpoint copy
/// are read back from the node's job slab and must match the host values.
fn gnFaultOrdinal() !?u32 {
    const two = std.posix.getenv("STWO_RV64_M8_FAULT_INJECTION") orelse return null;
    if (!std.mem.eql(u8, two, "1")) return null;
    const v = std.posix.getenv("STWO_RV64_M8_GN_NODE_FAULT_ORDINAL") orelse return null;
    return std.fmt.parseInt(u32, v, 10) catch error.InvalidGnNodeFaultOrdinal;
}
const GnCheck = struct {
    pub const field_index: u32 = 0x474e_4f44; // "GNOD"
    /// Fold children: om31 node proofs under the diet-wire profile (fold
    /// Merkle cap 2^3); leaf children: native proofs with full paths.
    const cap_log: u32 = 3;
    const leaf_cap_log: u32 = 0;
    const fold_domain: u32 = 0x4f464c31;
    /// >= 1 + the largest om31 node wire in words: 759,512 B on 24628607 /
    /// 26235156 [M] (189,879 words); 2^18 words = 1 MiB of bytes.
    const wire_words: u32 = 1 << 18;
    outer: *Job.OuterNodeJob,
    next: api.Job = undefined,
    symbols: Seed.Symbols,
    program: Seed.Program,
    prog_key: [32]u8,
    regions: [][]u32,
    expected: []u32, // host copy (comparison; restored before host assembly)
    checkpoint: [9]u32, // host copy (comparison)
    field_words: usize,
    d_prog: api.DeviceBuffer = undefined,
    d_regions: [Seed.max_children]api.DeviceBuffer = undefined,
    d_scratch: api.DeviceBuffer = undefined,
    d_outputs: ?api.DeviceBuffer = null,
    timer: ?GpuTimer = null,
    report: GnReport = .{},
    host_timer_ns: u64 = 0,
    seed_status: u32 = 0xffff_ffff,
    bind_status: u32 = 0xffff_ffff,
    dev_outputs: [64]u32 = @splat(0),
    dev_checkpoint: [9]u32 = @splat(0),
    /// What NodeClasses.harvest keeps of this node's class (owned).
    harvest: Harvest = .{},
    const Harvest = struct {
        vars: []u32 = &.{},
        constants: [][4]u32 = &.{},
        shapes: [Seed.max_children][]u32 = @splat(&.{}),
        identities: [Seed.max_children][8]u32 = undefined,
        fixed_roots: [Seed.max_children][8]u32 = undefined,
        n_outputs: [Seed.max_children]u32 = @splat(0),
        n: usize = 0,
        tail: u32 = 0,
        statement: Seed.Statement = undefined,
        fn deinit(self: *Harvest, a: std.mem.Allocator) void {
            a.free(self.vars);
            a.free(self.constants);
            for (self.shapes[0..self.n]) |x| a.free(x);
        }
    };

    fn init(a: std.mem.Allocator, input: Prestage.Input, staged: *@import("jobs/outer_staged.zig").Staged, node_job: *Job.OuterNodeJob, symbols: Seed.Symbols, events: ?*const Events.Api) !GnCheck {
        var warm = try std.time.Timer.start();
        const seeds = staged.assignment.seeds;
        const n = seeds.len / 5;
        const vars = try a.alloc(u32, n);
        defer a.free(vars);
        for (vars, 0..) |*v, i| v.* = seeds[5 * i];
        var found: std.ArrayListUnmanaged(GnRecord.Live.Found) = .empty;
        defer {
            for (found.items) |*f| f.deinit(a);
            found.deinit(a);
        }
        try GnRecord.Live.find(a, seeds, !input.is_leaf, &found);
        if (found.items.len == 0 or (input.is_leaf and found.items.len != 1) or found.items.len > Seed.max_children) {
            std.debug.print("GN_NODE ordinal={d} error=GnNodeChildrenNotFound found={d} leaf={}\n", .{ input.ordinal, found.items.len, input.is_leaf });
            return error.GnNodeChildrenNotFound;
        }
        const n_out = staged.expected.len;
        var prefix: [8]u32 = undefined;
        {
            var channel = Outer.protocol.Channel.init();
            (try Outer.protocol.targetConfig()).mixInto(&channel);
            Outer.protocol.mixProfile(&channel);
            const cp = @import("stwo_core").channel.raw_mod_m31.om31Checkpoint(&channel);
            if (cp.draws != 0) return error.GnNodePrefixDraws;
            for (&prefix, 0..) |*w, i| w.* = std.mem.readInt(u32, cp.digest[4 * i ..][0..4], .little);
        }
        const identity = Recorder.words8(input.key.identity);
        const fixed_root = Recorder.words8(staged.fixed_root);
        var classes: [Seed.max_children]Seed.ChildClass = undefined;
        var shapes: [Seed.max_children]Seed.Shape = undefined;
        var shaped: usize = 0;
        defer for (shapes[0..shaped]) |sh| a.free(sh.trees);
        for (found.items, 0..) |f, k| {
            var at: usize = 0;
            shapes[k] = try Seed.Shape.parse(a, f.entry.shape, &at);
            shaped += 1;
            classes[k] = .{ .shape = shapes[k], .wire_words = wire_words, .n_outputs = f.entry.n_outputs, .identity = f.entry.identity, .fixed_root = f.entry.fixed_root };
        }
        const regions = try a.alloc([]u32, found.items.len);
        var made: usize = 0;
        errdefer {
            for (regions[0..made]) |x| a.free(x);
            a.free(regions);
        }
        var program: Seed.Program = undefined;
        if (input.is_leaf) {
            const f = found.items[0];
            const s0 = f.at;
            const proof_len = try Seed.leafTapeLength(a, classes[0], leaf_cap_log);
            if (s0 + proof_len > n) return error.GnNodeLeafTapeTooLong;
            const tail: u32 = @intCast(n - s0 - proof_len);
            const outputs_at: u32 = @intCast(wire_words + f.entry.image.len + 4 * tail);
            const constants = try a.alloc([4]u32, s0);
            defer a.free(constants);
            for (constants, 0..) |*c, j| c.* = seeds[5 * j + 1 ..][0..4].*;
            program = try Seed.buildLeaf(a, classes[0], leaf_cap_log, tail, vars, constants, .{ .kind = 2, .outputs_at = outputs_at, .domain = 0, .version_word = 0, .n_outputs = @intCast(n_out / 4), .prefix = prefix, .identity = identity, .fixed_root = fixed_root, .profile = @splat(0) });
            errdefer program.deinit(a);
            // [len][wire placeholder][image][statement tail][outputs]: the
            // native producer's words (from the host values, erased below).
            const region = try a.alloc(u32, outputs_at + n_out);
            @memset(region, 0);
            region[0] = 1;
            @memcpy(region[wire_words..][0..f.entry.image.len], f.entry.image);
            for (0..tail) |j| @memcpy(region[wire_words + f.entry.image.len + 4 * j ..][0..4], seeds[5 * (s0 + proof_len + j) + 1 ..][0..4]);
            @memcpy(region[outputs_at..][0..n_out], staged.expected);
            regions[0] = region;
            made = 1;
        } else {
            const tape = try Seed.tapeLength(classes[0..found.items.len], cap_log, a);
            if (tape > n) return error.GnNodeFoldTapeTooLong;
            const constants = try a.alloc([4]u32, n - tape);
            defer a.free(constants);
            for (constants, 0..) |*c, j| c.* = seeds[5 * j + 1 ..][0..4].*;
            for (found.items, 0..) |f, k| {
                const L = try Seed.Layout.of(shapes[k]);
                const need = (f.entry.wire.len + 3) / 4 + 1;
                if (need > wire_words or f.entry.image.len != L.words) return error.GnNodeChildRegion;
                const region = try a.alloc(u32, wire_words + f.entry.image.len);
                @memset(region, 0);
                region[0] = @intCast(f.entry.wire.len);
                @memcpy(std.mem.sliceAsBytes(region[1..need])[0..f.entry.wire.len], f.entry.wire);
                @memcpy(region[wire_words..], f.entry.image);
                regions[k] = region;
                made += 1;
            }
            var profile: [8]u32 = undefined;
            @memcpy(&profile, regions[0][3..11]);
            const arity = found.items.len;
            program = try Seed.buildFold(a, classes[0..arity], cap_log, vars, constants, .{ .domain = fold_domain, .version_word = if (arity == 2) 2 else (@as(u32, @intCast(arity)) << 8) | 2, .n_outputs = @intCast(n_out / 4), .prefix = prefix, .identity = identity, .fixed_root = fixed_root, .profile = profile });
        }
        errdefer program.deinit(a);
        var harvest = Harvest{ .vars = try a.dupe(u32, vars), .n = found.items.len };
        errdefer harvest.deinit(a);
        {
            const n_const: usize = program.header(Seed.P.n_constants);
            harvest.constants = try a.alloc([4]u32, n_const);
            for (harvest.constants, 0..) |*c, j| c.* = seeds[5 * j + 1 ..][0..4].*;
        }
        for (found.items, 0..) |f, k| {
            harvest.shapes[k] = try a.dupe(u32, f.entry.shape);
            harvest.identities[k] = f.entry.identity;
            harvest.fixed_roots[k] = f.entry.fixed_root;
            harvest.n_outputs[k] = f.entry.n_outputs;
        }
        harvest.tail = if (input.is_leaf) @intCast(n - found.items[0].at - try Seed.leafTapeLength(a, classes[0], leaf_cap_log)) else 0;
        harvest.statement = .{ .kind = program.header(Seed.P.statement), .outputs_at = program.header(Seed.P.outputs_at), .domain = program.header(Seed.P.domain), .version_word = program.header(Seed.P.version_word), .n_outputs = program.header(Seed.P.n_outputs), .prefix = prefix, .identity = identity, .fixed_root = fixed_root, .profile = program.words[program.header(Seed.P.profile)..][0..8].* };
        // Negative test (two-key: STWO_RV64_M8_FAULT_INJECTION=1 and
        // STWO_RV64_M8_GN_NODE_FAULT_ORDINAL=n): one MAIN-tree Merkle path
        // word of child 0's image flips; seed_tape must refuse the node.
        if (try gnFaultOrdinal()) |f| if (f == input.ordinal) {
            const L = try Seed.Layout.of(shapes[0]);
            regions[0][wire_words + L.trees[1].paths] ^= 1;
            std.debug.print("GN_NODE fault_injected ordinal={d}\n", .{input.ordinal});
        };
        var key: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(program.words), &key, .{});
        // Erase the host values: the node can only be proved from the device's.
        const host_expected = try a.dupe(u32, staged.expected);
        errdefer a.free(host_expected);
        const host_checkpoint = staged.checkpoint;
        const writable: []u32 = @constCast(staged.assignment.seeds);
        for (0..n) |i| @memset(writable[5 * i + 1 ..][0..4], 0);
        staged.checkpoint = @splat(0);
        if (staged.image.expected.words != 0) @memset(@constCast(staged.expected), 0);
        var self = GnCheck{ .outer = node_job, .symbols = symbols, .program = program, .prog_key = key, .regions = regions, .expected = host_expected, .checkpoint = host_checkpoint, .field_words = 32 + n_out, .harvest = harvest };
        _ = try node_job.layout.add(.opaque_words, field_index, self.field_words);
        self.timer = if (events) |ev| GpuTimer{ .api = ev } else null;
        self.report = .{ .ran = true, .children = @intCast(found.items.len), .seeds = n, .warm_ns = warm.read(), .launches = 4 };
        for (regions) |x| self.report.source_words += x.len;
        return self;
    }
    fn arm(self: *GnCheck) void {
        _ = self;
    }
    fn deinit(self: *GnCheck, a: std.mem.Allocator) void {
        self.harvest.deinit(a);
        if (self.timer) |*t| t.deinit();
        self.program.deinit(a);
        for (self.regions) |x| a.free(x);
        a.free(self.regions);
        a.free(self.expected);
    }
    fn job(self: *GnCheck) api.Job {
        return api.Job.from(GnCheck, self);
    }
    pub fn classKey(self: *GnCheck) [32]u8 {
        return self.next.classKey();
    }
    fn g(words: u64) u64 {
        return std.mem.alignForward(u64, @max(words, 1), 64);
    }
    fn extra(self: *const GnCheck) u64 {
        var n = g(@as(u64, self.program.header(Seed.P.scratch_words)) + 8) + g(self.expected.len);
        for (self.regions) |x| n += g(x.len);
        return n;
    }
    pub fn footprint(self: *GnCheck) api.Footprint {
        var fp = self.next.footprint();
        const x = self.extra();
        fp.device_words += @intCast(x);
        fp.staged_words += @intCast(x);
        fp.pinned_words += self.program.words.len;
        for (self.regions) |r| fp.pinned_words += r.len;
        return fp;
    }
    pub fn stage(self: *GnCheck, s: *api.Stager) !void {
        try self.next.vtable.stage(self.next.ctx, s);
        var t = try std.time.Timer.start();
        const p = try s.persistent(self.prog_key, self.program.words.len);
        self.d_prog = p.buffer;
        if (p.fresh) {
            const pinned = try s.pinned(self.program.words.len);
            @memcpy(pinned, self.program.words);
            try s.upload(p.buffer, pinned);
        }
        // Check mode only: the children's seed sources (GPU-native: their
        // request-slab regions, already on the device).
        for (self.regions, 0..) |x, k| {
            self.d_regions[k] = try s.alloc(x.len);
            const pinned = try s.pinned(x.len);
            @memcpy(pinned, x);
            try s.upload(self.d_regions[k], pinned);
        }
        self.d_scratch = try s.alloc(@as(usize, self.program.header(Seed.P.scratch_words)) + 8);
        if (self.outer.staged.image.expected.words == 0) self.d_outputs = try s.alloc(@max(self.expected.len, 1));
        self.host_timer_ns += t.read();
    }
    pub fn enqueue(self: *GnCheck, e: *api.Enqueue) !void {
        var t = try std.time.Timer.start();
        try e.waitStaged();
        try e.slab.bind(&self.outer.layout);
        const field = try e.slab.field(.opaque_words, field_index);
        const st = self.outer.staged;
        const bases = self.outer.bases;
        const seeds: [*]u32 = @constCast(bases.at(st.image.seeds));
        const channel_seed: [*]u32 = @constCast(bases.at(st.image.channel_seed));
        const outputs: [*]u32 = if (st.image.expected.words != 0) @constCast(bases.at(st.image.expected)) else self.d_outputs.?.ptr;
        var io = Seed.Io{
            .program = self.d_prog.ptr,
            .program_words = self.program.words.len,
            .children = @splat(null),
            .children_words = @splat(0),
            .seeds = seeds,
            .seeds_words = st.assignment.seeds.len,
            .scratch = self.d_scratch.ptr,
            .scratch_words = self.d_scratch.words,
            .seed_status = &field.ptr[0],
            .bind_status = &field.ptr[1],
            .outputs = outputs,
            .checkpoint = channel_seed,
            .outputs_copy = field.ptr + 32,
            .checkpoint_copy = field.ptr + 16,
            .outputs_words = @intCast(self.expected.len),
            .n_children = @intCast(self.regions.len),
            .n_ops = self.program.header(Seed.P.n_ops),
            .n_caps = self.program.header(Seed.P.n_caps),
        };
        for (self.regions, 0..) |_, k| {
            io.children[k] = self.d_regions[k].ptr;
            io.children_words[k] = self.d_regions[k].words;
        }
        if (self.timer) |*tm| GpuTimer.mark(@ptrCast(tm), false, e.stream());
        const rc = self.symbols.fill(e.ctx(), K.lane, &io);
        if (self.timer) |*tm| GpuTimer.mark(@ptrCast(tm), true, e.stream());
        if (rc != 0) {
            std.log.err("GN_NODE seed fill enqueue failed rc={d}", .{rc});
            return error.GnNodeSeedFillEnqueueFailed;
        }
        self.host_timer_ns += t.read();
        try self.next.vtable.enqueue(self.next.ctx, e);
    }
    pub fn finish(self: *GnCheck, view: api.SlabView) !void {
        if (self.timer) |*tm| GpuTimer.resolve(@ptrCast(tm));
        // Host assembly publishes the host outputs (verified == device below).
        if (self.outer.staged.image.expected.words != 0) @memcpy(@constCast(self.outer.staged.expected), self.expected);
        const w = try @import("jobs/slab.zig").read(view, .opaque_words, field_index);
        self.seed_status = w[0];
        self.bind_status = w[1];
        @memcpy(&self.dev_checkpoint, w[16..25]);
        @memcpy(self.dev_outputs[0..self.expected.len], w[32..][0..self.expected.len]);
        if (self.seed_status != 0 or self.bind_status != 0) {
            std.debug.print("GN_NODE rejected ordinal={d} seed_tape=0x{x} child_binding=0x{x}\n", .{ self.outer.staged.ordinal, self.seed_status, self.bind_status });
            return error.GnNodeDeviceRejected;
        }
        try self.next.vtable.finish(self.next.ctx, view);
    }
    pub fn abort(self: *GnCheck) void {
        self.next.vtable.abort(self.next.ctx);
    }
    /// After the node proved: the device outputs and checkpoint equal the
    /// legacy host values (the proof bytes themselves are the gate's check).
    fn verify(self: *GnCheck, ordinal: u32, staged: anytype) !void {
        _ = staged;
        const out_eq = std.mem.eql(u32, self.dev_outputs[0..self.expected.len], self.expected);
        const cp_eq = std.mem.eql(u32, &self.dev_checkpoint, &self.checkpoint);
        self.report.gpu_ns = if (self.timer) |tm| tm.ns else 0;
        self.report.host_ns = self.host_timer_ns;
        std.debug.print("GN_NODE ordinal={d} children={d} seeds={d} seed_tape=0x{x} child_binding=0x{x} outputs_identical={} checkpoint_identical={} seed_gpu_ns={d} seed_host_ns={d} warm_ns={d} launches={d} source_words={d}\n", .{ ordinal, self.report.children, self.report.seeds, self.seed_status, self.bind_status, out_eq, cp_eq, self.report.gpu_ns, self.report.host_ns, self.report.warm_ns, self.report.launches, self.report.source_words });
        if (!out_eq or !cp_eq) return error.GnNodeStatementMismatch;
    }
};

/// gn-node: GPU-native node class products harvested from a warm request
/// proved under STWO_RV64_M8_GN_NODE=check (the first node of each class).
/// Each entry is an outer_device.NodeClass: the class Staged template (its
/// seed limbs, checkpoint and outputs erased: the device writes them per
/// node), the seed-program inputs (seed variables, class constants, child
/// classes, statement), the encoder descriptor and OODS program. The service
/// binder registers an entry under its authority (outer_device.Recursion
/// register + ClassInfo.node) after `programFor` laid the children out in
/// the request slab's region sizes (image at the end of each region).
pub const NodeClasses = struct {
    pub const Entry = struct {
        class_key: [32]u8,
        node: OuterDevice.NodeClass,
        shared: *const Shared,
        staged: *@import("jobs/outer_staged.zig").Staged,
        desc: []u32,
        oods_program: []u32,
        vars: []u32,
        constants: [][4]u32,
        shapes: [][]u32, // child PCS shapes (outer_seed_record.appendShape words)
        identities: [][8]u32,
        fixed_roots: [][8]u32,
        n_outputs: []u32,
        leaf: bool,
        tail: u32,
        statement: Seed.Statement,
        program: []u32 = &.{},
        max_encoded_bytes: usize,
        /// Per device: the worker's whole-node graph cache (the Prover of that
        /// GPU; set by the binder). With it every node of the class replays
        /// the class's captured body graph (rebinding only node buffers).
        graphs: [OuterDevice.max_graph_devices]?*Graphs.Cache = @splat(null),
        /// The seed program for children regions of `region_words` words
        /// each (1 + the child class's encoded capacity), image at the end.
        pub fn programFor(self: *Entry, region_words: []const u32) !void {
            const a = std.heap.c_allocator;
            if (region_words.len != self.shapes.len) return error.GnNodeChildCount;
            var classes: [Seed.max_children]Seed.ChildClass = undefined;
            var parsed: [Seed.max_children]Seed.Shape = undefined;
            var n: usize = 0;
            defer for (parsed[0..n]) |p| a.free(p.trees);
            for (self.shapes, 0..) |sw, k| {
                var at: usize = 0;
                parsed[k] = try Seed.Shape.parse(a, sw, &at);
                n += 1;
                const L = try Seed.Layout.of(parsed[k]);
                if (region_words[k] < L.words + 1) return error.GnNodeChildRegion;
                classes[k] = .{ .shape = parsed[k], .wire_words = @intCast(region_words[k] - L.words), .n_outputs = self.n_outputs[k], .identity = self.identities[k], .fixed_root = self.fixed_roots[k] };
            }
            var st = self.statement;
            const prog = if (self.leaf) blk: {
                const L = try Seed.Layout.of(parsed[0]);
                // leaf: [len][native bytes][image][statement tail][outputs]
                st.outputs_at = classes[0].wire_words + @as(u32, @intCast(L.words)) + 4 * self.tail;
                break :blk try Seed.buildLeaf(a, classes[0], GnCheck.leaf_cap_log, self.tail, self.vars, self.constants, st);
            } else try Seed.buildFold(a, classes[0..n], GnCheck.cap_log, self.vars, self.constants, st);
            if (self.program.len != 0) a.free(self.program);
            self.program = prog.words;
            self.node.program = prog.words;
            std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(prog.words), &self.node.prog_key, .{});
        }
    };
    var mutex: std.Thread.Mutex = .{};
    var entries: std.ArrayListUnmanaged(*Entry) = .empty;
    pub fn get(class_key: [32]u8) ?*Entry {
        mutex.lock();
        defer mutex.unlock();
        for (entries.items) |e| if (std.mem.eql(u8, &e.class_key, &class_key)) return e;
        return null;
    }
    pub fn count() usize {
        mutex.lock();
        defer mutex.unlock();
        return entries.items.len;
    }
    /// Returns true when `staged` became the class template (the caller
    /// must not deinit it).
    fn harvest(shared: *const Shared, input: Prestage.Input, staged: *@import("jobs/outer_staged.zig").Staged, job: *Job.OuterNodeJob, g: *const GnCheck) !bool {
        if (get(staged.class_key) != null) return false;
        if (staged.image.expected.words == 0) return error.GnNodeClassNeedsDeviceChecks;
        const a = std.heap.c_allocator;
        const shape = job.pcs.?.prepared.metadata.shape;
        const desc = try EncJob.descriptorFor(a, shape, try EncJob.envelopeFor(input.key.identity, staged.expected.len / 4), staged.fixed_root);
        errdefer a.free(desc);
        const counts = try a.alloc([]const u32, shape.trees.len);
        defer a.free(counts);
        for (counts, shape.trees) |*c, t| c.* = t.sample_counts;
        const program = try Prestage.oodsProgram(a, input.key, counts);
        errdefer a.free(program);
        const e = try a.create(Entry);
        errdefer a.destroy(e);
        const nk = g.regions.len;
        e.* = .{
            .class_key = staged.class_key,
            .node = .{ .program = &.{}, .prog_key = @splat(0), .n_children = @intCast(nk), .output_words = @intCast(staged.expected.len), .ctx = e, .make = make },
            .shared = shared,
            .staged = staged,
            .desc = desc,
            .oods_program = program,
            .vars = try a.dupe(u32, g.harvest.vars),
            .constants = try a.dupe([4]u32, g.harvest.constants),
            .shapes = try a.alloc([]u32, nk),
            .identities = try a.dupe([8]u32, g.harvest.identities[0..nk]),
            .fixed_roots = try a.dupe([8]u32, g.harvest.fixed_roots[0..nk]),
            .n_outputs = try a.dupe(u32, g.harvest.n_outputs[0..nk]),
            .leaf = input.is_leaf,
            .tail = g.harvest.tail,
            .statement = g.harvest.statement,
            .max_encoded_bytes = 0,
        };
        {
            var sw: std.ArrayListUnmanaged(u32) = .empty;
            defer sw.deinit(a);
            try GnRecord.appendShape(a, &sw, shape);
            const own = try parseShape(a, sw.items);
            defer a.free(own.trees);
            // Region capacity: the wire bytes, then this node's PCS image (its
            // parent's seed source) in the last image words.
            e.max_encoded_bytes = 4 * (@as(usize, desc[Enc.D.max_payload_words]) + (try Seed.Layout.of(own)).words);
        }
        for (e.shapes, g.harvest.shapes[0..nk]) |*dst, src| dst.* = try a.dupe(u32, src);
        // The template carries no host value: the device writes seeds,
        // checkpoint and outputs per node.
        @memset(@constCast(staged.expected), 0);
        // A leaf's schedule (tasks, indices, chain ends) is a class constant
        // of the template too: move it from the node region (re-packed and
        // uploaded per node, ~75 MB for a 2.4 M-task leaf) to the class
        // region (uploaded once per worker). Layout only, proof-neutral.
        if (!staged.assignment.reusable) {
            staged.assignment.reusable = true;
            staged.image = @import("jobs/outer_staged.zig").Staged.layoutWith(&staged.assignment, staged.statics, if (staged.lookup != null) staged.expected.len else 0);
        }
        mutex.lock();
        defer mutex.unlock();
        try entries.append(a, e);
        std.debug.print("GN_NODE_CLASS harvested ordinal={d} class={x} leaf={} children={d} classes={d}\n", .{ input.ordinal, staged.class_key[0..8].*, input.is_leaf, nk, entries.items.len });
        return true;
    }
    fn parseShape(a: std.mem.Allocator, words: []const u32) !Seed.Shape {
        var at: usize = 0;
        return Seed.Shape.parse(a, words, &at);
    }
    const Made = struct {
        job: Job.OuterNodeJob,
        enc: EncJob.EncodedNode,
    };
    fn make(raw: *anyopaque, _: std.mem.Allocator, target: OuterDevice.Target) anyerror!OuterDevice.Made {
        const a = std.heap.c_allocator;
        const e: *Entry = @ptrCast(@alignCast(raw));
        if (e.program.len == 0) return error.GnNodeClassProgramNotLaidOut;
        const m = try a.create(Made);
        errdefer a.destroy(m);
        m.job = try Job.OuterNodeJob.initWhole(e.staged, &e.shared.kernels, e.shared.whole());
        errdefer m.job.deinit();
        m.job.defer_decode = true; // no host PCS decode: the device encoder publishes
        if (target.device < e.graphs.len) m.job.graphs = e.graphs[target.device];
        m.enc = try EncJob.EncodedNode.initTarget(a, &m.job, e.shared.encode orelse return error.GnNodeEncoderUnloaded, e.desc, .{ .region = target.region, .pcs_status = target.pcs_status, .encode_status = target.encode_status, .layout_status_oods = target.oods_status });
        if (e.shared.oods) |sym| try m.enc.withOods(sym, e.oods_program);
        m.enc.image_tail = true;
        m.enc.outputs_on_device = true;
        // No host decode in finish: the template's host outputs are erased
        // (the device wrote this node's), and the slab words are the verdicts.
        m.enc.device_publish = true;
        return .{ .job = m.enc.job(), .ctx = m, .inputs = inputs, .destroy = destroyMade };
    }
    fn inputs(raw: *anyopaque) anyerror!OuterDevice.Inputs {
        const m: *Made = @ptrCast(@alignCast(raw));
        const st = m.job.staged;
        const b = m.job.bases;
        const out = OuterDevice.Inputs{
            .seeds = .{ .ptr = @constCast(b.at(st.image.seeds)), .words = st.assignment.seeds.len },
            .channel_seed = .{ .ptr = @constCast(b.at(st.image.channel_seed)), .words = 9 },
            .outputs = .{ .ptr = @constCast(b.at(st.image.expected)), .words = st.expected.len },
        };
        m.enc.outputs_device = out.outputs;
        return out;
    }
    fn destroyMade(raw: *anyopaque) void {
        const m: *Made = @ptrCast(@alignCast(raw));
        m.enc.deinit();
        m.job.deinit();
        std.heap.c_allocator.destroy(m);
    }
};

/// STWO_RV64_M8_GN_NODE=job: one GPU-native node job (outer_device.NodeJob)
/// over a node-local stand-in of its GPU's request-slab segment: the
/// children's regions (uploaded in stage: the producers write them on device
/// in a request), the node's encoded region and its 7 status words. After
/// the job the region bytes and words are copied into a job-slab field for
/// the host comparison (the GPU-native publish reads the slab mirror).
const GnJob = struct {
    pub const field_index: u32 = 0x474e_4a42; // "GNJB"
    node: OuterDevice.NodeJob,
    made: *NodeClasses.Made,
    regions: [Seed.max_children][]u32,
    n_children: usize,
    region_words: [Seed.max_children]u32,
    target_words: usize,
    field_words: usize,
    d2d: K.Copy,
    bytes: ?[]u8 = null,
    image_eq: bool = false,
    host_image: []u32,
    verdicts: [7]u32 = @splat(0xffff_ffff),
    outcome: Graphs.Outcome = .direct,
    launches: u32 = 0,
    allocator: std.mem.Allocator,
    target: api.DeviceBuffer = undefined,
    words: api.DeviceBuffer = undefined,

    fn init(a: std.mem.Allocator, entry: *NodeClasses.Entry, g: *const GnCheck, region_words: []const u32, shared: *const Shared, own_image: []const u32, device: u32) !GnJob {
        const nk = g.regions.len;
        var self = GnJob{ .node = undefined, .made = undefined, .regions = undefined, .n_children = nk, .region_words = undefined, .target_words = 1 + entry.max_encoded_bytes / 4, .field_words = 0, .d2d = shared.kernels.d2d, .host_image = &.{}, .allocator = a };
        // Children regions in the slab convention (image in the last words;
        // a leaf's native child keeps its tail + outputs after the image).
        var made: usize = 0;
        errdefer for (self.regions[0..made]) |x| a.free(x);
        for (g.regions, 0..) |src, k| {
            const L = blk: {
                var at: usize = 0;
                const sh = try Seed.Shape.parse(a, entry.shapes[k], &at);
                defer a.free(sh.trees);
                break :blk try Seed.Layout.of(sh);
            };
            const extra: usize = src.len - (GnCheck.wire_words + L.words); // leaf tail + outputs
            const words = region_words[k] + extra;
            const r = try a.alloc(u32, words);
            @memcpy(r, src[0..words]); // GnCheck regions already put the image at wire_words
            self.regions[k] = r;
            self.region_words[k] = @intCast(words);
            made += 1;
        }
        // The node job (production code path) over placeholder buffers; stage
        // binds the real device addresses before anything runs.
        const fake: [*]u32 = @ptrFromInt(64);
        const target = OuterDevice.Target{ .device = device, .region = .{ .ptr = fake, .words = self.target_words }, .pcs_status = .{ .ptr = fake, .words = 1 }, .encode_status = .{ .ptr = fake, .words = 1 }, .oods_status = .{ .ptr = fake, .words = 1 } };
        const m = try entry.node.make(entry.node.ctx, a, target);
        errdefer m.destroy(m.ctx);
        self.made = @ptrCast(@alignCast(m.ctx));
        self.node = .{ .a = a, .ops = .{ .seed = shared.seed.?, .d2d = @ptrCast(shared.kernels.d2d), .peer = shared.peer orelse return error.GnNodeJobPeerOpsUnloaded }, .class = &entry.node, .device = 0, .verdicts = .{ .seed_tape = .{ .ptr = fake, .words = 1 }, .child_binding = .{ .ptr = fake, .words = 1 }, .lookup_sum = .{ .ptr = fake, .words = 1 }, .channel_order = .{ .ptr = fake, .words = 1 } }, .made = m };
        self.node.n_children = @intCast(nk);
        for (0..nk) |k| self.node.children[k] = .{ .device = 0, .region = .{ .ptr = fake, .words = self.region_words[k] } };
        // Field: target region + 7 verdict words (host readback of the stand-in segment).
        self.field_words = self.target_words + 8;
        _ = try self.made.job.layout.add(.opaque_words, field_index, self.field_words);
        self.host_image = try a.dupe(u32, own_image);
        return self;
    }
    fn deinit(self: *GnJob, a: std.mem.Allocator) void {
        self.node.deinit();
        for (self.regions[0..self.n_children]) |x| a.free(x);
        if (self.bytes) |b| a.free(b);
        a.free(self.host_image);
    }
    fn job(self: *GnJob) api.Job {
        return api.Job.from(GnJob, self);
    }
    pub fn classKey(self: *GnJob) [32]u8 {
        return self.node.classKey();
    }
    fn g64(words: u64) u64 {
        return std.mem.alignForward(u64, @max(words, 1), 64);
    }
    fn segWords(self: *const GnJob) usize {
        var n: usize = 0;
        for (self.region_words[0..self.n_children]) |w| n += g64(w);
        return n + g64(self.target_words) + 64;
    }
    pub fn footprint(self: *GnJob) api.Footprint {
        var fp = self.node.footprint();
        const x = self.segWords();
        fp.device_words += x;
        fp.staged_words += x;
        for (self.regions[0..self.n_children]) |r| fp.pinned_words += r.len;
        return fp;
    }
    pub fn stage(self: *GnJob, s: *api.Stager) !void {
        const seg = try s.alloc(self.segWords());
        var at: usize = 0;
        for (self.regions[0..self.n_children], 0..) |r, k| {
            const b = try seg.slice(at, r.len);
            const pinned = try s.pinned(r.len);
            @memcpy(pinned, r);
            try s.upload(b, pinned);
            self.node.children[k] = .{ .device = 0, .region = b };
            at += @intCast(g64(r.len));
        }
        const target = try seg.slice(at, self.target_words);
        at += @intCast(g64(self.target_words));
        const words = try seg.slice(at, 8);
        self.node.verdicts = .{ .seed_tape = try words.slice(0, 1), .child_binding = try words.slice(1, 1), .lookup_sum = try words.slice(2, 1), .channel_order = try words.slice(3, 1) };
        self.made.enc.target = .{ .region = target, .pcs_status = try words.slice(4, 1), .encode_status = try words.slice(5, 1), .layout_status_oods = try words.slice(6, 1) };
        if (self.made.enc.oods) |*o| o.status = try words.slice(6, 1);
        self.target = target;
        self.words = words;
        try self.node.stage(s);
    }
    pub fn enqueue(self: *GnJob, e: *api.Enqueue) !void {
        try self.node.enqueue(e);
        const f = try e.slab.field(.opaque_words, field_index);
        if (self.d2d(e.ctx(), @ptrCast(f.ptr), @ptrCast(self.target.ptr), self.target_words * 4) != 0) return error.GnNodeJobCopyFailed;
        if (self.d2d(e.ctx(), @ptrCast(f.ptr + self.target_words), @ptrCast(self.words.ptr), 7 * 4) != 0) return error.GnNodeJobCopyFailed;
    }
    pub fn finish(self: *GnJob, view: api.SlabView) !void {
        const w = try @import("jobs/slab.zig").read(view, .opaque_words, field_index);
        @memcpy(&self.verdicts, w[self.target_words..][0..7]);
        const n = w[0];
        if (n <= 4 * (self.target_words - 1)) {
            const b = try self.allocator.alloc(u8, n);
            @memcpy(b, std.mem.sliceAsBytes(w[1..])[0..n]);
            self.bytes = b;
        }
        // The node's own PCS image tail (its parent's seed source).
        const tail = w[self.target_words - self.host_image.len .. self.target_words];
        self.image_eq = std.mem.eql(u32, tail, self.host_image);
        self.outcome = self.made.job.report.outcome;
        self.launches = self.made.job.report.launches;
        try self.node.finish(view);
    }
    pub fn abort(self: *GnJob) void {
        self.node.abort();
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
        std.debug.print("GPU_M8_OUTER_NODE_HOST ordinal={d} device={d} prestage_ns={d} init_ns={d} job_ns={d} stage_ns={d} enqueue_ns={d} wait_ns={d} finish_ns={d} decode_ns={d} assemble_ns={d} fixed_handoff={} class_plan={} class_plan_builds={d} class_plan_hits={d} class_plan_build_ns={d}\n", .{ ordinal, r.receipt.device, r.prestage_ns, r.init_ns, r.job_ns, r.receipt.stage_ns, r.receipt.enqueue_ns, r.receipt.wait_ns, r.finish_ns, r.decode_ns, r.assemble_ns, r.fixed_handoff, r.borrowed_plan, CP.stats.builds.load(.monotonic), CP.stats.hits.load(.monotonic), CP.stats.build_ns.load(.monotonic) });
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
    /// M8 feeder (STWO_RV64_M8_JOBS=1): an already-booted, parked WorkerSet
    /// shared with the native hybrid (one context per GPU for the request).
    /// The window unparks/parks it like its own persistent set but never
    /// stops it (its owner does).
    shared_set: ?*Jobs.WorkerSet = null,

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
            // Two-key fault injection (outer_checks.zig): a leftover ordinal
            // alone refuses service start instead of failing production nodes.
            k.fault_ordinal = try Env.optionalUnsigned(u32, "STWO_RV64_M8_OUTER_FAULT_ORDINAL");
            if (k.fault_ordinal != null and !try Env.flag("STWO_RV64_M8_FAULT_INJECTION", false)) return error.M8FaultInjectionNotArmed;
            k.reserve_bytes = try Env.unsigned(u64, "STWO_RV64_M8_OUTER_RESERVE_BYTES", k.reserve_bytes);
            k.graphs = try Graphs.Policy.fromEnv();
            // Node-job knobs are parsed per job; check them here so a bad
            // value fails the service at create, not at the first node.
            _ = try Env.flag("STWO_RV64_M8_OUTER_STREAM", true);
            _ = try Env.unsigned(usize, "STWO_RV64_M8_OUTER_STREAM_CHUNK_WORDS", 0);
            _ = try Env.unsigned(u64, "STWO_RV64_M8_OUTER_PCS_RESERVE_TREES", 0);
            _ = try Env.optionalUnsigned(u64, "STWO_RV64_M8_OUTER_DECLARE_WORDS");
            _ = try Env.flag("STWO_RV64_M8_OUTER_LEAF_PERSISTENT", false);
            _ = try CP.selected();
            _ = try CP.hostBudgetBytes();
            _ = try Checks.selected();
            _ = try Checks.faultOrdinal();
            _ = try Enc.mode();
            _ = try Enc.faultOrdinal();
            _ = try Enc.oodsFaultOrdinal();
            _ = try Enc.oodsPointFaultOrdinal();
            return k;
        }
    };

    /// Use `set` (parked, owned by the caller, outliving this Hybrid) for
    /// every window instead of booting one. Before the first window only.
    pub fn adoptSet(self: *Hybrid, set: *Jobs.WorkerSet) !void {
        if (self.window != null or !self.persist) return error.M8OuterSharedSetRequiresPersistentWindow;
        if (!set.parked()) return error.M8OuterSharedSetNotParked;
        self.shared_set = set;
    }
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
        const set = if (self.shared_set) |shared| shared else if (self.persist) try Jobs.WorkerSet.startParked(self.allocator, self.library, config) else try Jobs.WorkerSet.startWith(self.allocator, self.library, config);
        errdefer if (self.shared_set == null) set.stop(self.allocator) else {
            _ = set.park(.{}) catch {};
        };
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
        if (self.shared_set == null) w.set.stop(self.allocator) else _ = w.set.park(.{}) catch |err| std.debug.print("GPU_M8_OUTER_WINDOW shared_park_failed error={s}\n", .{@errorName(err)});
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
