//! Node proving and installed-class custody owner; class locks never cross into the facade.
const Timer = @import("outer_gpu_timer.zig");
const Checks = @import("outer_node_checks.zig");
const Schema = @import("outer_job_factory.zig");
const std = @import("std");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Prestage = @import("outer_job_prestage.zig");
const K = @import("jobs/outer_kernels.zig");
const Graphs = @import("jobs/outer_graph_cache.zig");
const Job = @import("jobs/outer_job.zig");
const FixedJob = @import("jobs/outer_fixed_job.zig");
const Worker = @import("jobs/worker.zig");
const api = @import("jobs/api.zig");
const Events = @import("cuda_events.zig");
const Enc = @import("jobs/outer_encode.zig");
const EncJob = @import("jobs/outer_encode_job.zig");
const Seed = @import("jobs/outer_seed_device.zig");
const GnRecord = @import("outer_seed_record.zig");
const OuterDevice = @import("jobs/outer_device.zig");
const Runtime = @import("native_node_class.zig");
const Recorder = @import("outer_node_checks.zig").Recorder;

pub const Prover = struct {
    shared: *const Schema.Shared,
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
        var timer: ?Timer.GpuTimer = if (self.shared.events) |*ev| Timer.GpuTimer{ .api = ev } else null;
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

    pub fn init(a: std.mem.Allocator, shared: *const Schema.Shared, worker: *Worker.Worker, policy: Graphs.Policy) Prover {
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
    fn gnJob(self: *Prover, a: std.mem.Allocator, input: Prestage.Input, cur: *const @import("jobs/outer_staged.zig").Staged, g: *const Checks.GnCheck, wire: []const u8, image: []const u32, handoff: ?Job.FixedHandoff) !void {
        const entry = NodeClasses.get(cur.class_key) orelse return error.GnNodeClassNotHarvested;
        // A leaf's Blake sample prefill tape is a per-node HOST input today
        // (leaf_graph): hand this node's to the template (same class, same
        // length; remaining host work, see the receipt).
        if (entry.staged.assignment.sample_tape) |t| {
            const c = cur.assignment.sample_tape orelse return error.GnNodeSampleTapeMissing;
            if (c.len != t.len) return error.GnNodeSampleTapeShape;
            entry.staged.assignment.sample_tape = c;
            entry.staged.assignment.sample_map = cur.assignment.sample_map;
        }
        // Under the hybrid window's per-job class-region policy (and with no
        // lane handoff of the same FIXED size) the node recommits its FIXED
        // tree from its own PP's raw evaluations: hand them over too (same
        // class: same layout and values). With persistent class regions the
        // FIXED tree is committed once per worker instead.
        if (cur != entry.staged and cur.fixed_raw.len != 0) {
            if (!std.mem.eql(u32, cur.fixed_logs, entry.fixed_logs)) return error.GnNodeFixedLayout;
            entry.staged.fixed_raw = cur.fixed_raw;
        }
        // Never keep a pointer into a PP that dies with this node.
        defer entry.staged.fixed_raw = &.{};
        var timer = try std.time.Timer.start();
        // Children regions in the slab convention: image in the last words.
        var region_words: [Seed.max_children]u32 = undefined;
        const nk = g.regions.len;
        for (g.regions, 0..) |x, k| {
            var at: usize = 0;
            const sh = try Seed.Shape.parse(std.heap.c_allocator, entry.shapes[k], &at);
            defer std.heap.c_allocator.free(sh.trees);
            region_words[k] = Checks.GnCheck.wire_words + @as(u32, @intCast((try Seed.Layout.of(sh)).words));
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
        // The FIXED coefficients the node just used (the lane's precommit
        // handoff region): in the hybrid window a second class-persistent
        // FIXED copy does not fit next to the legacy pipeline's live memory.
        w.made.job.fixed_handoff = handoff;
        // Class regions follow the Prover's policy: the hybrid window stages
        // them per job (its workers park between requests; persistent class
        // regions would sit next to the legacy pipeline's live memory).
        w.made.job.persistent_classes = self.persistent_classes;
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
    pub fn prove(self: *Prover, a: std.mem.Allocator, input: Prestage.Input, fixed: ?Schema.FixedHandoff, report: ?*Schema.Report) !Outer.prove.Produced {
        var timer = try std.time.Timer.start();
        const staged = try Prestage.prestage(a, input);
        // gn-node: the first node of a class leaves its Staged as the class
        // template of the GPU-native node job (NodeClasses).
        var keep_staged = false;
        defer if (!keep_staged) staged.deinit();
        var r = Schema.Report{ .prestage_ns = timer.lap() };
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
        var gpu: ?Timer.GpuTimer = if (self.shared.events) |*ev| Timer.GpuTimer{ .api = ev } else null;
        defer if (gpu) |*t| t.deinit();
        if (gpu) |*t| job.timing = t.timing();
        // Device encoding (check mode): the encoder runs after the body on the
        // same stream; its bytes are compared with the host's below.
        var encode: ?Checks.EncodeCheck = null;
        defer if (encode) |*c| c.deinit(a);
        if (self.shared.encode_mode != .off) {
            if (self.shared.encode_mode != .check) return error.M8OuterDeviceEncodePublishNotLanded;
            encode = try Checks.EncodeCheck.init(a, &job, self.shared, input.key, staged);
            encode.?.arm();
            encode.?.node.fault = if (try Enc.faultOrdinal()) |n| n == input.ordinal else false;
            encode.?.node.oods_fault = if (try Enc.oodsFaultOrdinal()) |n| n == input.ordinal else false;
            encode.?.node.oods_point_fault = if (try Enc.oodsPointFaultOrdinal()) |n| n == input.ordinal else false;
        }
        var gn: ?Checks.GnCheck = null;
        defer if (gn) |*g| g.deinit(a);
        if (self.shared.seed) |sym| {
            gn = try Checks.GnCheck.init(a, input, staged, &job, sym, if (self.shared.events) |*ev| ev else null);
            gn.?.arm();
            // Checks.GnCheck erases host outputs and derives them on the device.
            // The diagnostic encoder must read that same device plane.
            if (encode) |*c| {
                c.node.outputs_on_device = true;
                gn.?.encoder = &c.node;
            }
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
            if (GnRecord.jobSelected()) try self.gnJob(a, input, staged, g, wire, image, job.fixed_handoff);
            if (report) |out| out.* = r;
        }
        if (record_image) |image| if (Recorder.dir() != null) Recorder.write(a, input, staged, &job, &produced, image) catch |err| {
            std.debug.print("GN_NODE_RECORD ordinal={d} error={s}\n", .{ input.ordinal, @errorName(err) });
            return err;
        };
        return produced;
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
        shared: *const Schema.Shared,
        runtime_symbols: Runtime.Symbols,
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
        /// Owned copy of the Authority's FIXED column logs (Staged.fixed_logs).
        fixed_logs: []u32 = &.{},
        owns_template: bool = false,
        resources_warmed: bool = false,
        compressed: ?@import("jobs/outer_packed_class.zig").Class = null,
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
                const region = try Seed.ChildRegion.of(region_words[k], L.words, if (self.leaf) self.tail else 0, if (self.leaf) @intCast(self.staged.expected.len) else 0);
                classes[k] = .{ .shape = parsed[k], .wire_words = region.wire_words, .n_outputs = self.n_outputs[k], .identity = self.identities[k], .fixed_root = self.fixed_roots[k] };
            }
            var st = self.statement;
            const prog = if (self.leaf) blk: {
                // leaf: [len][native bytes][image][statement tail][outputs]
                st.outputs_at = (try Seed.ChildRegion.of(region_words[0], (try Seed.Layout.of(parsed[0])).words, self.tail, @intCast(self.staged.expected.len))).outputs_at;
                break :blk try Seed.buildLeaf(a, classes[0], Checks.GnCheck.leaf_cap_log, self.tail, self.vars, self.constants, st);
            } else try Seed.buildFold(a, classes[0..n], Checks.GnCheck.cap_log, self.vars, self.constants, st);
            if (self.program.len != 0) a.free(self.program);
            self.program = prog.words;
            self.node.program = prog.words;
            std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(prog.words), &self.node.prog_key, .{});
        }
    };
    var mutex: std.Thread.Mutex = .{};
    var entries: std.ArrayListUnmanaged(*Entry) = .empty;
    var install_nodes: std.AutoHashMapUnmanaged(u32, *Entry) = .empty;
    pub fn beginInstall() void {
        mutex.lock();
        defer mutex.unlock();
        install_nodes.clearRetainingCapacity();
    }
    pub fn installedNodes(a: std.mem.Allocator) ![]*Entry {
        mutex.lock();
        defer mutex.unlock();
        const out = try a.alloc(*Entry, install_nodes.count());
        errdefer a.free(out);
        for (out, 0..) |*entry, i| entry.* = install_nodes.get(@intCast(i)) orelse return error.GnNodeInstallOrdinal;
        return out;
    }
    /// Service teardown, after every class cache, worker and request is gone.
    /// Diagnostic templates retain their existing process lifetime.
    pub fn releaseInstalled() void {
        mutex.lock();
        defer mutex.unlock();
        const a = std.heap.c_allocator;
        install_nodes.clearRetainingCapacity();
        var keep: usize = 0;
        for (entries.items) |e| {
            if (!e.owns_template) {
                entries.items[keep] = e;
                keep += 1;
                continue;
            }
            for (e.shapes) |shape| a.free(shape);
            a.free(e.shapes);
            a.free(e.desc);
            a.free(e.oods_program);
            a.free(e.vars);
            a.free(e.constants);
            a.free(e.identities);
            a.free(e.fixed_roots);
            a.free(e.n_outputs);
            a.free(e.program);
            a.free(e.fixed_logs);
            if (e.compressed) |*p| p.deinit(a);
            e.staged.deinit();
            a.destroy(e);
        }
        entries.shrinkRetainingCapacity(keep);
    }
    pub fn installing() bool {
        const v = std.posix.getenv("STWO_RV64_M8_GN_INSTALL") orelse return false;
        return std.mem.eql(u8, v, "1");
    }
    fn installNode(ordinal: u32, e: *Entry) !void {
        mutex.lock();
        defer mutex.unlock();
        if (install_nodes.get(ordinal)) |old| {
            if (old != e) return error.GnNodeInstallOrdinal;
        } else try install_nodes.put(std.heap.c_allocator, ordinal, e);
    }
    pub fn get(class_key: [32]u8) ?*Entry {
        mutex.lock();
        defer mutex.unlock();
        for (entries.items) |e| if (std.mem.eql(u8, &e.class_key, &class_key)) return e;
        return null;
    }
    pub fn pack(entry: *Entry) !void {
        if (entry.compressed == null) entry.compressed = try Prestage.packTemplate(std.heap.c_allocator, entry.staged);
        entry.node.compressed = true;
    }
    pub fn count() usize {
        mutex.lock();
        defer mutex.unlock();
        return entries.items.len;
    }
    /// Returns true when `staged` became the class template (the caller
    /// must not deinit it).
    fn harvest(shared: *const Schema.Shared, input: Prestage.Input, staged: *@import("jobs/outer_staged.zig").Staged, job: *Job.OuterNodeJob, g: *const Checks.GnCheck) !bool {
        if (get(staged.class_key)) |known| {
            if (installing()) try installNode(input.ordinal, known);
            return false;
        }
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
        const own_template = installing();
        const template = if (own_template) try Prestage.retainTemplate(a, input, staged) else staged;
        errdefer if (own_template) template.deinit();
        const nk = g.regions.len;
        e.* = .{
            .class_key = staged.class_key,
            .node = .{ .program = &.{}, .prog_key = @splat(0), .n_children = @intCast(nk), .output_words = @intCast(staged.expected.len), .ctx = e, .make = Runtime.Adapter(Entry).make },
            .shared = shared,
            .runtime_symbols = .{ .kernels = &shared.kernels, .whole = shared.whole(), .encode = shared.encode, .oods = shared.oods },
            .staged = template,
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
            .owns_template = own_template,
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
        // The template outlives the node's Authority / PP: own what the
        // Staged borrowed from them. FIXED raw evaluations are not kept (the
        // class FIXED tree comes from its persistent region or the lane's
        // precommit handoff; packFixed refuses rather than read freed PP).
        e.fixed_logs = try a.dupe(u32, template.fixed_logs);
        template.fixed_logs = e.fixed_logs;
        // (fixed_raw stays this node's until its job-mode check ends; see
        // Prover.gnJob, which then erases it.)
        // The template carries no host value: the device writes seeds,
        // checkpoint and outputs per node.
        @memset(@constCast(template.expected), 0);
        // A leaf's schedule (tasks, indices, chain ends) is a class constant
        // of the template too: move it from the node region (re-packed and
        // uploaded per node, ~75 MB for a 2.4 M-task leaf) to the class
        // region (uploaded once per worker). Layout only, proof-neutral.
        if (!template.assignment.reusable) {
            template.assignment.reusable = true;
            template.image = @import("jobs/outer_staged.zig").Staged.layoutWith(&template.assignment, template.statics, if (template.lookup != null) template.expected.len else 0);
        }
        mutex.lock();
        defer mutex.unlock();
        try entries.append(a, e);
        if (own_template) try install_nodes.put(a, input.ordinal, e);
        std.debug.print("GN_NODE_CLASS harvested ordinal={d} class={x} leaf={} children={d} classes={d}\n", .{ input.ordinal, staged.class_key[0..8].*, input.is_leaf, nk, entries.items.len });
        return !own_template;
    }
    fn parseShape(a: std.mem.Allocator, words: []const u32) !Seed.Shape {
        var at: usize = 0;
        return Seed.Shape.parse(a, words, &at);
    }
    const Made = Runtime.Made;
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

    fn init(a: std.mem.Allocator, entry: *NodeClasses.Entry, g: *const Checks.GnCheck, region_words: []const u32, shared: *const Schema.Shared, own_image: []const u32, device: u32) !GnJob {
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
            const extra: usize = src.len - (Checks.GnCheck.wire_words + L.words); // leaf tail + outputs
            const words = region_words[k] + extra;
            const r = try a.alloc(u32, words);
            @memcpy(r, src[0..words]); // Checks.GnCheck regions already put the image at wire_words
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
// Class-installation mode (GPU-native install only, STWO_RV64_M8_GN_INSTALL=1
// set by native_recursion_install.zig): the legacy request orchestration and
// native proving stay as they are; every leaf/fold/root
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
