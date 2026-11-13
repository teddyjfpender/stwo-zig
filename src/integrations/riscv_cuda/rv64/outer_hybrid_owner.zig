//! Hybrid service lifetime owner: lanes, request windows, FIXED handoff and teardown.
const Schema = @import("outer_job_factory.zig");
const std = @import("std");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Prestage = @import("outer_job_prestage.zig");
const Graphs = @import("jobs/outer_graph_cache.zig");
const FixedJob = @import("jobs/outer_fixed_job.zig");
const Worker = @import("jobs/worker.zig");
const Q = Outer.protocol.Q;
const Env = @import("jobs/outer_env.zig");
const OuterWindow = @import("jobs/outer_window.zig");
const CP = @import("jobs/outer_class_plan.zig");
const Checks = @import("jobs/outer_checks.zig");
const Enc = @import("jobs/outer_encode.zig");

const Dev = Outer.device_prove;
const Assignment = @import("outer_assignment.zig");
const Jobs = @import("jobs/mod.zig");
const Circuit = @import("stwo_circuit_frontend");
const Service = @import("pcs_native.zig");
const Memory = @import("runtime_memory.zig");

/// Node jobs run only while the GPU-native service installs its recursion
/// classes; every ordinary request keeps the legacy owner path.
pub fn hybridSelected() !bool {
    return Schema.NodeClasses.installing();
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
        var fr: Schema.Prover.FixedReport = .{};
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
        var r: Schema.Report = .{};
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

/// Window resources and graph caches, owned per physical device.
const Window = struct {
    set: *Jobs.WorkerSet,
    shared: Schema.Shared,
    provers: []Schema.Prover,
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

            k.fixed_handoff = k.fixed_handoff and k.fixed_job;

            // Two-key fault injection (outer_checks.zig): a leftover ordinal
            // alone refuses service start instead of failing production nodes.
            k.fault_ordinal = try Env.optionalUnsigned(u32, "STWO_RV64_M8_OUTER_FAULT_ORDINAL");
            if (k.fault_ordinal != null and !try Env.flag("STWO_RV64_M8_FAULT_INJECTION", false)) return error.M8FaultInjectionNotArmed;

            k.graphs = try Graphs.Policy.fromEnv();
            // Node-job knobs are parsed per job; check them here so a bad
            // value fails the service at create, not at the first node.
            _ = true;
            _ = 0;
            _ = 0;
            _ = try Env.optionalUnsigned(u64, "STWO_RV64_M8_OUTER_DECLARE_WORDS");
            _ = false;
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

    pub fn create(a: std.mem.Allocator, library: []const u8) !*Hybrid {
        const fs_path = std.posix.getenv("STWO_RV64_M8_OUTER_FS_LIBRARY") orelse return error.MissingM8OuterFsLibrary;
        _ = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return error.MissingM8JobsLibrary;
        const knobs = try Knobs.fromEnv();
        const persist = true;
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
        std.debug.print("GPU_M8_OUTER_INSTALL lanes={d} devices={d}\n", .{ made.len, services.len });
    }

    fn prover(self: *Hybrid, lane: usize) !*Schema.Prover {
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
        var shared = try Schema.Shared.init(&set.libs.base, &set.libs.addon, self.fs_path);
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
        const provers = try self.allocator.alloc(Schema.Prover, unique);
        self.window = .{ .set = set, .shared = shared, .provers = provers, .lane_prover = lane_prover, .started_ns = 0 };
        const w = &self.window.?;
        self.open_now = true;
        for (provers, workers[0..provers.len]) |*p, worker| {
            p.* = Schema.Prover.init(self.allocator, &w.shared, worker, self.knobs.graphs);
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
