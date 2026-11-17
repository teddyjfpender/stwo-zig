//! Prep, device and finish queues for one admitted recursion plan.
const std = @import("std");
const Root = @import("services_root.zig");
const Graph = @import("leaf_graph.zig");
const Outer = @import("outer_wrap.zig");
const Bridge = @import("../om31_outer.zig");
const FoldTape = @import("fold_tape.zig");
const SharedBudget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Dag = @import("ready_dag.zig");
const Pools = @import("stwo_prover_engine").work_pool;
const ownership_owner = @import("execution_wrap_ownership.zig");
const Pending = ownership_owner.Pending;
const cached = ownership_owner.cached;
const child = ownership_owner.child;
const hybridChildren = ownership_owner.hybridChildren;
const context_owner = @import("execution_wrap_context.zig");
const Pipe = context_owner.Pipe;
const PreparedExecution = context_owner.PreparedExecution;
const main_owner = @import("execution_wrap.zig");
const Node = main_owner.Node;
const ParallelOptions = main_owner.ParallelOptions;
const Report = main_owner.Report;
const run = main_owner.run;
const treeJson = main_owner.treeJson;

pub const Pipelined = struct {
    input: PreparedExecution,
    options: ParallelOptions,
    pipe: Pipe.Options,
    plan: *const Dag.Plan,
    queue: Dag.Queue,
    scramble_seed: ?u64 = null,
    scramble_dispatch: u64 = 0,
    nodes: []Node,
    records: []Pipe.Record,
    prep_pool: *Pools.WorkPool,
    proofs: [Dag.max_nodes]?Pending = @splat(null),
    mutex: std.Thread.Mutex = .{},
    changed: std.Thread.Condition = .{},
    fatal: ?anyerror = null,
    ready: std.ArrayList(*Pipe.Job) = .empty,
    finishing: std.ArrayList(*Pipe.Job) = .empty,
    leaves_ahead: usize = 0,
    /// Leaves inside prep right now (streaming throttle while native runs).
    prepping_leaves: usize = 0,
    /// Per lane: kind of the node in its device stage (sched M6 size-class
    /// admission when several lanes share one physical device).
    lane_leaf: [4]bool = @splat(false),
    leaves_per_device: usize = 1,
    peak_leaves_ahead: usize = 0,
    peak_ready: usize = 0,
    origin_ns: u64,
    graph_ns: u64 = 0,
    wrap_ns: u64 = 0,
    fold_ns: u64 = 0,
    restored_leaves: usize = 0,
    restored_folds: usize = 0,
    retired_bytes: usize = 0,
    pub fn now(self: *Pipelined) u64 {
        return self.input.timer.read() - self.origin_ns;
    }
    pub fn running(self: *const Pipelined) bool {
        if (self.input.stream) |stream| if (stream.stopped.load(.acquire)) return false;
        return self.fatal == null and self.queue.failure == null and self.queue.completed < self.plan.count;
    }
    /// Caller holds the mutex. Streaming: open the leaves whose native proof
    /// is final; hold leaf prep to the configured share while native runs.
    pub fn admitLeaves(self: *Pipelined) bool {
        const stream = self.input.stream orelse return true;
        if (self.queue.closed.count() != 0) for (0..self.input.words.len) |ordinal| {
            if (self.queue.closed.isSet(ordinal) and stream.ready[ordinal].load(.acquire)) self.queue.openLeaf(ordinal);
        };
        return stream.nativeComplete() or self.prepping_leaves < stream.prep_during_native;
    }
    pub fn stop(self: *Pipelined, err: anyerror) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.fatal == null) self.fatal = err;
        self.changed.broadcast();
    }
    /// Caller holds the mutex.
    pub fn failLocked(self: *Pipelined, job: *Pipe.Job, err: anyerror) void {
        std.log.err("rv64 OM31 pipelined recursion node {d} failed: {s}", .{ job.id, @errorName(err) });
        self.queue.fail(job.id, err);
        self.changed.broadcast();
    }
    pub fn hostWorker(self: *Pipelined) void {
        var binding = Pools.ScopedPoolBinding.init(self.prep_pool) catch |err| return self.stop(err);
        defer binding.deinit();
        const a = self.input.allocator;
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.running()) {
            // Finishing first: completion is what makes parents ready.
            if (self.finishing.items.len != 0) {
                const job = self.finishing.orderedRemove(0);
                self.mutex.unlock();
                const finished = self.finish(job);
                self.mutex.lock();
                if (finished) |retired| self.completeLocked(job, retired) else |err| {
                    self.failLocked(job, err);
                    self.mutex.unlock();
                    job.destroy(a);
                    self.mutex.lock();
                }
                continue;
            }
            const leaves = self.admitLeaves() and self.leaves_ahead < self.pipe.prep_ahead;
            const next = self.queue.takeFiltered(leaves) catch |err| {
                if (self.fatal == null) self.fatal = err;
                self.changed.broadcast();
                return;
            };
            if (next) |id| {
                const spec = self.plan.nodes[id];
                // k-ary (m3) and binary (r1) folds alike: ordered, adjacent kids.
                var kid_buffer: [Dag.max_arity]Pending = undefined;
                var children: ?[]const Pending = null;
                if (!spec.isLeaf()) {
                    for (spec.kids(), 0..) |kid, i| kid_buffer[i] = self.proofs[kid].?;
                    children = kid_buffer[0..spec.arity];
                } else {
                    self.leaves_ahead += 1;
                    self.prepping_leaves += 1;
                    self.peak_leaves_ahead = @max(self.peak_leaves_ahead, self.leaves_ahead);
                }
                const taken = self.now();
                self.mutex.unlock();
                const job = a.create(Pipe.Job) catch |err| {
                    self.mutex.lock();
                    if (spec.isLeaf()) self.leaves_ahead -= 1;
                    if (spec.isLeaf()) self.prepping_leaves -= 1;
                    self.queue.fail(id, err);
                    self.changed.broadcast();
                    continue;
                };
                job.* = .{ .id = id, .record = .{ .id = id, .kind = if (spec.isLeaf()) "leaf" else "fold", .first_leaf = spec.first_leaf, .leaf_count = spec.leaf_count, .stamps = .{ .taken = taken } } };
                const prepared = self.prep(job, children);
                self.mutex.lock();
                if (spec.isLeaf()) self.prepping_leaves -= 1;
                if (prepared) |needs_device| {
                    if (needs_device) {
                        self.ready.appendAssumeCapacity(job);
                        self.peak_ready = @max(self.peak_ready, self.ready.items.len);
                    } else {
                        // Restored from durable bytes: no device stage.
                        if (spec.isLeaf()) self.leaves_ahead -= 1;
                        self.finishing.appendAssumeCapacity(job);
                    }
                    self.changed.broadcast();
                } else |err| {
                    if (spec.isLeaf()) self.leaves_ahead -= 1;
                    self.failLocked(job, err);
                    self.mutex.unlock();
                    job.destroy(a);
                    self.mutex.lock();
                }
                continue;
            }
            self.changed.wait(&self.mutex);
        }
        self.changed.broadcast();
    }
    /// Returns true when the node needs the device stage.
    pub fn prep(self: *Pipelined, job: *Pipe.Job, children: ?[]const Pending) !bool {
        const in = self.input;
        const a = in.allocator;
        job.record.stamps.prep_start = self.now();
        var timer = try std.time.Timer.start();
        var name_buffer: [64]u8 = undefined;
        var kid_buffer: [Dag.max_arity]Bridge.Child = undefined;
        const kids: []const Bridge.Child = if (children) |list| blk: {
            for (list, 0..) |pending, i| kid_buffer[i] = child(pending);
            break :blk kid_buffer[0..list.len];
        } else &.{};
        const name = if (children != null) blk: {
            job.digest = try Bridge.expectedDigest(kids);
            // M6 hint-tape (HT1) minimal hook: a class-cached fold skips the graph.
            if (try self.prepFoldTape(job, kids, &timer)) return true;
            const fold = try a.create(Bridge.Graph);
            fold.* = Bridge.buildFoldTraceOnly(a, kids) catch |err| {
                a.destroy(fold);
                return err;
            };
            job.fold = fold;
            if (!std.mem.eql(u8, &job.digest, &fold.output_digest)) return error.RecursiveFoldDigest;
            if (FoldTape.mode() == .check and !hybridChildren(kids)) {
                const tape = try FoldTape.record(a, kids);
                defer a.free(tape);
                try FoldTape.compare(a, tape, &fold.ctx);
            }
            break :blk try std.fmt.bufPrint(&name_buffer, "fold-{d:0>6}.proof", .{job.id});
        } else blk: {
            const ordinal = self.plan.nodes[job.id].first_leaf;
            job.leaf = try self.leafGraph(ordinal, true);
            if (job.leaf.?.seed_tape != null) {
                if (try self.prepLeafTape(job, &timer)) return true;
                // A PP hit can outlive a bounded assignment-template miss. Rebuild
                // the full graph after a refusal; never prove the stub directly.
                job.leaf.?.deinit();
                job.leaf = null;
                job.leaf = try self.leafGraph(ordinal, false);
            }
            if (!std.mem.eql(u32, job.leaf.?.words, in.words[ordinal])) return error.RecursiveLeafFrame;
            job.digest = job.leaf.?.digest;
            break :blk try std.fmt.bufPrint(&name_buffer, "leaf-{d:0>6}.proof", .{ordinal});
        };
        job.record.graph_ns = timer.lap();
        const encoded = try cached(a, in.dir, name, in.allow_resume);
        defer if (encoded) |bytes| a.free(bytes);
        if (encoded) |bytes| {
            // Durable bytes: independent CPU reception (rebuilds PP/authority).
            const proof = try a.create(Outer.Wrapped);
            errdefer a.destroy(proof);
            proof.* = try Outer.wrapGraphOrLoadWithFactory(a, job.ctx(), job.digest, bytes, @intCast(job.id), null);
            job.wrapped = proof;
            job.record.restored = true;
            job.record.stamps.prep_end = self.now();
            return false;
        }
        // Fold v2: the topology-only producer plan cache keys by geometry class.
        // class_hint is threadlocal and Prepared.init (via prepare_host) runs on
        // this prep thread, so set it here as the lane path does in prove().
        if (children != null) Outer.Device.class_hint = try Bridge.classKey(kids) else Outer.Device.class_hint = job.leaf.?.class;
        defer Outer.Device.class_hint = null;
        Outer.Device.class_is_leaf = children == null;
        defer Outer.Device.class_is_leaf = false;
        Outer.Device.blake_sample_inputs = if (children == null) job.leaf.?.blake_sample_inputs else null;
        defer Outer.Device.blake_sample_inputs = null;
        // Any lane's factory: host prep reads only immutable library symbols.
        const raw_shape = @import("stwo_circuit_frontend").common.finalize.rawComponentSizes(.fromBuilder(&job.ctx().circuit));
        job.host = try Outer.prepareHost(a, job.ctx(), self.options.lanes[0].factory);
        Outer.reportShape(job.record.kind, job.id, raw_shape, job.ctx());
        job.record.variables = job.ctx().circuit.n_vars;
        job.record.finalize_ns = job.host.?.finalize_ns;
        job.record.columns_ns = job.host.?.columns_ns;
        job.record.host_plan_ns = job.host.?.host_plan_ns;
        job.record.host_authority_ns = job.host.?.authority_ns;
        job.record.stamps.prep_end = self.now();
        return true;
    }
    pub fn leafGraph(self: *Pipelined, ordinal: usize, allow_tape: bool) !Graph.Graph {
        const in = self.input;
        const a = in.allocator;
        const worker = in.inventory.workers[ordinal];
        const factory: ?Outer.Device.Factory = if (allow_tape and !in.allow_resume) self.options.lanes[0].factory else null;
        return if (ordinal < in.setups.len) try Graph.cpuTraceWithTape(a, .{ .setup = in.setups[ordinal], .request = in.bundle.requests[ordinal], .expected = worker, .first = in.inventory.first_ids[ordinal], .manifest = in.manifest, .index = ordinal, .stage = &in.stages.stages[ordinal], .config = in.config, .encoded = &in.bundle.cpus[ordinal], .fixed = if (in.fixed) |authority| authority.at(ordinal) else null }, factory) else try Graph.truthTraceWithTape(a, .{ .truth = in.truths[ordinal - in.setups.len], .expected = worker, .manifest = in.manifest, .config = in.config, .encoded = &in.bundle.truths[ordinal - in.setups.len], .fixed = if (in.fixed) |authority| authority.at(ordinal) else null }, factory);
    }
    pub fn prepLeafTape(self: *Pipelined, job: *Pipe.Job, timer: *std.time.Timer) !bool {
        const in = self.input;
        const a = in.allocator;
        const graph = &job.leaf.?;
        const values = graph.seed_tape orelse return false;
        if (!std.mem.eql(u32, graph.words, in.words[self.plan.nodes[job.id].first_leaf])) return error.RecursiveLeafFrame;
        const class = graph.class orelse return error.MissingLeafSeedClass;
        var tape = Outer.Device.SeedTape{ .values = values };
        Outer.Device.seed_tape = &tape;
        defer Outer.Device.seed_tape = null;
        Outer.Device.class_hint = class;
        defer Outer.Device.class_hint = null;
        Outer.Device.class_is_leaf = true;
        defer Outer.Device.class_is_leaf = false;
        Outer.Device.blake_sample_inputs = graph.blake_sample_inputs;
        defer Outer.Device.blake_sample_inputs = null;
        const graph_ns = timer.lap();
        const host = (try Outer.prepareHostTape(a, graph.ctx, self.options.lanes[0].factory, class)) orelse return false;
        if (!tape.consumed) {
            var unused = host;
            unused.deinit(a);
            return false;
        }
        graph.ctx.circuit.n_vars = tape.n_vars;
        job.digest = graph.digest;
        job.host = host;
        job.record.graph_ns = graph_ns;
        job.record.variables = tape.n_vars;
        job.record.host_plan_ns = host.host_plan_ns;
        job.record.host_authority_ns = host.authority_ns;
        job.record.stamps.prep_end = self.now();
        std.debug.print("LEAF_SEED_TAPE used node={} class={x} seeds={} record_ns={} authority_ns={} prep_ns={}\n", .{ job.id, class[0..8], values.len, graph_ns, host.authority_ns, job.record.stamps.prep_end - job.record.stamps.prep_start });
        return true;
    }
    /// M6 hint-tape (HT1): a fold whose class PP and class plan are cached is
    /// prepared from its seed tape and a flags-only stub graph. Returns false
    /// (nothing changed; the caller builds the graph) on any miss, on durable
    /// bytes (the restore path needs the real graph) and when the tape is off.
    pub fn prepFoldTape(self: *Pipelined, job: *Pipe.Job, kids: []const Bridge.Child, timer: *std.time.Timer) !bool {
        if (FoldTape.mode() != .on or hybridChildren(kids)) return false;
        const in = self.input;
        const a = in.allocator;
        if (in.allow_resume) {
            var name_buffer: [64]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buffer, "fold-{d:0>6}.proof", .{job.id});
            if (in.dir.statFile(name)) |_| return false else |err| if (err != error.FileNotFound) return err;
        }
        const class = try Bridge.classKey(kids);
        if (!Outer.tapeReady(self.options.lanes[0].factory, class)) return false;
        const values = try FoldTape.record(a, kids);
        defer a.free(values);
        const record_ns = timer.lap();
        var tape = Outer.Device.SeedTape{ .values = values };
        Outer.Device.seed_tape = &tape;
        defer Outer.Device.seed_tape = null;
        Outer.Device.class_hint = class;
        defer Outer.Device.class_hint = null;
        const fold = try a.create(Bridge.Graph);
        fold.* = FoldTape.stub(a, job.digest) catch |err| {
            a.destroy(fold);
            return err;
        };
        const host = Outer.prepareHostTape(a, &fold.ctx, self.options.lanes[0].factory, class) catch |err| {
            fold.deinit();
            a.destroy(fold);
            return err;
        };
        if (host == null or !tape.consumed) {
            var unused = host;
            if (unused) |*h| h.deinit(a);
            fold.deinit();
            a.destroy(fold);
            std.debug.print("FOLD_SEED_TAPE fallback node={} class={x} record_ns={}\n", .{ job.id, class[0..8], record_ns });
            return false;
        }
        fold.ctx.circuit.n_vars = tape.n_vars;
        job.fold = fold;
        job.host = host;
        job.record.graph_ns = record_ns;
        job.record.variables = tape.n_vars;
        job.record.host_plan_ns = host.?.host_plan_ns;
        job.record.host_authority_ns = host.?.authority_ns;
        job.record.stamps.prep_end = self.now();
        std.debug.print("FOLD_SEED_TAPE used node={} class={x} seeds={} record_ns={} authority_ns={} plan_ns={} prep_ns={}\n", .{ job.id, class[0..8], values.len, record_ns, host.?.authority_ns, host.?.host_plan_ns, job.record.stamps.prep_end - job.record.stamps.prep_start });
        return true;
    }
    pub fn deviceLane(self: *Pipelined, lane: usize) void {
        var binding = Pools.ScopedPoolBinding.init(self.options.lanes[lane].pool) catch |err| return self.stop(err);
        defer binding.deinit();
        const a = self.input.allocator;
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.running()) {
            const open = if (self.input.stream) |stream| stream.deviceOpen() else true;
            // Size-class admission: a leaf (the large composition class) may
            // start only while fewer than leaves_per_device leaves run on
            // this lane's physical device; folds always may.
            var device_leaves: usize = 0;
            for (self.options.lanes, 0..) |other, i| {
                if (i != lane and other.physical_device == self.options.lanes[lane].physical_device and self.lane_leaf[i]) device_leaves += 1;
            }
            const leaf_ok = device_leaves < self.leaves_per_device;
            var eligible = false;
            for (self.ready.items) |job| eligible = eligible or leaf_ok or job.leaf == null;
            if (!eligible or !open) {
                self.changed.wait(&self.mutex);
                continue;
            }
            // m5: the widest (highest) parent, then the lowest leaf id.
            // critical (sched M6): the deepest node below the root first (a
            // leaf before a fold at equal depth), then the lowest id.
            var best: ?usize = null;
            for (self.ready.items, 0..) |job, i| {
                if (job.leaf != null and !leaf_ok) continue;
                if (best == null) {
                    best = i;
                    continue;
                }
                const b = self.ready.items[best.?];
                const better = if (self.scramble_seed) |seed|
                    Dag.scrambleRank(seed, self.scramble_dispatch, job.id) < Dag.scrambleRank(seed, self.scramble_dispatch, b.id)
                else switch (self.queue.policy) {
                    .m5 => job.record.leaf_count > b.record.leaf_count or (job.record.leaf_count == b.record.leaf_count and job.id < b.id),
                    .critical => self.plan.priority(job.id) > self.plan.priority(b.id) or (self.plan.priority(job.id) == self.plan.priority(b.id) and job.id < b.id),
                };
                if (better) best = i;
            }
            const job = self.ready.orderedRemove(best.?);
            self.scramble_dispatch +%= 1;
            if (job.leaf != null) self.leaves_ahead -= 1;
            self.lane_leaf[lane] = job.leaf != null;
            self.changed.broadcast();
            self.mutex.unlock();
            const proved = self.device(job, lane);
            self.mutex.lock();
            self.lane_leaf[lane] = false;
            self.changed.broadcast();
            if (proved) |_| {
                self.finishing.appendAssumeCapacity(job);
                self.changed.broadcast();
            } else |err| {
                self.failLocked(job, err);
                self.mutex.unlock();
                job.destroy(a);
                self.mutex.lock();
            }
        }
        self.changed.broadcast();
    }
    pub fn device(self: *Pipelined, job: *Pipe.Job, lane: usize) !void {
        const a = self.input.allocator;
        job.record.lane = lane;
        job.record.stamps.device_start = self.now();
        defer job.record.stamps.device_end = self.now();
        job.proved = try Outer.proveDevice(a, job.ctx(), &job.host.?, job.digest, @intCast(job.id), self.options.lanes[lane].factory);
        job.host.?.deinit(a);
        job.host = null;
        job.record.authority_ns = job.proved.?.timings.authority_ns;
        job.record.device_prove_ns = job.proved.?.timings.prove_ns;
    }
    /// Returns retired prover bytes. On success the proof moves to job.wrapped.
    pub fn finish(self: *Pipelined, job: *Pipe.Job) !usize {
        const a = self.input.allocator;
        job.record.stamps.finish_start = self.now();
        // The parent consumes only the child's verifier metadata and proof.
        job.releaseGraph(a);
        var timer = try std.time.Timer.start();
        if (job.wrapped == null) {
            const proof = try a.create(Outer.Wrapped);
            errdefer a.destroy(proof);
            proof.* = try Outer.finishProved(a, &job.proved.?, job.digest);
            job.proved = null;
            job.wrapped = proof;
        }
        job.record.verify_ns = timer.lap();
        const spec = self.plan.nodes[job.id];
        var name_buffer: [64]u8 = undefined;
        const name = if (spec.isLeaf()) try std.fmt.bufPrint(&name_buffer, "leaf-{d:0>6}.proof", .{spec.first_leaf}) else try std.fmt.bufPrint(&name_buffer, "fold-{d:0>6}.proof", .{job.id});
        const bytes = try job.wrapped.?.serialize(a);
        defer a.free(bytes);
        try @import("publication.zig").write(self.input.dir, name, bytes);
        const retired = job.wrapped.?.retireProverData();
        job.record.publish_ns = timer.read();
        job.record.stamps.finish_end = self.now();
        return retired;
    }
    /// Caller holds the mutex. Verified and durably published: release the
    /// children only now, exactly as the lane path's publication does.
    pub fn completeLocked(self: *Pipelined, job: *Pipe.Job, retired: usize) void {
        const a = self.input.allocator;
        const id = job.id;
        const proof = job.wrapped.?;
        job.wrapped = null;
        self.proofs[id] = .{ .proof = proof, .node = id };
        const spec = self.plan.nodes[id];
        self.nodes[id] = .{ .first_leaf = spec.first_leaf, .leaf_count = spec.leaf_count, .left = spec.left(), .right = spec.right(), .authority = proof.effectiveIdentity(), .digest = proof.digest };
        self.retired_bytes += retired;
        const r = job.record;
        const host_ns = (r.stamps.prep_end - r.stamps.prep_start) + (r.stamps.finish_end - r.stamps.finish_start);
        const device_ns = r.stamps.device_end - r.stamps.device_start;
        if (!spec.isLeaf()) {
            for (spec.kids()) |kid| {
                self.proofs[kid].?.deinit(a);
                self.proofs[kid] = null;
            }
            self.fold_ns += host_ns + device_ns;
            self.restored_folds += @intFromBool(r.restored);
        } else {
            self.graph_ns += r.graph_ns;
            self.wrap_ns += host_ns - r.graph_ns + device_ns;
            self.restored_leaves += @intFromBool(r.restored);
        }
        self.records[id] = r;
        self.queue.complete(id);
        a.destroy(job);
        self.changed.broadcast();
    }
};

pub fn runPipelined(input: PreparedExecution, options: ParallelOptions, pipe: Pipe.Options, plan: *const Dag.Plan, nodes: []Node, budget: *SharedBudget) !Report {
    const a = input.allocator;
    const coordinator_stack = 8 << 20;
    const helper_stack = options.lanes[0].pool.stackSize();
    // Prep coordinators and their shared helper pool are charged to the same
    // host budget as the lane stacks; nothing here touches device memory.
    // Each host worker may run one transient PP/authority side thread.
    var stacks = try budget.reserveExternal(try std.math.add(usize, try std.math.mul(usize, 2 * pipe.host_workers, coordinator_stack), try std.math.mul(usize, pipe.prep_pool_workers - 1, helper_stack)));
    defer stacks.deinit();
    const prep_pool = try a.create(Pools.WorkPool);
    defer a.destroy(prep_pool);
    prep_pool.* = .{};
    try prep_pool.initInPlaceWithOptions(.{ .worker_count = pipe.prep_pool_workers, .stack_size = helper_stack, .backing_allocator = a });
    defer prep_pool.deinit();
    const records = try a.alloc(Pipe.Record, plan.count);
    defer a.free(records);
    @memset(records, .{});
    var shared = Pipelined{ .input = input, .options = options, .pipe = pipe, .plan = plan, .queue = try Dag.Queue.initPolicy(plan, options.lanes.len, options.max_pending_authorities, try Dag.Policy.fromEnv()), .nodes = nodes, .records = records, .prep_pool = prep_pool, .origin_ns = input.timer.read(), .scramble_seed = try Dag.scrambleSeedFromEnv() };
    if (shared.scramble_seed) |seed| std.debug.print("RECURSION_ADMISSION_ORDER policy=seeded_scramble seed={}\n", .{seed});
    if (input.stream != null) shared.queue.closeAllLeaves();

    try shared.ready.ensureTotalCapacity(a, plan.count);
    defer shared.ready.deinit(a);
    try shared.finishing.ensureTotalCapacity(a, plan.count);
    defer shared.finishing.deinit(a);
    defer {
        for (shared.ready.items) |job| job.destroy(a);
        for (shared.finishing.items) |job| job.destroy(a);
        for (shared.proofs[0..plan.count]) |proof| if (proof) |p| p.deinit(a);
    }
    const RootCheck = struct {
        input: *const PreparedExecution,
        metadata: ?Root.Metadata = null,
        failure: ?anyerror = null,
        ns: u64 = 0,
        pub fn run(self: *@This()) void {
            var timer = std.time.Timer.start() catch unreachable;
            const in = self.input;
            self.metadata = Root.check(in.allocator, in.setups, in.truths, in.bundle.requests, in.expected, in.config, in.fixed, in.bundle.stage_one_bytes, in.frames, .{}) catch |err| blk: {
                self.failure = err;
                break :blk null;
            };
            self.ns = timer.read();
        }
    };
    var root_check = RootCheck{ .input = &input };
    var root_thread: ?std.Thread = null;
    var root_joined = false;
    defer if (!root_joined) if (root_thread) |thread| thread.join();
    // Streaming: Root.check reads the whole bundle, so it starts once native
    // production is done (below); the M5 path starts it here.
    if (input.stream == null) {
        root_thread = std.Thread.spawn(.{ .stack_size = coordinator_stack }, RootCheck.run, .{&root_check}) catch null;
        if (root_thread == null) root_check.run();
    } else {
        input.stream.?.mutex.lock();
        input.stream.?.attached = &shared;
        input.stream.?.mutex.unlock();
    }
    defer if (input.stream) |stream| {
        stream.mutex.lock();
        stream.attached = null;
        stream.mutex.unlock();
    };
    std.log.info("rv64 OM31 pipelined recursion: nodes={d} lanes={d} host_workers={d} prep_pool_workers={d} prep_ahead={d}", .{ plan.count, options.lanes.len, pipe.host_workers, pipe.prep_pool_workers, pipe.prep_ahead });
    var threads: [36]std.Thread = undefined;
    var launched: usize = 0;
    for (options.lanes, 0..) |_, lane| {
        threads[launched] = std.Thread.spawn(.{ .stack_size = coordinator_stack }, Pipelined.deviceLane, .{ &shared, lane }) catch |err| {
            shared.stop(err);
            break;
        };
        launched += 1;
    }
    if (shared.fatal == null) for (0..pipe.host_workers) |_| {
        threads[launched] = std.Thread.spawn(.{ .stack_size = coordinator_stack }, Pipelined.hostWorker, .{&shared}) catch |err| {
            shared.stop(err);
            break;
        };
        launched += 1;
    };
    var stream_wait_ns: u64 = 0;
    if (input.stream) |stream| {
        shared.mutex.lock();
        while (!stream.nativeComplete() and shared.running()) shared.changed.wait(&shared.mutex);
        shared.mutex.unlock();
        stream_wait_ns = shared.now();
        if (stream.nativeComplete()) {
            root_thread = std.Thread.spawn(.{ .stack_size = coordinator_stack }, RootCheck.run, .{&root_check}) catch null;
            if (root_thread == null) root_check.run();
        }
    }
    for (threads[0..launched]) |thread| thread.join();
    const recursion_wall_ns = shared.now();
    if (root_thread) |thread| thread.join();
    root_joined = true;
    if (input.stream) |stream| if (stream.stopped.load(.acquire)) return stream.fatal orelse error.StreamingRecursionCancelled;
    if (root_check.failure) |err| return err;
    if (shared.fatal) |err| return err;
    if (shared.queue.failure) |failure| return failure.err;
    if (shared.queue.completed != plan.count or shared.queue.active != 0 or shared.queue.live != 1) return error.RecursiveLeafCoverage;
    const final = shared.proofs[plan.root] orelse return error.RecursiveLeafCoverage;
    const info = nodes[plan.root];
    const verify_start = input.timer.read();
    try Outer.requireDigest(final.proof.produced.outputs, info.digest);
    var fresh = try final.proof.verifyFresh(a);
    defer fresh.deinit(a);
    const metadata = root_check.metadata orelse return error.RecursiveRootMetadataMissing;
    const verify_ns = input.timer.read() - verify_start;
    const bytes = try final.proof.serialize(a);
    defer a.free(bytes);
    try @import("publication.zig").write(input.dir, "root.proof", bytes);
    const tree = try treeJson(a, plan, nodes, input.frames);
    defer a.free(tree);
    try @import("publication.zig").write(input.dir, "tree.json", tree);
    const n = input.inventory.workers.len;
    const folds = plan.count - n;
    const report = Report{ .outer_shape = @tagName(Outer.shape()), .fold_arity = plan.arity, .outer_backend = "cuda_trace_only", .assignment_source = "gpu_original_circuit_dag", .gpu_new_leaf_proofs = n - shared.restored_leaves, .gpu_new_fold_proofs = folds - shared.restored_folds, .leaf_proofs = n, .restored_leaves = shared.restored_leaves, .fold_proofs = folds, .restored_folds = shared.restored_folds, .peak_pending_authorities = shared.queue.peak, .retired_preprocessed_bytes = shared.retired_bytes, .root_node = plan.root, .root_digest = info.digest, .root_authority = info.authority, .manifest = metadata.manifest.digest, .graph_ns = shared.graph_ns, .wrap_ns = shared.wrap_ns, .fold_ns = shared.fold_ns, .root_verify_ns = verify_ns, .total_ns = input.timer.read(), .root_proof_bytes = bytes.len };
    const report_bytes = try std.json.Stringify.valueAlloc(a, report, .{ .whitespace = .indent_2 });
    defer a.free(report_bytes);
    try @import("publication.zig").write(input.dir, "report.json", report_bytes);
    // Measured per-lane device-stage occupancy (wall time a lane spends inside
    // the device stage: precommit, authority, device proof). It is an upper
    // bound on kernel busy time; CUDA event spans are logged separately.
    var lane_busy = [_]u64{0} ** 4;
    for (records) |r| if (r.lane) |lane| {
        lane_busy[lane] += r.stamps.device_end - r.stamps.device_start;
    };
    var busy_total: u64 = 0;
    for (lane_busy[0..options.lanes.len]) |b| busy_total += b;
    var last_leaf_end: u64 = 0;
    for (records, 0..) |r, id| if (plan.nodes[id].isLeaf()) {
        last_leaf_end = @max(last_leaf_end, r.stamps.finish_end);
    };
    const stream_report = if (input.stream) |stream| .{ .enabled = true, .prep_during_native = stream.prep_during_native, .native_done_ns = stream.native_done_ns, .admitted_device_overlap = stream.admissionActive(), .leaf_ready_ns = stream.ready_ns[0..input.words.len] } else null;
    const occupancy = @as(f64, @floatFromInt(busy_total)) / @as(f64, @floatFromInt(@max(1, recursion_wall_ns * options.lanes.len)));
    const scheduler = try std.json.Stringify.valueAlloc(a, .{ .schema = 1, .candidate = true, .pipelined = true, .lanes = options.lanes.len, .pool_worker_budget = options.pool_worker_budget, .max_pending_authorities = options.max_pending_authorities, .peak_authority_slots = shared.queue.peak, .host_budget = budget.snapshot() }, .{ .whitespace = .indent_2 });
    defer a.free(scheduler);
    try @import("publication.zig").write(input.dir, "scheduler.json", scheduler);
    const AbsoluteNode = struct { id: usize, stamps: Pipe.AbsoluteStamps };
    const absolute_nodes = try a.alloc(AbsoluteNode, records.len);
    defer a.free(absolute_nodes);
    for (records, absolute_nodes) |record, *absolute| absolute.* = .{ .id = record.id, .stamps = try Pipe.absoluteStamps(record.stamps, shared.origin_ns) };
    const timeline = try std.json.Stringify.valueAlloc(a, .{ .schema = "rv64-om31-pipelined-recursion-timeline/v1", .measured = true, .scope = "nodes.stamps are ns since pipeline origin; nodes_absolute and stream ready/done use input Timer ns (not UTC/Nsight); device stage = precommit+authority+device proof; occupancy is an upper bound on GPU kernel busy", .origin_ns = shared.origin_ns, .clock = .{ .relative = "pipeline_origin", .absolute = @as([]const u8, if (input.stream != null) "Streaming.timer" else "input.timer"), .legacy_missing_stamp = 0, .absolute_missing_stamp = "null", .native_wait_is_wakeup_observation = true }, .nodes_absolute = absolute_nodes, .options = pipe, .lanes = options.lanes.len, .dag_wall_ns = recursion_wall_ns, .concurrent_root_metadata_check_ns = root_check.ns, .root_publication_ns = input.timer.read() - verify_start, .lane_device_stage_ns = lane_busy[0..options.lanes.len], .lane_device_stage_occupancy = occupancy, .peak_leaves_ahead = shared.peak_leaves_ahead, .peak_ready = shared.peak_ready, .policy = @tagName(shared.queue.policy), .stream = stream_report, .device_wait_for_native_ns = stream_wait_ns, .last_leaf_finish_ns = last_leaf_end, .tail_after_last_leaf_ns = recursion_wall_ns -| last_leaf_end, .nodes = records }, .{ .whitespace = .indent_1 });
    defer a.free(timeline);
    try @import("publication.zig").write(input.dir, "pipeline.json", timeline);
    std.log.info("rv64 OM31 pipelined recursion done: dag_wall_ns={d} lane_device_stage_occupancy={d:.3}", .{ recursion_wall_ns, occupancy });
    return report;
}

// ===========================================================================
// sched M6: streaming native -> recursion handoff (STWO_RV64_RECURSION_STREAM,
// default 1; 0 = the M5 sequential handoff). Scheduling only: every leaf graph,
// fold graph and proof is built from exactly the inputs of the M5 path (the
// same requests, stage-one bytes, encoded native proofs, keys and FIXED
// authority), so proof bytes are unchanged. Native coordinator hook:
// gkr_local/coordinator.zig `Stream`.
//   sealed   (produce thread, after the stage-one barrier): inventory, stage
//            views and the manifest are rebuilt here from the sealed bytes,
//            then the recursion coordinator thread starts;
//   done(i)  (stage-two worker thread): leaf i's frame words are derived and
//            the leaf opens for host prep (CPU only, overlapping stage two);
//   nativeDone (after produce, the terminal check and native publication):
//            device lanes and the root metadata check may start.
// ===========================================================================
