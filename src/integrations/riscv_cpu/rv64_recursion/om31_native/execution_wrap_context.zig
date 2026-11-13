//! Plan-bound lane execution and terminal publication ownership.
const std = @import("std");
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const Coordinator = @import("../../word16_global_execution/services/gkr_local/coordinator.zig");
const Execution = @import("../../word16_global_execution/services/gkr_local/execution.zig");
const MW = @import("../../word16_global_execution/services/gkr_local/manifest_wire.zig");
const FixedSet = @import("../../word16_global_execution/services/gkr_local/fixed_authority_set.zig").Set;
const Root = @import("services_root.zig");
const Graph = @import("leaf_graph.zig");
const Outer = @import("outer_wrap.zig");
const Bridge = @import("../om31_outer.zig");
const SharedBudget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Dag = @import("ready_dag.zig");
const Pools = @import("stwo_prover_engine").work_pool;
const ownership_owner = @import("execution_wrap_ownership.zig");
const Pending = ownership_owner.Pending;
const cached = ownership_owner.cached;
const child = ownership_owner.child;
const pipeline_owner = @import("execution_wrap_pipeline.zig");
const runPipelined = pipeline_owner.runPipelined;
const stream_owner = @import("execution_wrap_stream.zig");
const Streaming = stream_owner.Streaming;
const main_owner = @import("execution_wrap.zig");
const Node = main_owner.Node;
const ParallelOptions = main_owner.ParallelOptions;
const Report = main_owner.Report;
const treeJson = main_owner.treeJson;

pub fn requireReceiverTrace(ctx: *const @import("common.zig").Context) !void {
    if (!ctx.trace_only or ctx.value_table.items.len != 0 or ctx.value_table.capacity != 0) return error.RecursiveReceiverWitnessForbidden;
}

pub const PreparedExecution = struct {
    allocator: std.mem.Allocator,
    setups: []const *const R.CpuSetup,
    truths: []const R.Truth,
    bundle: *const Coordinator.Bundle,
    expected: P.Expected,
    config: W.PcsConfig,
    fixed: ?*const FixedSet,
    dir: std.fs.Dir,
    allow_resume: bool,
    inventory: *const Execution.Inventory,
    stages: *const MW.Owned,
    manifest: *const @import("../../word16_global_execution/services/gkr_local/manifest.zig").PendingManifest,
    words: []const []const u32,
    frames: Root.Frames,
    timer: *std.time.Timer,
    existing_only: bool = false,
    /// Sequential planned path only; parallel lanes carry their own factory.
    factory: ?Outer.Device.Factory = null,
    /// sched M6 streaming handoff: leaves open as native workers finish and
    /// device lanes start only after native production (scheduling only).
    stream: ?*Streaming = null,
};
pub const Outcome = struct { pending: Pending, restored: bool, retired_bytes: usize, graph_ns: u64 = 0, proof_ns: u64 = 0, wrap_only_ns: u64 = 0, serialize_ns: u64 = 0, write_ns: u64 = 0 };
pub const ParallelExecution = struct {
    input: PreparedExecution,
    options: ParallelOptions,
    plan: *const Dag.Plan,
    dispatch: Dag.Dispatcher,
    nodes: []Node,
    proofs: [Dag.max_nodes]?Pending = @splat(null),
    graph_ns: u64 = 0,
    wrap_ns: u64 = 0,
    fold_ns: u64 = 0,
    restored_leaves: usize = 0,
    restored_folds: usize = 0,
    retired_bytes: usize = 0,
    pub fn runLane(self: *ParallelExecution, lane: usize) void {
        var binding = Pools.ScopedPoolBinding.init(self.options.lanes[lane].pool) catch |err| {
            self.dispatch.stop(err);
            return;
        };
        defer binding.deinit();
        while (self.dispatch.take() catch return) |id| {
            const taken_ns = std.time.nanoTimestamp();
            const outcome = self.prove(id, self.options.lanes[lane].factory) catch |err| {
                self.dispatch.fail(id, err);
                return;
            };
            var publication = Publication{ .execution = self, .outcome = outcome };
            self.dispatch.publish(id, &publication, Publication.apply);
            // Log-only per-node timeline (absolute CLOCK_REALTIME ns, comparable
            // across lanes and with Nsight Systems); proof bytes are unaffected.
            const spec = self.plan.nodes[id];
            std.debug.print("RECURSION_NODE_TIMELINE node={d} kind={s} first_leaf={d} leaf_count={d} lane={d} device={d} taken_unix_ns={d} graph_ns={d} wrap_ns={d} serialize_ns={d} write_ns={d} published_unix_ns={d} restored={}\n", .{ id, if (spec.isLeaf()) "leaf" else "fold", spec.first_leaf, spec.leaf_count, lane, self.options.lanes[lane].physical_device, taken_ns, outcome.graph_ns, outcome.wrap_only_ns, outcome.serialize_ns, outcome.write_ns, std.time.nanoTimestamp(), outcome.restored });
        }
    }
    const Publication = struct {
        execution: *ParallelExecution,
        outcome: Outcome,
        pub fn apply(raw: *anyopaque, id: usize) void {
            const publication: *@This() = @ptrCast(@alignCast(raw));
            const self = publication.execution;
            const outcome = publication.outcome;
            self.proofs[id] = outcome.pending;
            const spec = self.plan.nodes[id];
            self.nodes[id] = .{ .first_leaf = spec.first_leaf, .leaf_count = spec.leaf_count, .left = spec.left(), .right = spec.right(), .authority = outcome.pending.proof.effectiveIdentity(), .digest = outcome.pending.proof.digest };
            self.retired_bytes += outcome.retired_bytes;
            if (!spec.isLeaf()) {
                for (spec.kids()) |kid| {
                    self.proofs[kid].?.deinit(self.input.allocator);
                    self.proofs[kid] = null;
                }
                self.fold_ns += outcome.graph_ns + outcome.proof_ns;
                self.restored_folds += @intFromBool(outcome.restored);
            } else {
                self.graph_ns += outcome.graph_ns;
                self.wrap_ns += outcome.proof_ns;
                self.restored_leaves += @intFromBool(outcome.restored);
            }
        }
    };
    pub fn prove(self: *ParallelExecution, id: usize, factory: ?Outer.Device.Factory) !Outcome {
        const in = self.input;
        const a = in.allocator;
        const spec = &self.plan.nodes[id];
        // Trace-only graphs for the receiver and the GPU circuit source; the
        // CPU outer prover (no factory) needs the builder assignment.
        const trace_only = in.existing_only or (factory != null and factory.?.prepare_from_circuit != null);
        if (!spec.isLeaf()) {
            var children: [Dag.max_arity]Bridge.Child = undefined;
            for (spec.kids(), 0..) |kid, i| children[i] = child(self.proofs[kid].?);
            const kids = children[0..spec.arity];
            const digest = try Bridge.expectedDigest(kids);
            var timer = try std.time.Timer.start();
            var graph = if (trace_only) try Bridge.buildFoldTraceOnly(a, kids) else try Bridge.buildFold(a, kids);
            defer graph.deinit();
            if (in.existing_only) try requireReceiverTrace(&graph.ctx);
            if (!std.mem.eql(u8, &digest, &graph.output_digest)) return error.RecursiveFoldDigest;
            const graph_ns = timer.lap();
            var name_buffer: [64]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buffer, "fold-{d:0>6}.proof", .{id});
            // Fold v2: topology-only producer caches key by geometry class.
            Outer.Device.class_hint = try Bridge.classKey(kids);
            defer Outer.Device.class_hint = null;
            return self.wrap(a, &graph.ctx, digest, id, name, factory, graph_ns, &timer);
        }
        const ordinal = spec.first_leaf;
        const worker = in.inventory.workers[ordinal];
        var timer = try std.time.Timer.start();
        const build_cpu = if (trace_only) &Graph.cpuTraceOnly else &Graph.cpu;
        const build_truth = if (trace_only) &Graph.truthTraceOnly else &Graph.truth;
        var graph = if (ordinal < in.setups.len) try build_cpu(a, .{ .setup = in.setups[ordinal], .request = in.bundle.requests[ordinal], .expected = worker, .first = in.inventory.first_ids[ordinal], .manifest = in.manifest, .index = ordinal, .stage = &in.stages.stages[ordinal], .config = in.config, .encoded = &in.bundle.cpus[ordinal], .fixed = if (in.fixed) |authority| authority.at(ordinal) else null }) else try build_truth(a, .{ .truth = in.truths[ordinal - in.setups.len], .expected = worker, .manifest = in.manifest, .config = in.config, .encoded = &in.bundle.truths[ordinal - in.setups.len], .fixed = if (in.fixed) |authority| authority.at(ordinal) else null });
        defer graph.deinit();
        if (in.existing_only) try requireReceiverTrace(graph.ctx);
        if (!std.mem.eql(u32, graph.words, in.words[ordinal])) return error.RecursiveLeafFrame;
        const graph_ns = timer.lap();
        var name_buffer: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "leaf-{d:0>6}.proof", .{ordinal});
        return self.wrap(a, graph.ctx, graph.digest, id, name, factory, graph_ns, &timer);
    }
    pub fn wrap(self: *ParallelExecution, a: std.mem.Allocator, ctx: *@import("common.zig").Context, digest: [32]u8, id: usize, name: []const u8, factory: ?Outer.Device.Factory, graph_ns: u64, timer: *std.time.Timer) !Outcome {
        const encoded = try cached(a, self.input.dir, name, self.input.allow_resume);
        if (self.input.existing_only and encoded == null) return error.MissingRecursiveNodeProof;
        defer if (encoded) |bytes| a.free(bytes);
        const proof = try a.create(Outer.Wrapped);
        errdefer a.destroy(proof);
        const wrap_start = timer.read();
        proof.* = try Outer.wrapGraphOrLoadWithFactory(a, ctx, digest, encoded, @intCast(id), factory);
        errdefer proof.deinit();
        const wrapped = timer.read();
        var serialized = wrapped;
        var written = wrapped;
        if (!self.input.existing_only) {
            const bytes = try proof.serialize(a);
            defer a.free(bytes);
            serialized = timer.read();
            try @import("publication.zig").write(self.input.dir, name, bytes);
            written = timer.read();
        }
        return .{ .pending = .{ .proof = proof, .node = id }, .restored = encoded != null, .retired_bytes = proof.retireProverData(), .graph_ns = graph_ns, .proof_ns = timer.read(), .wrap_only_ns = wrapped - wrap_start, .serialize_ns = serialized - wrapped, .write_ns = written - serialized };
    }
};

/// Single-lane plan-driven execution (m3 k-ary trees): producer with an
/// optional factory, or the strict receiver (existing_only). Node IDs are in
/// topological order, so a parent always follows all of its children.
pub fn runPreparedSequential(input: PreparedExecution, arity: usize) !Report {
    const a = input.allocator;
    const plan = try Dag.Plan.initArity(input.inventory.workers.len, arity);
    const nodes = try a.alloc(Node, plan.count);
    defer a.free(nodes);
    var shared = ParallelExecution{ .input = input, .options = .{ .lanes = &.{}, .pool_worker_budget = 0 }, .plan = &plan, .dispatch = .{ .queue = .{ .plan = &plan, .limit = std.math.maxInt(usize) } }, .nodes = nodes };
    defer for (shared.proofs[0..plan.count]) |proof| if (proof) |p| p.deinit(a);
    for (0..plan.count) |id| {
        std.log.info("rv64 OM31 recursion m3 node {d}/{d}: arity={d}", .{ id + 1, plan.count, plan.nodes[id].arity });
        const outcome = try shared.prove(id, input.factory);
        var publication = ParallelExecution.Publication{ .execution = &shared, .outcome = outcome };
        ParallelExecution.Publication.apply(&publication, id);
        shared.dispatch.queue.status[id] = .done;
        shared.dispatch.queue.completed += 1;
    }
    if (input.existing_only and (shared.restored_leaves != input.inventory.workers.len or shared.restored_leaves + shared.restored_folds != plan.count)) return error.RecursiveReceiverMustRestoreAll;
    const backend: []const u8 = if (input.existing_only) "cpu_trace_only_receiver" else if (input.factory != null and input.factory.?.prepare_from_circuit != null) "cuda_trace_only" else if (input.factory != null) "cuda_from_host_assignment" else "cpu";
    return finishPlanned(&shared, &plan, backend, null);
}
pub fn runPreparedParallel(input: PreparedExecution, options: ParallelOptions, pipeline: ?Pipe.Options, arity: usize) !Report {
    const a = input.allocator;
    // The two-stage pipeline (M2a) schedules any plan arity (canon-vk M5):
    // prep/finish/complete iterate the node's ordered kid list.
    const plan = try Dag.Plan.initArity(input.inventory.workers.len, arity);
    const budget = try @import("../../rv64_recursion_budget.zig").require(SharedBudget, a);
    const stack_bytes = 8 << 20;
    const nodes = try a.alloc(Node, plan.count);
    defer a.free(nodes);
    if (pipeline) |pipe| return runPipelined(input, options, pipe, &plan, nodes, budget);
    var shared = ParallelExecution{ .input = input, .options = options, .plan = &plan, .dispatch = .{ .queue = try Dag.Queue.init(&plan, options.lanes.len, options.max_pending_authorities) }, .nodes = nodes };
    defer for (shared.proofs[0..plan.count]) |proof| if (proof) |p| p.deinit(a);
    var threads: [4]std.Thread = undefined;
    var launched: usize = 0;
    // Every started lane joins on every path, including partial spawn failure.
    for (options.lanes, 0..) |_, lane| {
        threads[lane] = std.Thread.spawn(.{ .stack_size = stack_bytes }, ParallelExecution.runLane, .{ &shared, lane }) catch |err| {
            shared.dispatch.stop(err);
            break;
        };
        launched += 1;
    }
    for (threads[0..launched]) |thread| thread.join();
    try shared.dispatch.result();
    return finishPlanned(&shared, &plan, "cuda_trace_only", .{ .options = options, .budget = budget });
}
pub const SchedulerInfo = struct { options: ParallelOptions, budget: *SharedBudget };
/// Root admission and publication shared by the planned paths. Binary trees
/// keep tree.json schema 2 byte for byte; k-ary trees publish schema 3 with
/// ordered child lists.
pub fn finishPlanned(shared: *ParallelExecution, plan: *const Dag.Plan, backend: []const u8, scheduler_info: ?SchedulerInfo) !Report {
    const input = shared.input;
    const a = input.allocator;
    const nodes = shared.nodes;
    const final = shared.proofs[plan.root] orelse return error.RecursiveLeafCoverage;
    const info = nodes[plan.root];
    const verify_start = input.timer.read();
    try Outer.requireDigest(final.proof.produced.outputs, info.digest);
    var fresh = try final.proof.verifyFresh(a);
    defer fresh.deinit(a);
    const metadata = try Root.check(a, input.setups, input.truths, input.bundle.requests, input.expected, input.config, input.fixed, input.bundle.stage_one_bytes, input.frames, .{});
    const verify_ns = input.timer.read() - verify_start;
    const bytes = try final.proof.serialize(a);
    defer a.free(bytes);
    const Pub = @import("publication.zig");
    if (input.existing_only) try Pub.requireBytes(input.dir, "root.proof", bytes) else try Pub.write(input.dir, "root.proof", bytes);
    const tree = try treeJson(a, plan, nodes, input.frames);
    defer a.free(tree);
    if (input.existing_only) try Pub.requireBytes(input.dir, "tree.json", tree) else try Pub.write(input.dir, "tree.json", tree);
    const n = input.inventory.workers.len;
    const folds = plan.count - n;
    const from_gpu = scheduler_info != null or input.factory != null;
    const report = Report{ .outer_shape = @tagName(Outer.shape()), .fold_arity = plan.arity, .outer_backend = backend, .assignment_source = if (input.existing_only) "none_receiver_trace_only" else if (std.mem.eql(u8, backend, "cuda_trace_only")) "gpu_original_circuit_dag" else "cpu_circuit_builder", .gpu_new_leaf_proofs = if (from_gpu) n - shared.restored_leaves else 0, .gpu_new_fold_proofs = if (from_gpu) folds - shared.restored_folds else 0, .leaf_proofs = n, .restored_leaves = shared.restored_leaves, .fold_proofs = folds, .restored_folds = shared.restored_folds, .peak_pending_authorities = shared.dispatch.queue.peak, .retired_preprocessed_bytes = shared.retired_bytes, .root_node = plan.root, .root_digest = info.digest, .root_authority = info.authority, .manifest = metadata.manifest.digest, .graph_ns = shared.graph_ns, .wrap_ns = shared.wrap_ns, .fold_ns = shared.fold_ns, .root_verify_ns = verify_ns, .total_ns = input.timer.read(), .root_proof_bytes = bytes.len };
    if (input.existing_only) return report;
    const report_bytes = try std.json.Stringify.valueAlloc(a, report, .{ .whitespace = .indent_2 });
    defer a.free(report_bytes);
    try Pub.write(input.dir, "report.json", report_bytes);
    const sched = scheduler_info orelse return report;
    const options = sched.options;
    const scheduler = try std.json.Stringify.valueAlloc(a, .{ .schema = 1, .candidate = true, .lanes = options.lanes.len, .pool_worker_budget = options.pool_worker_budget, .max_pending_authorities = options.max_pending_authorities, .peak_authority_slots = shared.dispatch.queue.peak, .host_budget = sched.budget.snapshot() }, .{ .whitespace = .indent_2 });
    defer a.free(scheduler);
    try Pub.write(input.dir, "scheduler.json", scheduler);
    return report;
}

// ===========================================================================
// Two-stage pipelined recursion (M2a). Every node is split into
//   prep   (host pool; no device): leaf/fold graph, exact padding, PP columns,
//          device assignment plan/pack/hash (Factory.prepare_host);
//   device (one lane per physical GPU, one active proof per device): FIXED
//          precommit, authority, staged-plan handoff, device proof;
//   finish (host pool): fresh native verification/capture, durable
//          publication, prover-data retirement, DAG completion.
// Node ids, ordinals, graphs and every proving operation are those of the
// lane path; only the executing thread changes, so proof bytes are identical.
// Device admission is unchanged (a prepared-but-not-running node owns host
// memory only; it holds no device lease until its lane starts it).
// ===========================================================================
pub const Pipe = struct {
    pub const Options = struct {
        host_workers: usize,
        prep_pool_workers: usize,
        /// Leaves taken for prep that have not yet reached a device lane.
        prep_ahead: usize,

        pub fn fromEnv(_: std.mem.Allocator, options: ParallelOptions) !?Options {
            const lanes = options.lanes.len;
            const result = Options{
                .host_workers = 8,
                .prep_pool_workers = 24,
                .prep_ahead = 3 * lanes,
            };
            if (result.host_workers == 0 or result.host_workers > 32 or result.prep_pool_workers == 0 or result.prep_pool_workers > Pools.MAX_WORKERS or result.prep_ahead == 0) return error.InvalidRecursionPipelineOption;
            return result;
        }
    };
    pub const Stamps = struct { taken: u64 = 0, prep_start: u64 = 0, prep_end: u64 = 0, device_start: u64 = 0, device_end: u64 = 0, finish_start: u64 = 0, finish_end: u64 = 0 };
    // Absolute means the input Timer's clock, NOT UTC or Nsight time. Zero
    // remains the legacy missing-stage sentinel; nullable copies prevent a
    // restored node from acquiring a fictitious event at the pipeline origin.
    pub const AbsoluteStamps = struct { taken: ?u64 = null, prep_start: ?u64 = null, prep_end: ?u64 = null, device_start: ?u64 = null, device_end: ?u64 = null, finish_start: ?u64 = null, finish_end: ?u64 = null };
    pub fn absoluteStamps(stamps: Stamps, origin_ns: u64) !AbsoluteStamps {
        var result: AbsoluteStamps = .{};
        inline for (std.meta.fields(Stamps)) |field| {
            const value = @field(stamps, field.name);
            if (value != 0) @field(result, field.name) = try std.math.add(u64, origin_ns, value);
        }
        return result;
    }
    pub const Record = struct {
        id: usize = 0,
        kind: []const u8 = "",
        first_leaf: usize = 0,
        leaf_count: usize = 0,
        lane: ?usize = null,
        restored: bool = false,
        variables: usize = 0,
        stamps: Stamps = .{},
        graph_ns: u64 = 0,
        finalize_ns: u64 = 0,
        columns_ns: u64 = 0,
        host_plan_ns: u64 = 0,
        host_authority_ns: u64 = 0,
        authority_ns: u64 = 0,
        device_prove_ns: u64 = 0,
        verify_ns: u64 = 0,
        publish_ns: u64 = 0,
    };
    pub const Job = struct {
        id: usize,
        leaf: ?Graph.Graph = null,
        fold: ?*Bridge.Graph = null,
        digest: [32]u8 = undefined,
        host: ?Outer.HostPrep = null,
        proved: ?Outer.Proved = null,
        wrapped: ?*Outer.Wrapped = null,
        record: Record = .{},
        pub fn ctx(self: *Job) *@import("common.zig").Context {
            if (self.leaf) |g| return g.ctx;
            return &self.fold.?.ctx;
        }
        pub fn releaseGraph(self: *Job, a: std.mem.Allocator) void {
            if (self.leaf) |*g| g.deinit();
            self.leaf = null;
            if (self.fold) |f| {
                f.deinit();
                a.destroy(f);
            }
            self.fold = null;
        }
        pub fn destroy(self: *Job, a: std.mem.Allocator) void {
            if (self.proved) |*p| p.deinit(a);
            if (self.host) |*h| h.deinit(a);
            if (self.wrapped) |w| {
                w.deinit();
                a.destroy(w);
            }
            self.releaseGraph(a);
            a.destroy(self);
        }
    };
};
