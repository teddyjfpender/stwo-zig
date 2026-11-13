//! Execution recursion orchestration and its stable public statement/report types.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const Coordinator = @import("../../word16_global_execution/services/gkr_local/coordinator.zig");
const Execution = @import("../../word16_global_execution/services/gkr_local/execution.zig");
const MW = @import("../../word16_global_execution/services/gkr_local/manifest_wire.zig");
const FixedSet = @import("../../word16_global_execution/services/gkr_local/fixed_authority_set.zig").Set;
const Root = @import("services_root.zig");
const CpuLeaf = @import("cpu_leaf.zig");
const TruthLeaf = @import("truth_leaf.zig");
const KeccakLeaf = @import("keccak_leaf.zig");
const Graph = @import("leaf_graph.zig");
const Outer = @import("outer_wrap.zig");
const Bridge = @import("../om31_outer.zig");
const FoldTape = @import("fold_tape.zig");
const Prove = @import("stwo_circuit_cpu_integration").om31.prove;
const Wire = @import("stwo_circuit_cpu_integration").om31.wire;
const SharedBudget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Dag = @import("ready_dag.zig");
const Pools = @import("stwo_prover_engine").work_pool;
const ownership_owner = @import("execution_wrap_ownership.zig");
pub const FoldClasses = ownership_owner.FoldClasses;
const Pending = ownership_owner.Pending;
const cached = ownership_owner.cached;
const combine = ownership_owner.combine;
const copyMarginals = ownership_owner.copyMarginals;
const freeMarginals = ownership_owner.freeMarginals;
const save = ownership_owner.save;
const context_owner = @import("execution_wrap_context.zig");
const Pipe = context_owner.Pipe;
const PreparedExecution = context_owner.PreparedExecution;
const requireReceiverTrace = context_owner.requireReceiverTrace;
const runPreparedParallel = context_owner.runPreparedParallel;
const runPreparedSequential = context_owner.runPreparedSequential;
const stream_owner = @import("execution_wrap_stream.zig");
pub const Streaming = stream_owner.Streaming;

pub const Node = struct { first_leaf: usize, leaf_count: usize, left: ?usize, right: ?usize, authority: [32]u8, digest: [32]u8 };
/// tree.json schema 3 (m3 k-ary trees): ordered adjacent children.
pub const WideNode = struct { first_leaf: usize, leaf_count: usize, children: []const usize, authority: [32]u8, digest: [32]u8 };
pub const Report = struct {
    schema: u32 = 2,
    accepted: bool = true,
    outer_backend: []const u8 = "cpu",
    leaf_proofs: usize,
    restored_leaves: usize,
    fold_proofs: usize,
    restored_folds: usize,
    peak_pending_authorities: usize,
    retired_preprocessed_bytes: usize,
    gpu_new_leaf_proofs: usize,
    gpu_new_fold_proofs: usize,
    assignment_source: []const u8 = "cpu_circuit_builder",
    root_node: usize,
    root_digest: [32]u8,
    root_authority: [32]u8,
    manifest: [32]u8,
    native_prove_ns: ?u64 = null,
    graph_ns: u64,
    wrap_ns: u64,
    fold_ns: u64,
    root_verify_ns: u64,
    total_ns: u64,
    root_proof_bytes: usize,
    portable_root_key_admission: bool = false,
    /// Plan arity (r1: 2, m3: 4 unless STWO_RV64_FOLD_ARITY overrides).
    /// Receivers derive the expected fold count from it and the leaf count.
    fold_arity: usize = 2,
    /// Outer padding shape (`outer_wrap.Shape`): exact (M4) or uniform-v1.
    outer_shape: []const u8 = "exact",
};
/// Streaming binary carry is the same ordered pair-fold tree as breadth-first
/// folding with odd promotion. Final blocks combine from the rightmost/smallest
/// block upward; left-associative finalization would produce a different tree.
pub const Lane = struct {
    physical_device: u32,
    factory: Outer.Device.Factory,
    pool: *@import("stwo_prover_engine").work_pool.WorkPool,
};
pub const ParallelOptions = struct {
    lanes: []const Lane,
    /// Sum of caller-owned pool workers; native proving must have drained.
    pool_worker_budget: usize,
    max_pending_authorities: usize = 17,
    /// Optional caller-owned reservation covering these pools' helper stacks.
    /// Must remain live and belong to the same shared host budget for the run.
    pool_stack_reservation: ?*const @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.ExternalReservation = null,
};
/// Selected native leaf capture plus assignment census only. This neither
/// verifies the other PCS proofs nor proves/accepts a recursive execution root.
pub fn inspectLeafSchedule(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, bundle: *const Coordinator.Bundle, expected: P.Expected, config: W.PcsConfig, fixed: ?*const FixedSet, ordinal: usize) !ScheduleInspection {
    var timer = try std.time.Timer.start();
    var inventory = try Execution.Inventory.initWithAuthority(a, setups, truths, bundle.requests, expected, config, fixed);
    defer inventory.deinit();
    if (ordinal >= inventory.workers.len or bundle.cpus.len != setups.len or bundle.truths.len != truths.len) return error.InvalidInspectionOrdinal;
    var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, bundle.stage_one_bytes);
    defer stages.deinit();
    var manifest = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
    defer manifest.deinit(a);
    const admission_ns = timer.lap();
    const worker = inventory.workers[ordinal];
    var graph = if (ordinal < setups.len) try Graph.cpuTraceOnly(a, .{ .setup = setups[ordinal], .request = bundle.requests[ordinal], .expected = worker, .first = inventory.first_ids[ordinal], .manifest = &manifest, .index = ordinal, .stage = &stages.stages[ordinal], .config = config, .encoded = &bundle.cpus[ordinal], .fixed = if (fixed) |authority| authority.at(ordinal) else null }) else try Graph.truthTraceOnly(a, .{ .truth = truths[ordinal - setups.len], .expected = worker, .manifest = &manifest, .config = config, .encoded = &bundle.truths[ordinal - setups.len], .fixed = if (fixed) |authority| authority.at(ordinal) else null });
    defer graph.deinit();
    if (!graph.ctx.trace_only) return error.InspectionRequiresTraceOnlyGraph;
    const native_capture_and_graph_ns = timer.lap();
    const Circuit = @import("stwo_circuit_frontend");
    const pre_padding_variables = graph.ctx.circuit.n_vars;
    const padding_targets = try Outer.paddingTargets(graph.ctx);
    // Match outer_wrap.wrapGraphOrLoadWithFactory BEFORE assignment planning.
    // No PP/Authority commitment or proof construction is needed for a census.
    try Circuit.common.finalize.padToTargets(@import("common.zig").Q, graph.ctx, padding_targets);
    const padding_ns = timer.lap();
    const Schedule = Circuit.builder.witness_plan;
    var metrics: Schedule.BuildMetrics = .{};
    var plan = try Schedule.buildProfiled(a, graph.ctx, &metrics);
    defer plan.deinit();
    const schedule_ns = timer.lap();
    var task_kinds: [9]usize = @splat(0);
    var hint_kinds: [9]usize = @splat(0);
    var permutation_count: usize = 0;
    var max_permutation_inputs: usize = 0;
    var permutation_pair_work: u64 = 0;
    var packed_index_bytes: usize = 0;
    for (plan.tasks) |task| {
        task_kinds[@intFromEnum(task.kind)] += 1;
        if (task.kind == .hint) hint_kinds[@intFromEnum(graph.ctx.witness_metadata.?.origins.items[task.index].kind)] += 1;
        if (task.kind == .permutation) {
            var buf: [6]u32 = undefined;
            const n = Schedule.inputs(graph.ctx, task, &buf).len;
            var outbuf: [4]u32 = undefined;
            const output_count = Schedule.outputs(graph.ctx, task, &outbuf).len;
            packed_index_bytes = try std.math.add(usize, packed_index_bytes, try std.math.mul(usize, try std.math.add(usize, n, output_count), 4));
            permutation_count += 1;
            max_permutation_inputs = @max(max_permutation_inputs, n);
            permutation_pair_work = try std.math.add(u64, permutation_pair_work, try std.math.mul(u64, @intCast(n), @intCast(n)));
        }
    }
    const circuit = &graph.ctx.circuit;
    const original_gate_counts = [_]usize{ circuit.add.items.len, circuit.sub.items.len, circuit.mul.items.len, circuit.pointwise_mul.items.len, circuit.triple_xor.items.len, circuit.m31_to_u32.items.len, circuit.blake_g_gate.items.len, circuit.permutation.len() };
    var skipped_definitions: [8]usize = undefined;
    for (original_gate_counts, task_kinds[0..8], &skipped_definitions) |original, scheduled, *skipped| skipped.* = try std.math.sub(usize, original, scheduled);
    var origin_kinds: [9]usize = @splat(0);
    for (graph.ctx.witness_metadata.?.origins.items) |origin| origin_kinds[@intFromEnum(origin.kind)] += 1;
    const census = try @import("schedule_census.zig").inspect(plan.level_ends, plan.tasks.len);
    return .{ .ordinal = ordinal, .kind = if (ordinal < setups.len) "cpu" else @tagName(std.meta.activeTag(truths[ordinal - setups.len])), .manifest = manifest.digest, .statement = worker.statement, .graph_digest = graph.digest, .variables = graph.ctx.circuit.n_vars, .pre_padding_variables = pre_padding_variables, .padding_targets = padding_targets, .padding_ns = padding_ns, .public_words = graph.words.len, .seed_count = plan.seeds.len, .constant_seed_count = try std.math.sub(usize, plan.seeds.len, origin_kinds[0]), .packed_index_bytes = packed_index_bytes, .census = census, .task_kinds = task_kinds, .hint_kinds = hint_kinds, .original_gate_counts = original_gate_counts, .skipped_computational_definitions = skipped_definitions, .hint_origin_counts = origin_kinds, .equality_constraint_gates = circuit.eq.items.len, .output_constraint_gates = circuit.output.items.len, .qm31_operation_rows = circuit.nQm31OpsRows(), .permutation_count = permutation_count, .max_permutation_inputs = max_permutation_inputs, .permutation_pair_work = permutation_pair_work, .estimated_device_assignment_bytes = try std.math.mul(usize, graph.ctx.circuit.n_vars, 16), .packed_task_bytes = try std.math.mul(usize, plan.tasks.len, 32), .packed_seed_bytes = try std.math.mul(usize, plan.seeds.len, 20), .host_plan_task_bytes = try std.math.mul(usize, plan.tasks.len, @sizeOf(Schedule.Task)), .host_level_end_bytes = try std.math.mul(usize, plan.level_ends.len, @sizeOf(usize)), .build_metrics = metrics, .admission_ns = admission_ns, .native_capture_and_graph_ns = native_capture_and_graph_ns, .schedule_ns = schedule_ns, .census_ns = timer.lap() };
}
pub const ScheduleInspection = struct {
    ordinal: usize,
    kind: []const u8,
    manifest: [32]u8,
    statement: [32]u8,
    graph_digest: [32]u8,
    variables: usize,
    geometry_scope: []const u8 = "after exact original outer padding, before PP/Authority commitments",
    pre_padding_variables: usize,
    padding_targets: @import("stwo_circuit_frontend").common.finalize.ComponentSizes,
    padding_ns: u64,
    public_words: usize,
    seed_count: usize,
    constant_seed_count: usize,
    packed_index_bytes: usize,
    census: @import("schedule_census.zig").Census,
    task_kinds: [9]usize,
    hint_kinds: [9]usize,
    original_gate_counts: [8]usize,
    skipped_computational_definitions: [8]usize,
    hint_origin_counts: [9]usize,
    equality_constraint_gates: usize,
    output_constraint_gates: usize,
    qm31_operation_rows: usize,
    permutation_count: usize,
    max_permutation_inputs: usize,
    permutation_pair_work: u64,
    estimated_device_assignment_bytes: usize,
    packed_task_bytes: usize,
    packed_seed_bytes: usize,
    host_plan_task_bytes: usize,
    host_level_end_bytes: usize,
    build_metrics: @import("stwo_circuit_frontend").builder.witness_plan.BuildMetrics,
    admission_ns: u64,
    native_capture_and_graph_ns: u64,
    schedule_ns: u64,
    census_ns: u64,
};

pub fn run(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, bundle: *const Coordinator.Bundle, expected: P.Expected, config: W.PcsConfig, fixed: ?*const FixedSet, dir: std.fs.Dir, allow_resume: bool, factory: ?Outer.Device.Factory) !Report {
    return runImpl(a, setups, truths, bundle, expected, config, fixed, dir, allow_resume, factory, null, false);
}
/// Explicit candidate route. Hardware admission remains with the caller; every
/// supplied lane must own a distinct physical device and an atomic GPU factory.
/// All graph/proof allocations share this identifiable synchronized budget.
pub fn runWithFactories(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, bundle: *const Coordinator.Bundle, expected: P.Expected, config: W.PcsConfig, fixed: ?*const FixedSet, dir: std.fs.Dir, allow_resume: bool, options: ParallelOptions) !Report {
    const budget = try @import("../../rv64_recursion_budget.zig").require(SharedBudget, a);
    try validateLanes(options);
    _ = budget.retain();
    defer budget.destroy();
    var stacks = try StackReservations.init(a, options);
    defer stacks.deinit();
    return runImpl(a, setups, truths, bundle, expected, config, fixed, dir, allow_resume, null, options, false);
}
/// Reserves existing OS helper stacks as well as newly spawned coordinators.
/// A borrowed caller reservation is validated, never consumed or double charged.
pub const StackReservations = struct {
    coordinators: SharedBudget.ExternalReservation,
    helpers: SharedBudget.ExternalReservation,
    pub fn init(a: std.mem.Allocator, options: ParallelOptions) !StackReservations {
        const budget = try @import("../../rv64_recursion_budget.zig").require(SharedBudget, a);
        var helper_bytes: usize = 0;
        for (options.lanes) |lane| {
            const bytes = try std.math.mul(usize, lane.pool.workerCount() - 1, lane.pool.stackSize());
            helper_bytes = try std.math.add(usize, helper_bytes, bytes);
        }
        var helpers = SharedBudget.ExternalReservation.empty();
        errdefer helpers.deinit();
        if (options.pool_stack_reservation) |existing| {
            try existing.requireOwner(budget.allocator(), existing.bytes);
            if (existing.bytes < helper_bytes) return error.InsufficientRecursionPoolStackReservation;
        } else helpers = try budget.reserveExternal(helper_bytes);
        const coordinators = try budget.reserveExternal(try std.math.mul(usize, options.lanes.len, 8 << 20));
        return .{ .coordinators = coordinators, .helpers = helpers };
    }
    pub fn deinit(self: *StackReservations) void {
        self.helpers.deinit();
        self.coordinators.deinit();
    }
};
/// Independent receiver: every physical leaf and fold must already exist.
/// Builds original trace-only verifier graphs; never computes a prover witness,
/// invokes a factory or rewrites the producer's proof/tree/report artifacts.
pub fn verifyExisting(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, bundle: *const Coordinator.Bundle, expected: P.Expected, config: W.PcsConfig, fixed: ?*const FixedSet, dir: std.fs.Dir) !Report {
    try @import("publication.zig").requireExisting(dir, try Dag.Plan.initArity(setups.len + truths.len, try foldArity()));
    return runImpl(a, setups, truths, bundle, expected, config, fixed, dir, true, null, null, true);
}
pub fn validateLanes(options: ParallelOptions) !void {
    if (options.lanes.len == 0 or options.lanes.len > 4) return error.InvalidRecursionAdmission;
    var identities: [4]Dag.LaneIdentity = undefined;
    for (options.lanes, 0..) |lane, i| {
        if (lane.factory.prepare_from_circuit == null) return error.TraceOnlySourceRequired;
        identities[i] = .{ .device = lane.physical_device, .factory = @intFromPtr(lane.factory.context), .pool = @intFromPtr(lane.pool), .workers = lane.pool.workerCount() };
    }
    try Dag.validateLanes(identities[0..options.lanes.len], options.pool_worker_budget, options.max_pending_authorities);
}
fn runImpl(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, bundle: *const Coordinator.Bundle, expected: P.Expected, config: W.PcsConfig, fixed: ?*const FixedSet, dir: std.fs.Dir, allow_resume: bool, factory: ?Outer.Device.Factory, parallel: ?ParallelOptions, existing_only: bool) !Report {
    var timer = try std.time.Timer.start();
    var inventory = try Execution.Inventory.initWithAuthority(a, setups, truths, bundle.requests, expected, config, fixed);
    defer inventory.deinit();
    var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, bundle.stage_one_bytes);
    defer stages.deinit();
    var manifest = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
    defer manifest.deinit(a);
    const n = inventory.workers.len;
    if (n == 0 or n > 256 or bundle.cpus.len != setups.len or bundle.truths.len != truths.len) return error.ServicesRootRoster;
    if (Outer.hybridProfileActive()) try Outer.requireHybridProofBudget((try Dag.Plan.initArity(n, try foldArity())).count);
    const words = try a.alloc([]const u32, n);
    @memset(words, &.{});
    defer {
        for (words) |value| a.free(value);
        a.free(words);
    }
    const cpus = try a.alloc(Root.CpuFrame, setups.len);
    @memset(cpus, .{ .words = &.{}, .physical_claims = &.{}, .terminal_marginals = &.{} });
    defer {
        for (cpus) |frame| freeMarginals(a, frame.terminal_marginals);
        a.free(cpus);
    }
    for (setups, 0..) |setup, i| {
        const local = manifest.entries[i].local orelse return error.WideCpuLocalRequired;
        words[i] = try CpuLeaf.expectedWords(a, setup, bundle.requests[i], inventory.first_ids[i], inventory.workers[i], manifest.digest, stages.stages[i].main, local.digest, bundle.cpus[i].claims);
        cpus[i] = .{ .words = words[i], .physical_claims = bundle.cpus[i].claims, .terminal_marginals = try copyMarginals(a, local.artifact.claims_to_verify_by_instance) };
    }
    const truth_frames = words[setups.len..];
    for (truths, 0..) |truth, i| {
        const ordinal = setups.len + i;
        const worker = inventory.workers[ordinal];
        const claims = bundle.truths[i].claims;
        if (truth == .keccak) {
            if (claims.len != 5) return error.InvalidWideTruthClaims;
            const public = KeccakLeaf.Public{ .ordinal = worker.ordinal, .statement = worker.statement, .manifest = manifest.digest, .claims = claims[0..5].* };
            words[ordinal] = try a.dupe(u32, &KeccakLeaf.statementWords(truth, public, stages.stages[ordinal].main));
        } else {
            if (claims.len != 1) return error.InvalidWideTruthClaims;
            const public = TruthLeaf.Public{ .ordinal = worker.ordinal, .statement = worker.statement, .manifest = manifest.digest, .claim = claims[0] };
            words[ordinal] = try a.dupe(u32, &TruthLeaf.statementWords(truth, public, stages.stages[ordinal].main));
        }
    }
    const frames = Root.Frames{ .cpus = cpus, .truths = truth_frames };
    // Pipelined route: the identical metadata check runs once on a side thread
    // concurrently with the DAG and must succeed before root publication.
    const arity = try foldArity();
    if (parallel) |options| if (try Pipe.Options.fromEnv(a, options)) |pipe| return runPreparedParallel(.{ .allocator = a, .setups = setups, .truths = truths, .bundle = bundle, .expected = expected, .config = config, .fixed = fixed, .dir = dir, .allow_resume = allow_resume, .inventory = &inventory, .stages = &stages, .manifest = &manifest, .words = words, .frames = frames, .timer = &timer }, options, pipe, arity);
    // Early rejection only. Acceptance still requires every freshly verified
    // leaf, every parent, the root and this exact metadata check again below.
    const metadata = try Root.check(a, setups, truths, bundle.requests, expected, config, fixed, bundle.stage_one_bytes, frames, .{});
    const prepared = PreparedExecution{ .allocator = a, .setups = setups, .truths = truths, .bundle = bundle, .expected = expected, .config = config, .fixed = fixed, .dir = dir, .allow_resume = allow_resume, .inventory = &inventory, .stages = &stages, .manifest = &manifest, .words = words, .frames = frames, .timer = &timer, .existing_only = existing_only, .factory = factory };
    if (parallel) |options| return runPreparedParallel(prepared, options, null, arity);
    // m3 k-ary trees use the plan-driven path; binary r1 keeps the original
    // streaming carry below byte for byte.
    if (arity != 2) return runPreparedSequential(prepared, arity);
    var nodes: std.ArrayList(Node) = .empty;
    defer nodes.deinit(a);
    try nodes.ensureTotalCapacity(a, 2 * n - 1);
    // Declared before `stack`: borrowed fold proofs must deinit first.
    var fold_classes: ?FoldClasses = if (existing_only) FoldClasses.fromEnv(a) else null;
    defer if (fold_classes) |*cache| cache.deinit();
    var stack = [_]?Pending{null} ** 9;
    defer for (stack) |item| if (item) |p| p.deinit(a);
    var graph_ns: u64 = 0;
    var wrap_ns: u64 = 0;
    var fold_ns: u64 = 0;
    var restored_leaves: usize = 0;
    var restored_folds: usize = 0;
    var retired_bytes: usize = 0;
    var pending_count: usize = 0;
    var peak_pending: usize = 0;
    for (inventory.workers, 0..) |worker, ordinal| {
        const graph_start = timer.read();
        std.log.info("rv64 OM31 recursion leaf {d}/{d}: admitted graph", .{ ordinal + 1, n });
        const trace_only = existing_only or (factory != null and factory.?.prepare_from_circuit != null);
        const build_cpu = if (trace_only) &Graph.cpuTraceOnly else &Graph.cpu;
        const build_truth = if (trace_only) &Graph.truthTraceOnly else &Graph.truth;
        var graph = if (ordinal < setups.len) try build_cpu(a, .{ .setup = setups[ordinal], .request = bundle.requests[ordinal], .expected = worker, .first = inventory.first_ids[ordinal], .manifest = &manifest, .index = ordinal, .stage = &stages.stages[ordinal], .config = config, .encoded = &bundle.cpus[ordinal], .fixed = if (fixed) |authority| authority.at(ordinal) else null }) else try build_truth(a, .{ .truth = truths[ordinal - setups.len], .expected = worker, .manifest = &manifest, .config = config, .encoded = &bundle.truths[ordinal - setups.len], .fixed = if (fixed) |authority| authority.at(ordinal) else null });
        var graph_live = true;
        defer if (graph_live) graph.deinit();
        if (existing_only) try requireReceiverTrace(graph.ctx);
        if (!std.mem.eql(u32, graph.words, words[ordinal])) return error.RecursiveLeafFrame;
        graph_ns += timer.read() - graph_start;
        var name_buffer: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "leaf-{d:0>6}.proof", .{ordinal});
        const encoded = try cached(a, dir, name, allow_resume);
        if (existing_only and encoded == null) return error.MissingRecursiveNodeProof;
        defer if (encoded) |bytes| a.free(bytes);
        const wrap_start = timer.read();
        std.log.info("rv64 OM31 recursion leaf {d}/{d}: {s} outer (vars={d})", .{ ordinal + 1, n, if (encoded != null) "freshly verify cached" else "prove", graph.ctx.circuit.n_vars });
        var current: ?Pending = blk: {
            const proof = try a.create(Outer.Wrapped);
            errdefer a.destroy(proof);
            proof.* = try Outer.wrapGraphOrLoadWithFactory(a, graph.ctx, graph.digest, encoded, @intCast(nodes.items.len), factory);
            std.log.info("rv64 OM31 recursion leaf {d}/{d} accepted: preprocess_ns={d} prove_ns={d} restore_ns={d} verify_ns={d}", .{ ordinal + 1, n, proof.timings.preprocess_ns, proof.timings.prove_ns, proof.timings.restore_ns, proof.timings.verify_ns });
            errdefer proof.deinit();
            // rootverify derive hook (no-op unless derive-vk-tables runs).
            @import("../root_verify.zig").recordLeaf(ordinal, proof.authority, graph.digest);
            if (!existing_only) try save(a, dir, name, proof);
            retired_bytes += proof.retireProverData();
            const node = nodes.items.len;
            nodes.appendAssumeCapacity(.{ .first_leaf = ordinal, .leaf_count = 1, .left = null, .right = null, .authority = proof.effectiveIdentity(), .digest = proof.digest });
            break :blk .{ .proof = proof, .node = node };
        };
        defer if (current) |p| p.deinit(a);
        restored_leaves += @intFromBool(encoded != null);
        wrap_ns += timer.read() - wrap_start;
        pending_count += 1;
        peak_pending = @max(peak_pending, pending_count);
        // Release graph's wide assignment before constructing any fold graph.
        graph.deinit();
        graph_live = false;
        var level: usize = 0;
        while (stack[level]) |left| : (level += 1) {
            const start = timer.read();
            peak_pending = @max(peak_pending, pending_count + 1);
            const parent = try combine(a, left, current.?, &nodes, dir, allow_resume, factory, existing_only, if (fold_classes) |*cache| cache else null);
            fold_ns += timer.read() - start;
            restored_folds += @intFromBool(parent.restored);
            retired_bytes += parent.retired_preprocessed_bytes;
            stack[level] = null;
            left.deinit(a);
            current.?.deinit(a);
            current = parent.pending;
            pending_count -= 1;
        }
        stack[level] = current;
        current = null;
    }
    var root: ?Pending = null;
    defer if (root) |p| p.deinit(a);
    defer if (fold_classes) |cache| std.debug.print("FOLD_CLASS_CACHE hits={d} misses={d} checked={d} classes={d}\n", .{ cache.hits, cache.misses, cache.checked, cache.entries.items.len });
    for (&stack) |*entry| if (entry.*) |left| {
        entry.* = null;
        if (root) |right| {
            // Keep left under explicit local ownership if parent construction fails.
            var owns_left = true;
            defer if (owns_left) left.deinit(a);
            const start = timer.read();
            peak_pending = @max(peak_pending, pending_count + 1);
            const parent = try combine(a, left, right, &nodes, dir, allow_resume, factory, existing_only, if (fold_classes) |*cache| cache else null);
            fold_ns += timer.read() - start;
            restored_folds += @intFromBool(parent.restored);
            retired_bytes += parent.retired_preprocessed_bytes;
            left.deinit(a);
            owns_left = false;
            right.deinit(a);
            root = parent.pending;
            pending_count -= 1;
        } else root = left;
    };
    const final = root orelse return error.RecursiveLeafCoverage;
    const info = nodes.items[final.node];
    if (info.first_leaf != 0 or info.leaf_count != n or nodes.items.len != 2 * n - 1) return error.RecursiveLeafCoverage;
    if (existing_only and (restored_leaves != n or restored_folds != n - 1)) return error.RecursiveReceiverMustRestoreAll;
    const verify_start = timer.read();
    try Outer.requireDigest(final.proof.produced.outputs, info.digest);
    var fresh = try final.proof.verifyFresh(a);
    defer fresh.deinit(a);
    _ = try Root.check(a, setups, truths, bundle.requests, expected, config, fixed, bundle.stage_one_bytes, frames, .{});
    const verify_ns = timer.read() - verify_start;
    const bytes = try final.proof.serialize(a);
    defer a.free(bytes);
    if (existing_only) try @import("publication.zig").requireBytes(dir, "root.proof", bytes) else try dir.writeFile(.{ .sub_path = "root.proof", .data = bytes });
    const tree = try std.json.Stringify.valueAlloc(a, .{ .schema = 2, .nodes = nodes.items, .root = final.node, .cpu_frames = cpus, .truth_frames = truth_frames }, .{ .whitespace = .indent_2 });
    defer a.free(tree);
    if (existing_only) try @import("publication.zig").requireBytes(dir, "tree.json", tree) else try dir.writeFile(.{ .sub_path = "tree.json", .data = tree });
    const trace_only_backend = factory != null and factory.?.prepare_from_circuit != null;
    const report = Report{ .outer_shape = @tagName(Outer.shape()), .outer_backend = if (existing_only) "cpu_trace_only_receiver" else if (trace_only_backend) "cuda_trace_only" else if (factory != null) "cuda_from_host_assignment" else "cpu", .assignment_source = if (existing_only) "none_receiver_trace_only" else if (trace_only_backend) "gpu_original_circuit_dag" else "cpu_circuit_builder", .gpu_new_leaf_proofs = if (factory != null) n - restored_leaves else 0, .gpu_new_fold_proofs = if (factory != null) n - 1 - restored_folds else 0, .leaf_proofs = n, .restored_leaves = restored_leaves, .fold_proofs = n - 1, .restored_folds = restored_folds, .peak_pending_authorities = peak_pending, .retired_preprocessed_bytes = retired_bytes, .root_node = final.node, .root_digest = info.digest, .root_authority = info.authority, .manifest = metadata.manifest.digest, .graph_ns = graph_ns, .wrap_ns = wrap_ns, .fold_ns = fold_ns, .root_verify_ns = verify_ns, .total_ns = timer.read(), .root_proof_bytes = bytes.len };
    const report_bytes = try std.json.Stringify.valueAlloc(a, report, .{ .whitespace = .indent_2 });
    defer a.free(report_bytes);
    if (!existing_only) try dir.writeFile(.{ .sub_path = "report.json", .data = report_bytes });
    return report;
}

/// Blowup-2 outer profiles (r1 and its canonical form) fold binary (accepted
/// bytes); every larger-blowup (m3) outer profile folds 4-ary. A profile with
/// a required arity (M6 diet `m6_outer_diet_k3_*`: 3) fixes it: an
/// STWO_RV64_FOLD_ARITY that names another arity fails closed, on the producer
/// and on the receiver alike.
pub fn foldArity() !usize {
    const profile = @import("stwo_circuit_cpu_integration").om31.protocol.active();
    if (profile.requiredFoldArity()) |required| {
        if (try Dag.policyArity(required) != required) return error.Om31ProfileFoldArityMismatch;
        return required;
    }
    return Dag.policyArity(if (profile.config().fri_config.log_blowup_factor == 1) 2 else 4);
}
/// Process-entry policy check (driver and receiver): every recursion policy
/// env value parses, or the process exits with a clean error (corpus P03).
pub fn checkPolicyEnv() !void {
    _ = try @import("stwo_circuit_cpu_integration").om31.protocol.checkEnv();
    _ = try Outer.checkShapeEnv();
    _ = try foldArity();
}
/// tree.json for every planned route. Binary trees keep schema 2 byte for
/// byte; k-ary trees publish schema 3 with ordered child lists, the arity and
/// the outer profile name.
pub fn treeJson(a: std.mem.Allocator, plan: *const Dag.Plan, nodes: []const Node, frames: Root.Frames) ![]u8 {
    if (plan.arity == 2) return std.json.Stringify.valueAlloc(a, .{ .schema = 2, .nodes = nodes, .root = plan.root, .cpu_frames = frames.cpus, .truth_frames = frames.truths }, .{ .whitespace = .indent_2 });
    const wide = try a.alloc(WideNode, plan.count);
    defer a.free(wide);
    for (wide, nodes, plan.nodes[0..plan.count]) |*out, node, *spec| out.* = .{ .first_leaf = node.first_leaf, .leaf_count = node.leaf_count, .children = spec.kids(), .authority = node.authority, .digest = node.digest };
    return std.json.Stringify.valueAlloc(a, .{ .schema = 3, .fold_arity = plan.arity, .outer_profile = @import("stwo_circuit_cpu_integration").om31.protocol.active().name(), .nodes = wide, .root = plan.root, .cpu_frames = frames.cpus, .truth_frames = frames.truths }, .{ .whitespace = .indent_2 });
}
