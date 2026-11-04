//! Bounded current-services recursion: O(log workers) live proof authorities.
//! Every cached proof is freshly checked under a key rebuilt from the trusted
//! statement graph. A cache never supplies its own admitted verifier key.
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
const Prove = @import("stwo_circuit_cpu_integration").om31.prove;
const Wire = @import("stwo_circuit_cpu_integration").om31.wire;
pub const Node = struct { first_leaf: usize, leaf_count: usize, left: ?usize, right: ?usize, authority: [32]u8, digest: [32]u8 };
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
};
const Pending = struct {
    proof: *Outer.Wrapped,
    node: usize,
    fn deinit(self: Pending, a: std.mem.Allocator) void {
        self.proof.deinit();
        a.destroy(self.proof);
    }
};
fn child(p: Pending) Bridge.Child {
    return .{ .authority = p.proof.authority, .produced = &p.proof.produced, .capture = &p.proof.capture };
}
fn freeMarginals(a: std.mem.Allocator, values: []const []const O) void {
    for (values) |pair| a.free(pair);
    a.free(values);
}
fn copyMarginals(a: std.mem.Allocator, values: []const []const O) ![]const []const O {
    const out = try a.alloc([]const O, values.len);
    errdefer a.free(out);
    var count: usize = 0;
    errdefer for (out[0..count]) |pair| a.free(pair);
    for (out, values) |*pair, value| {
        pair.* = try a.dupe(O, value);
        count += 1;
    }
    return out;
}
fn cached(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, allow_resume: bool) !?[]u8 {
    if (!allow_resume) return null;
    return dir.readFileAlloc(a, name, Wire.MAX_BYTES) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}
fn save(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, proof: *const Outer.Wrapped) !void {
    const bytes = try proof.serialize(a);
    defer a.free(bytes);
    try dir.writeFile(.{ .sub_path = name, .data = bytes });
}
const Fold = struct { pending: Pending, restored: bool, retired_preprocessed_bytes: usize };
/// Borrows children throughout construction. The caller releases them ONLY
/// after the new parent has a complete proof, fresh capture and durable bytes.
fn combine(a: std.mem.Allocator, left: Pending, right: Pending, nodes: *std.ArrayList(Node), dir: std.fs.Dir, allow_resume: bool, factory: ?Outer.Device.Factory, existing_only: bool) !Fold {
    const l = nodes.items[left.node];
    const r = nodes.items[right.node];
    if (l.first_leaf + l.leaf_count != r.first_leaf) return error.RecursiveLeafAdjacency;
    std.log.info("rv64 OM31 recursion fold: [{d},{d}) + [{d},{d})", .{ l.first_leaf, l.first_leaf + l.leaf_count, r.first_leaf, r.first_leaf + r.leaf_count });
    const children = [2]Bridge.Child{ child(left), child(right) };
    const digest = try Bridge.expectedDigest(children);
    const build_fold = if (existing_only or (factory != null and factory.?.prepare_from_circuit != null)) &Bridge.buildFoldTraceOnly else &Bridge.buildFold;
    var graph = try build_fold(a, children);
    defer graph.deinit();
    if (existing_only) try requireReceiverTrace(&graph.ctx);
    if (!std.mem.eql(u8, &digest, &graph.output_digest)) return error.RecursiveFoldDigest;
    var name_buffer: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buffer, "fold-{d:0>6}.proof", .{nodes.items.len});
    const encoded = try cached(a, dir, name, allow_resume);
    if (existing_only and encoded == null) return error.MissingRecursiveNodeProof;
    defer if (encoded) |bytes| a.free(bytes);
    const proof = try a.create(Outer.Wrapped);
    errdefer a.destroy(proof);
    proof.* = try Outer.wrapGraphOrLoadWithFactory(a, &graph.ctx, digest, encoded, @intCast(nodes.items.len), factory);
    std.log.info("rv64 OM31 recursion fold accepted: preprocess_ns={d} prove_ns={d} restore_ns={d} verify_ns={d}", .{ proof.timings.preprocess_ns, proof.timings.prove_ns, proof.timings.restore_ns, proof.timings.verify_ns });
    errdefer proof.deinit();
    if (!existing_only) try save(a, dir, name, proof);
    const retired_bytes = proof.retireProverData();
    const node = nodes.items.len;
    nodes.appendAssumeCapacity(.{ .first_leaf = l.first_leaf, .leaf_count = l.leaf_count + r.leaf_count, .left = left.node, .right = right.node, .authority = proof.authority.identity, .digest = digest });
    return .{ .pending = .{ .proof = proof, .node = node }, .restored = encoded != null, .retired_preprocessed_bytes = retired_bytes };
}
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
    const padding_targets = Circuit.common.finalize.computePaddedSizes(.fromBuilder(&graph.ctx.circuit));
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
const SharedBudget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
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
    try @import("publication.zig").requireExisting(dir, try Dag.Plan.init(setups.len + truths.len));
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
    // Early rejection only. Acceptance still requires every freshly verified
    // leaf, every parent, the root and this exact metadata check again below.
    const metadata = try Root.check(a, setups, truths, bundle.requests, expected, config, fixed, bundle.stage_one_bytes, frames, .{});
    if (parallel) |options| return runPreparedParallel(.{ .allocator = a, .setups = setups, .truths = truths, .bundle = bundle, .expected = expected, .config = config, .fixed = fixed, .dir = dir, .allow_resume = allow_resume, .inventory = &inventory, .stages = &stages, .manifest = &manifest, .words = words, .frames = frames, .timer = &timer }, options);
    var nodes: std.ArrayList(Node) = .empty;
    defer nodes.deinit(a);
    try nodes.ensureTotalCapacity(a, 2 * n - 1);
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
            if (!existing_only) try save(a, dir, name, proof);
            retired_bytes += proof.retireProverData();
            const node = nodes.items.len;
            nodes.appendAssumeCapacity(.{ .first_leaf = ordinal, .leaf_count = 1, .left = null, .right = null, .authority = proof.authority.identity, .digest = proof.digest });
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
            const parent = try combine(a, left, current.?, &nodes, dir, allow_resume, factory, existing_only);
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
    for (&stack) |*entry| if (entry.*) |left| {
        entry.* = null;
        if (root) |right| {
            // Keep left under explicit local ownership if parent construction fails.
            var owns_left = true;
            defer if (owns_left) left.deinit(a);
            const start = timer.read();
            peak_pending = @max(peak_pending, pending_count + 1);
            const parent = try combine(a, left, right, &nodes, dir, allow_resume, factory, existing_only);
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
    var fresh = try Prove.verify(a, final.proof.authority, final.proof.produced.outputs, final.proof.produced.claims, &final.proof.produced.proof.proof);
    defer fresh.deinit(a);
    _ = try Root.check(a, setups, truths, bundle.requests, expected, config, fixed, bundle.stage_one_bytes, frames, .{});
    const verify_ns = timer.read() - verify_start;
    const bytes = try final.proof.serialize(a);
    defer a.free(bytes);
    if (existing_only) try @import("publication.zig").requireBytes(a, dir, "root.proof", bytes) else try dir.writeFile(.{ .sub_path = "root.proof", .data = bytes });
    const tree = try std.json.Stringify.valueAlloc(a, .{ .schema = 2, .nodes = nodes.items, .root = final.node, .cpu_frames = cpus, .truth_frames = truth_frames }, .{ .whitespace = .indent_2 });
    defer a.free(tree);
    if (existing_only) try @import("publication.zig").requireBytes(a, dir, "tree.json", tree) else try dir.writeFile(.{ .sub_path = "tree.json", .data = tree });
    const trace_only_backend = factory != null and factory.?.prepare_from_circuit != null;
    const report = Report{ .outer_backend = if (existing_only) "cpu_trace_only_receiver" else if (trace_only_backend) "cuda_trace_only" else if (factory != null) "cuda_from_host_assignment" else "cpu", .assignment_source = if (existing_only) "none_receiver_trace_only" else if (trace_only_backend) "gpu_original_circuit_dag" else "cpu_circuit_builder", .gpu_new_leaf_proofs = if (factory != null) n - restored_leaves else 0, .gpu_new_fold_proofs = if (factory != null) n - 1 - restored_folds else 0, .leaf_proofs = n, .restored_leaves = restored_leaves, .fold_proofs = n - 1, .restored_folds = restored_folds, .peak_pending_authorities = peak_pending, .retired_preprocessed_bytes = retired_bytes, .root_node = final.node, .root_digest = info.digest, .root_authority = info.authority, .manifest = metadata.manifest.digest, .graph_ns = graph_ns, .wrap_ns = wrap_ns, .fold_ns = fold_ns, .root_verify_ns = verify_ns, .total_ns = timer.read(), .root_proof_bytes = bytes.len };
    const report_bytes = try std.json.Stringify.valueAlloc(a, report, .{ .whitespace = .indent_2 });
    defer a.free(report_bytes);
    if (!existing_only) try dir.writeFile(.{ .sub_path = "report.json", .data = report_bytes });
    return report;
}

fn requireReceiverTrace(ctx: *const @import("common.zig").Context) !void {
    if (!ctx.trace_only or ctx.value_table.items.len != 0 or ctx.value_table.capacity != 0) return error.RecursiveReceiverWitnessForbidden;
}

const Dag = @import("ready_dag.zig");
const Pools = @import("stwo_prover_engine").work_pool;
const PreparedExecution = struct {
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
};
const Outcome = struct { pending: Pending, restored: bool, retired_bytes: usize, graph_ns: u64 = 0, proof_ns: u64 = 0, wrap_only_ns: u64 = 0, serialize_ns: u64 = 0, write_ns: u64 = 0 };
const ParallelExecution = struct {
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
    fn runLane(self: *ParallelExecution, lane: usize) void {
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
            std.debug.print("RECURSION_NODE_TIMELINE node={d} kind={s} first_leaf={d} leaf_count={d} lane={d} device={d} taken_unix_ns={d} graph_ns={d} wrap_ns={d} serialize_ns={d} write_ns={d} published_unix_ns={d} restored={}\n", .{ id, if (spec.left == null) "leaf" else "fold", spec.first_leaf, spec.leaf_count, lane, self.options.lanes[lane].physical_device, taken_ns, outcome.graph_ns, outcome.wrap_only_ns, outcome.serialize_ns, outcome.write_ns, std.time.nanoTimestamp(), outcome.restored });
        }
    }
    const Publication = struct {
        execution: *ParallelExecution,
        outcome: Outcome,
        fn apply(raw: *anyopaque, id: usize) void {
            const publication: *@This() = @ptrCast(@alignCast(raw));
            const self = publication.execution;
            const outcome = publication.outcome;
            self.proofs[id] = outcome.pending;
            const spec = self.plan.nodes[id];
            self.nodes[id] = .{ .first_leaf = spec.first_leaf, .leaf_count = spec.leaf_count, .left = spec.left, .right = spec.right, .authority = outcome.pending.proof.authority.identity, .digest = outcome.pending.proof.digest };
            self.retired_bytes += outcome.retired_bytes;
            if (spec.left) |left| {
                self.proofs[left].?.deinit(self.input.allocator);
                self.proofs[spec.right.?].?.deinit(self.input.allocator);
                self.proofs[left] = null;
                self.proofs[spec.right.?] = null;
                self.fold_ns += outcome.graph_ns + outcome.proof_ns;
                self.restored_folds += @intFromBool(outcome.restored);
            } else {
                self.graph_ns += outcome.graph_ns;
                self.wrap_ns += outcome.proof_ns;
                self.restored_leaves += @intFromBool(outcome.restored);
            }
        }
    };
    fn prove(self: *ParallelExecution, id: usize, factory: Outer.Device.Factory) !Outcome {
        const in = self.input;
        const a = in.allocator;
        const spec = self.plan.nodes[id];
        if (spec.left) |left_id| {
            const left = self.proofs[left_id].?;
            const right = self.proofs[spec.right.?].?;
            const children = [2]Bridge.Child{ child(left), child(right) };
            const digest = try Bridge.expectedDigest(children);
            var timer = try std.time.Timer.start();
            var graph = try Bridge.buildFoldTraceOnly(a, children);
            defer graph.deinit();
            if (!std.mem.eql(u8, &digest, &graph.output_digest)) return error.RecursiveFoldDigest;
            const graph_ns = timer.lap();
            var name_buffer: [64]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buffer, "fold-{d:0>6}.proof", .{id});
            return self.wrap(a, &graph.ctx, digest, id, name, factory, graph_ns, &timer);
        }
        const ordinal = spec.first_leaf;
        const worker = in.inventory.workers[ordinal];
        var timer = try std.time.Timer.start();
        var graph = if (ordinal < in.setups.len) try Graph.cpuTraceOnly(a, .{ .setup = in.setups[ordinal], .request = in.bundle.requests[ordinal], .expected = worker, .first = in.inventory.first_ids[ordinal], .manifest = in.manifest, .index = ordinal, .stage = &in.stages.stages[ordinal], .config = in.config, .encoded = &in.bundle.cpus[ordinal], .fixed = if (in.fixed) |authority| authority.at(ordinal) else null }) else try Graph.truthTraceOnly(a, .{ .truth = in.truths[ordinal - in.setups.len], .expected = worker, .manifest = in.manifest, .config = in.config, .encoded = &in.bundle.truths[ordinal - in.setups.len], .fixed = if (in.fixed) |authority| authority.at(ordinal) else null });
        defer graph.deinit();
        if (!std.mem.eql(u32, graph.words, in.words[ordinal])) return error.RecursiveLeafFrame;
        const graph_ns = timer.lap();
        var name_buffer: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "leaf-{d:0>6}.proof", .{ordinal});
        return self.wrap(a, graph.ctx, graph.digest, id, name, factory, graph_ns, &timer);
    }
    fn wrap(self: *ParallelExecution, a: std.mem.Allocator, ctx: *@import("common.zig").Context, digest: [32]u8, id: usize, name: []const u8, factory: Outer.Device.Factory, graph_ns: u64, timer: *std.time.Timer) !Outcome {
        const encoded = try cached(a, self.input.dir, name, self.input.allow_resume);
        defer if (encoded) |bytes| a.free(bytes);
        const proof = try a.create(Outer.Wrapped);
        errdefer a.destroy(proof);
        const wrap_start = timer.read();
        proof.* = try Outer.wrapGraphOrLoadWithFactory(a, ctx, digest, encoded, @intCast(id), factory);
        errdefer proof.deinit();
        const wrapped = timer.read();
        const bytes = try proof.serialize(a);
        defer a.free(bytes);
        const serialized = timer.read();
        try @import("publication.zig").write(self.input.dir, name, bytes);
        const written = timer.read();
        return .{ .pending = .{ .proof = proof, .node = id }, .restored = encoded != null, .retired_bytes = proof.retireProverData(), .graph_ns = graph_ns, .proof_ns = timer.read(), .wrap_only_ns = wrapped - wrap_start, .serialize_ns = serialized - wrapped, .write_ns = written - serialized };
    }
};

fn runPreparedParallel(input: PreparedExecution, options: ParallelOptions) !Report {
    const a = input.allocator;
    const plan = try Dag.Plan.init(input.inventory.workers.len);
    const budget = try @import("../../rv64_recursion_budget.zig").require(SharedBudget, a);
    const stack_bytes = 8 << 20;
    const nodes = try a.alloc(Node, plan.count);
    defer a.free(nodes);
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
    const final = shared.proofs[plan.root] orelse return error.RecursiveLeafCoverage;
    const info = nodes[plan.root];
    const verify_start = input.timer.read();
    try Outer.requireDigest(final.proof.produced.outputs, info.digest);
    var fresh = try Prove.verify(a, final.proof.authority, final.proof.produced.outputs, final.proof.produced.claims, &final.proof.produced.proof.proof);
    defer fresh.deinit(a);
    const metadata = try Root.check(a, input.setups, input.truths, input.bundle.requests, input.expected, input.config, input.fixed, input.bundle.stage_one_bytes, input.frames, .{});
    const verify_ns = input.timer.read() - verify_start;
    const bytes = try final.proof.serialize(a);
    defer a.free(bytes);
    try @import("publication.zig").write(input.dir, "root.proof", bytes);
    const tree = try std.json.Stringify.valueAlloc(a, .{ .schema = 2, .nodes = nodes, .root = plan.root, .cpu_frames = input.frames.cpus, .truth_frames = input.frames.truths }, .{ .whitespace = .indent_2 });
    defer a.free(tree);
    try @import("publication.zig").write(input.dir, "tree.json", tree);
    const n = input.inventory.workers.len;
    const report = Report{ .outer_backend = "cuda_trace_only", .assignment_source = "gpu_original_circuit_dag", .gpu_new_leaf_proofs = n - shared.restored_leaves, .gpu_new_fold_proofs = n - 1 - shared.restored_folds, .leaf_proofs = n, .restored_leaves = shared.restored_leaves, .fold_proofs = n - 1, .restored_folds = shared.restored_folds, .peak_pending_authorities = shared.dispatch.queue.peak, .retired_preprocessed_bytes = shared.retired_bytes, .root_node = plan.root, .root_digest = info.digest, .root_authority = info.authority, .manifest = metadata.manifest.digest, .graph_ns = shared.graph_ns, .wrap_ns = shared.wrap_ns, .fold_ns = shared.fold_ns, .root_verify_ns = verify_ns, .total_ns = input.timer.read(), .root_proof_bytes = bytes.len };
    const report_bytes = try std.json.Stringify.valueAlloc(a, report, .{ .whitespace = .indent_2 });
    defer a.free(report_bytes);
    try @import("publication.zig").write(input.dir, "report.json", report_bytes);
    const scheduler = try std.json.Stringify.valueAlloc(a, .{ .schema = 1, .candidate = true, .lanes = options.lanes.len, .pool_worker_budget = options.pool_worker_budget, .max_pending_authorities = options.max_pending_authorities, .peak_authority_slots = shared.dispatch.queue.peak, .host_budget = budget.snapshot() }, .{ .whitespace = .indent_2 });
    defer a.free(scheduler);
    try @import("publication.zig").write(input.dir, "scheduler.json", scheduler);
    return report;
}
