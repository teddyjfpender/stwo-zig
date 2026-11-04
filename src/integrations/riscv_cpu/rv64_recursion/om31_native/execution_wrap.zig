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
/// Receiver-only, in-process fold v2 class authorities. Each entry was built by
/// THIS process from an honest trace-only fold graph; a later fold of the same
/// geometry class (Bridge.classKey) reuses its retired PP + verifier Authority
/// and skips graph/PP/FIXED construction. Never persisted, never producer-fed.
/// STWO_RV64_FOLD_CLASS_CACHE=0 disables; =check rebuilds and compares.
pub const FoldClasses = struct {
    const PPT = @import("stwo_circuit_frontend").common.preprocessed.PreprocessedCircuit;
    const Entry = struct { key: [32]u8, pp: *PPT, authority: *Prove.Authority };
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    check: bool = false,
    hits: usize = 0,
    misses: usize = 0,
    checked: usize = 0,
    pub fn fromEnv(a: std.mem.Allocator) ?FoldClasses {
        const value = std.posix.getenv("STWO_RV64_FOLD_CLASS_CACHE") orelse "1";
        if (std.mem.eql(u8, value, "0")) return null;
        return .{ .allocator = a, .check = std.mem.eql(u8, value, "check") };
    }
    pub fn deinit(self: *FoldClasses) void {
        for (self.entries.items) |entry| {
            entry.authority.deinit();
            self.allocator.destroy(entry.authority);
            entry.pp.deinit(self.allocator);
            self.allocator.destroy(entry.pp);
        }
        self.entries.deinit(self.allocator);
    }
    fn find(self: *const FoldClasses, key: [32]u8) ?Entry {
        for (self.entries.items) |entry| if (std.mem.eql(u8, &entry.key, &key)) return entry;
        return null;
    }
    /// Takes ownership of a freshly verified, retired fold's PP/Authority.
    fn adopt(self: *FoldClasses, key: [32]u8, proof: *Outer.Wrapped) !void {
        if (proof.borrowed or !proof.authority.retired) return error.FoldClassAdoptRequiresRetiredOwner;
        try self.entries.append(self.allocator, .{ .key = key, .pp = proof.pp, .authority = proof.authority });
        proof.borrowed = true;
    }
};
/// Borrows children throughout construction. The caller releases them ONLY
/// after the new parent has a complete proof, fresh capture and durable bytes.
fn combine(a: std.mem.Allocator, left: Pending, right: Pending, nodes: *std.ArrayList(Node), dir: std.fs.Dir, allow_resume: bool, factory: ?Outer.Device.Factory, existing_only: bool, classes: ?*FoldClasses) !Fold {
    const l = nodes.items[left.node];
    const r = nodes.items[right.node];
    if (l.first_leaf + l.leaf_count != r.first_leaf) return error.RecursiveLeafAdjacency;
    std.log.info("rv64 OM31 recursion fold: [{d},{d}) + [{d},{d})", .{ l.first_leaf, l.first_leaf + l.leaf_count, r.first_leaf, r.first_leaf + r.leaf_count });
    const children = [2]Bridge.Child{ child(left), child(right) };
    const digest = try Bridge.expectedDigest(&children);
    const class_key = try Bridge.classKey(&children);
    const hit: ?FoldClasses.Entry = if (!existing_only) null else if (classes) |cache| cache.find(class_key) else null;
    if (hit) |entry| if (!classes.?.check) {
        var timer = try std.time.Timer.start();
        var name_buffer: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "fold-{d:0>6}.proof", .{nodes.items.len});
        const encoded = (try cached(a, dir, name, allow_resume)) orelse return error.MissingRecursiveNodeProof;
        defer a.free(encoded);
        const proof = try a.create(Outer.Wrapped);
        errdefer a.destroy(proof);
        proof.* = try Outer.restoreWithAuthority(a, entry.pp, entry.authority, digest, encoded);
        classes.?.hits += 1;
        std.log.info("rv64 OM31 recursion fold accepted (class cache hit): class={x} restore_ns={d} verify_ns={d} total_ns={d}", .{ class_key[0..8], proof.timings.restore_ns, proof.timings.verify_ns, timer.read() });
        const node = nodes.items.len;
        nodes.appendAssumeCapacity(.{ .first_leaf = l.first_leaf, .leaf_count = l.leaf_count + r.leaf_count, .left = left.node, .right = right.node, .authority = proof.authority.identity, .digest = digest });
        return .{ .pending = .{ .proof = proof, .node = node }, .restored = true, .retired_preprocessed_bytes = 0 };
    };
    const build_fold = if (existing_only or (factory != null and factory.?.prepare_from_circuit != null)) &Bridge.buildFoldTraceOnly else &Bridge.buildFold;
    var graph = try build_fold(a, &children);
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
    if (hit) |entry| {
        // check mode: the class authority must equal the freshly rebuilt one.
        if (!std.mem.eql(u8, &entry.authority.identity, &proof.authority.identity)) return error.FoldClassAuthorityMismatch;
        classes.?.checked += 1;
        std.log.info("rv64 OM31 recursion fold class check ok: class={x}", .{class_key[0..8]});
    } else if (existing_only) if (classes) |cache| {
        try cache.adopt(class_key, proof);
        cache.misses += 1;
        std.log.info("rv64 OM31 recursion fold class adopted: class={x} identity={x}", .{ class_key[0..8], proof.authority.identity[0..8] });
    };
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
    const report = Report{ .outer_shape = @tagName(Outer.shape()), .outer_backend = if (existing_only) "cpu_trace_only_receiver" else if (trace_only_backend) "cuda_trace_only" else if (factory != null) "cuda_from_host_assignment" else "cpu", .assignment_source = if (existing_only) "none_receiver_trace_only" else if (trace_only_backend) "gpu_original_circuit_dag" else "cpu_circuit_builder", .gpu_new_leaf_proofs = if (factory != null) n - restored_leaves else 0, .gpu_new_fold_proofs = if (factory != null) n - 1 - restored_folds else 0, .leaf_proofs = n, .restored_leaves = restored_leaves, .fold_proofs = n - 1, .restored_folds = restored_folds, .peak_pending_authorities = peak_pending, .retired_preprocessed_bytes = retired_bytes, .root_node = final.node, .root_digest = info.digest, .root_authority = info.authority, .manifest = metadata.manifest.digest, .graph_ns = graph_ns, .wrap_ns = wrap_ns, .fold_ns = fold_ns, .root_verify_ns = verify_ns, .total_ns = timer.read(), .root_proof_bytes = bytes.len };
    const report_bytes = try std.json.Stringify.valueAlloc(a, report, .{ .whitespace = .indent_2 });
    defer a.free(report_bytes);
    if (!existing_only) try dir.writeFile(.{ .sub_path = "report.json", .data = report_bytes });
    return report;
}

fn requireReceiverTrace(ctx: *const @import("common.zig").Context) !void {
    if (!ctx.trace_only or ctx.value_table.items.len != 0 or ctx.value_table.capacity != 0) return error.RecursiveReceiverWitnessForbidden;
}

const Dag = @import("ready_dag.zig");
/// Blowup-2 outer profiles (r1 and its canonical form) fold binary (accepted
/// bytes); every larger-blowup (m3) outer profile folds 4-ary.
pub fn foldArity() !usize {
    const profile = @import("stwo_circuit_cpu_integration").om31.protocol.active();
    return Dag.policyArity(if (profile.config().fri_config.log_blowup_factor == 1) 2 else 4);
}
/// Process-entry policy check (driver and receiver): every recursion policy
/// env value parses, or the process exits with a clean error (corpus P03).
pub fn checkPolicyEnv() !void {
    _ = try @import("stwo_circuit_cpu_integration").om31.protocol.checkEnv();
    _ = try Outer.checkShapeEnv();
    _ = try foldArity();
}
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
    existing_only: bool = false,
    /// Sequential planned path only; parallel lanes carry their own factory.
    factory: ?Outer.Device.Factory = null,
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
            std.debug.print("RECURSION_NODE_TIMELINE node={d} kind={s} first_leaf={d} leaf_count={d} lane={d} device={d} taken_unix_ns={d} graph_ns={d} wrap_ns={d} serialize_ns={d} write_ns={d} published_unix_ns={d} restored={}\n", .{ id, if (spec.isLeaf()) "leaf" else "fold", spec.first_leaf, spec.leaf_count, lane, self.options.lanes[lane].physical_device, taken_ns, outcome.graph_ns, outcome.wrap_only_ns, outcome.serialize_ns, outcome.write_ns, std.time.nanoTimestamp(), outcome.restored });
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
            self.nodes[id] = .{ .first_leaf = spec.first_leaf, .leaf_count = spec.leaf_count, .left = spec.left(), .right = spec.right(), .authority = outcome.pending.proof.authority.identity, .digest = outcome.pending.proof.digest };
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
    fn prove(self: *ParallelExecution, id: usize, factory: ?Outer.Device.Factory) !Outcome {
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
    fn wrap(self: *ParallelExecution, a: std.mem.Allocator, ctx: *@import("common.zig").Context, digest: [32]u8, id: usize, name: []const u8, factory: ?Outer.Device.Factory, graph_ns: u64, timer: *std.time.Timer) !Outcome {
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
fn runPreparedSequential(input: PreparedExecution, arity: usize) !Report {
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
fn runPreparedParallel(input: PreparedExecution, options: ParallelOptions, pipeline: ?Pipe.Options, arity: usize) !Report {
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
const SchedulerInfo = struct { options: ParallelOptions, budget: *SharedBudget };
/// tree.json for every planned route. Binary trees keep schema 2 byte for
/// byte; k-ary trees publish schema 3 with ordered child lists, the arity and
/// the outer profile name.
fn treeJson(a: std.mem.Allocator, plan: *const Dag.Plan, nodes: []const Node, frames: Root.Frames) ![]u8 {
    if (plan.arity == 2) return std.json.Stringify.valueAlloc(a, .{ .schema = 2, .nodes = nodes, .root = plan.root, .cpu_frames = frames.cpus, .truth_frames = frames.truths }, .{ .whitespace = .indent_2 });
    const wide = try a.alloc(WideNode, plan.count);
    defer a.free(wide);
    for (wide, nodes, plan.nodes[0..plan.count]) |*out, node, *spec| out.* = .{ .first_leaf = node.first_leaf, .leaf_count = node.leaf_count, .children = spec.kids(), .authority = node.authority, .digest = node.digest };
    return std.json.Stringify.valueAlloc(a, .{ .schema = 3, .fold_arity = plan.arity, .outer_profile = @import("stwo_circuit_cpu_integration").om31.protocol.active().name(), .nodes = wide, .root = plan.root, .cpu_frames = frames.cpus, .truth_frames = frames.truths }, .{ .whitespace = .indent_2 });
}
/// Root admission and publication shared by the planned paths. Binary trees
/// keep tree.json schema 2 byte for byte; k-ary trees publish schema 3 with
/// ordered child lists.
fn finishPlanned(shared: *ParallelExecution, plan: *const Dag.Plan, backend: []const u8, scheduler_info: ?SchedulerInfo) !Report {
    const input = shared.input;
    const a = input.allocator;
    const nodes = shared.nodes;
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
    const Pub = @import("publication.zig");
    if (input.existing_only) try Pub.requireBytes(a, input.dir, "root.proof", bytes) else try Pub.write(input.dir, "root.proof", bytes);
    const tree = try treeJson(a, plan, nodes, input.frames);
    defer a.free(tree);
    if (input.existing_only) try Pub.requireBytes(a, input.dir, "tree.json", tree) else try Pub.write(input.dir, "tree.json", tree);
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
const Pipe = struct {
    pub const Options = struct {
        host_workers: usize,
        prep_pool_workers: usize,
        /// Leaves taken for prep that have not yet reached a device lane.
        prep_ahead: usize,
        fn envUsize(a: std.mem.Allocator, name: []const u8, default: usize) !usize {
            const text = std.process.getEnvVarOwned(a, name) catch |err| switch (err) {
                error.EnvironmentVariableNotFound => return default,
                else => return err,
            };
            defer a.free(text);
            return std.fmt.parseUnsigned(usize, text, 10) catch error.InvalidRecursionPipelineOption;
        }
        /// STWO_RV64_RECURSION_PIPELINE=0 selects the original lane path.
        pub fn fromEnv(a: std.mem.Allocator, options: ParallelOptions) !?Options {
            if (try envUsize(a, "STWO_RV64_RECURSION_PIPELINE", 1) == 0) return null;
            const lanes = options.lanes.len;
            const result = Options{
                .host_workers = try envUsize(a, "STWO_RV64_RECURSION_HOST_WORKERS", 8),
                .prep_pool_workers = try envUsize(a, "STWO_RV64_RECURSION_PREP_POOL_WORKERS", 24),
                .prep_ahead = try envUsize(a, "STWO_RV64_RECURSION_PREP_AHEAD", 3 * lanes),
            };
            if (result.host_workers == 0 or result.host_workers > 32 or result.prep_pool_workers == 0 or result.prep_pool_workers > Pools.MAX_WORKERS or result.prep_ahead == 0) return error.InvalidRecursionPipelineOption;
            return result;
        }
    };
    const Stamps = struct { taken: u64 = 0, prep_start: u64 = 0, prep_end: u64 = 0, device_start: u64 = 0, device_end: u64 = 0, finish_start: u64 = 0, finish_end: u64 = 0 };
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
    const Job = struct {
        id: usize,
        leaf: ?Graph.Graph = null,
        fold: ?*Bridge.Graph = null,
        digest: [32]u8 = undefined,
        host: ?Outer.HostPrep = null,
        proved: ?Outer.Proved = null,
        wrapped: ?*Outer.Wrapped = null,
        record: Record = .{},
        fn ctx(self: *Job) *@import("common.zig").Context {
            if (self.leaf) |g| return g.ctx;
            return &self.fold.?.ctx;
        }
        fn releaseGraph(self: *Job, a: std.mem.Allocator) void {
            if (self.leaf) |*g| g.deinit();
            self.leaf = null;
            if (self.fold) |f| {
                f.deinit();
                a.destroy(f);
            }
            self.fold = null;
        }
        fn destroy(self: *Job, a: std.mem.Allocator) void {
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
const Pipelined = struct {
    input: PreparedExecution,
    options: ParallelOptions,
    pipe: Pipe.Options,
    plan: *const Dag.Plan,
    queue: Dag.Queue,
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
    peak_leaves_ahead: usize = 0,
    peak_ready: usize = 0,
    origin_ns: u64,
    graph_ns: u64 = 0,
    wrap_ns: u64 = 0,
    fold_ns: u64 = 0,
    restored_leaves: usize = 0,
    restored_folds: usize = 0,
    retired_bytes: usize = 0,
    fn now(self: *Pipelined) u64 {
        return self.input.timer.read() - self.origin_ns;
    }
    fn running(self: *const Pipelined) bool {
        return self.fatal == null and self.queue.failure == null and self.queue.completed < self.plan.count;
    }
    fn stop(self: *Pipelined, err: anyerror) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.fatal == null) self.fatal = err;
        self.changed.broadcast();
    }
    /// Caller holds the mutex.
    fn failLocked(self: *Pipelined, job: *Pipe.Job, err: anyerror) void {
        std.log.err("rv64 OM31 pipelined recursion node {d} failed: {s}", .{ job.id, @errorName(err) });
        self.queue.fail(job.id, err);
        self.changed.broadcast();
    }
    fn hostWorker(self: *Pipelined) void {
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
            const leaves = self.leaves_ahead < self.pipe.prep_ahead;
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
                    self.peak_leaves_ahead = @max(self.peak_leaves_ahead, self.leaves_ahead);
                }
                const taken = self.now();
                self.mutex.unlock();
                const job = a.create(Pipe.Job) catch |err| {
                    self.mutex.lock();
                    if (spec.isLeaf()) self.leaves_ahead -= 1;
                    self.queue.fail(id, err);
                    self.changed.broadcast();
                    continue;
                };
                job.* = .{ .id = id, .record = .{ .id = id, .kind = if (spec.isLeaf()) "leaf" else "fold", .first_leaf = spec.first_leaf, .leaf_count = spec.leaf_count, .stamps = .{ .taken = taken } } };
                const prepared = self.prep(job, children);
                self.mutex.lock();
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
    fn prep(self: *Pipelined, job: *Pipe.Job, children: ?[]const Pending) !bool {
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
            const fold = try a.create(Bridge.Graph);
            fold.* = Bridge.buildFoldTraceOnly(a, kids) catch |err| {
                a.destroy(fold);
                return err;
            };
            job.fold = fold;
            if (!std.mem.eql(u8, &job.digest, &fold.output_digest)) return error.RecursiveFoldDigest;
            break :blk try std.fmt.bufPrint(&name_buffer, "fold-{d:0>6}.proof", .{job.id});
        } else blk: {
            const ordinal = self.plan.nodes[job.id].first_leaf;
            const worker = in.inventory.workers[ordinal];
            job.leaf = if (ordinal < in.setups.len) try Graph.cpuTraceOnly(a, .{ .setup = in.setups[ordinal], .request = in.bundle.requests[ordinal], .expected = worker, .first = in.inventory.first_ids[ordinal], .manifest = in.manifest, .index = ordinal, .stage = &in.stages.stages[ordinal], .config = in.config, .encoded = &in.bundle.cpus[ordinal], .fixed = if (in.fixed) |authority| authority.at(ordinal) else null }) else try Graph.truthTraceOnly(a, .{ .truth = in.truths[ordinal - in.setups.len], .expected = worker, .manifest = in.manifest, .config = in.config, .encoded = &in.bundle.truths[ordinal - in.setups.len], .fixed = if (in.fixed) |authority| authority.at(ordinal) else null });
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
        if (children != null) Outer.Device.class_hint = try Bridge.classKey(kids);
        defer Outer.Device.class_hint = null;
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
    fn deviceLane(self: *Pipelined, lane: usize) void {
        var binding = Pools.ScopedPoolBinding.init(self.options.lanes[lane].pool) catch |err| return self.stop(err);
        defer binding.deinit();
        const a = self.input.allocator;
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.running()) {
            if (self.ready.items.len == 0) {
                self.changed.wait(&self.mutex);
                continue;
            }
            // Critical path first: the widest (highest) parent, then the
            // lowest leaf id, matching the lane path's parent preference.
            var best: usize = 0;
            for (self.ready.items, 0..) |job, i| {
                const b = self.ready.items[best];
                if (job.record.leaf_count > b.record.leaf_count or (job.record.leaf_count == b.record.leaf_count and job.id < b.id)) best = i;
            }
            const job = self.ready.orderedRemove(best);
            if (job.leaf != null) self.leaves_ahead -= 1;
            self.changed.broadcast();
            self.mutex.unlock();
            const proved = self.device(job, lane);
            self.mutex.lock();
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
    fn device(self: *Pipelined, job: *Pipe.Job, lane: usize) !void {
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
    fn finish(self: *Pipelined, job: *Pipe.Job) !usize {
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
    fn completeLocked(self: *Pipelined, job: *Pipe.Job, retired: usize) void {
        const a = self.input.allocator;
        const id = job.id;
        const proof = job.wrapped.?;
        job.wrapped = null;
        self.proofs[id] = .{ .proof = proof, .node = id };
        const spec = self.plan.nodes[id];
        self.nodes[id] = .{ .first_leaf = spec.first_leaf, .leaf_count = spec.leaf_count, .left = spec.left(), .right = spec.right(), .authority = proof.authority.identity, .digest = proof.digest };
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

fn runPipelined(input: PreparedExecution, options: ParallelOptions, pipe: Pipe.Options, plan: *const Dag.Plan, nodes: []Node, budget: *SharedBudget) !Report {
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
    var shared = Pipelined{ .input = input, .options = options, .pipe = pipe, .plan = plan, .queue = try Dag.Queue.init(plan, options.lanes.len, options.max_pending_authorities), .nodes = nodes, .records = records, .prep_pool = prep_pool, .origin_ns = input.timer.read() };
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
        fn run(self: *@This()) void {
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
    const root_thread = std.Thread.spawn(.{ .stack_size = coordinator_stack }, RootCheck.run, .{&root_check}) catch null;
    var root_joined = false;
    defer if (!root_joined) if (root_thread) |thread| thread.join();
    if (root_thread == null) root_check.run();
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
    for (threads[0..launched]) |thread| thread.join();
    const recursion_wall_ns = shared.now();
    if (root_thread) |thread| thread.join();
    root_joined = true;
    if (root_check.failure) |err| return err;
    if (shared.fatal) |err| return err;
    if (shared.queue.failure) |failure| return failure.err;
    if (shared.queue.completed != plan.count or shared.queue.active != 0 or shared.queue.live != 1) return error.RecursiveLeafCoverage;
    const final = shared.proofs[plan.root] orelse return error.RecursiveLeafCoverage;
    const info = nodes[plan.root];
    const verify_start = input.timer.read();
    try Outer.requireDigest(final.proof.produced.outputs, info.digest);
    var fresh = try Prove.verify(a, final.proof.authority, final.proof.produced.outputs, final.proof.produced.claims, &final.proof.produced.proof.proof);
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
    const occupancy = @as(f64, @floatFromInt(busy_total)) / @as(f64, @floatFromInt(@max(1, recursion_wall_ns * options.lanes.len)));
    const scheduler = try std.json.Stringify.valueAlloc(a, .{ .schema = 1, .candidate = true, .pipelined = true, .lanes = options.lanes.len, .pool_worker_budget = options.pool_worker_budget, .max_pending_authorities = options.max_pending_authorities, .peak_authority_slots = shared.queue.peak, .host_budget = budget.snapshot() }, .{ .whitespace = .indent_2 });
    defer a.free(scheduler);
    try @import("publication.zig").write(input.dir, "scheduler.json", scheduler);
    const timeline = try std.json.Stringify.valueAlloc(a, .{ .schema = "rv64-om31-pipelined-recursion-timeline/v1", .measured = true, .scope = "ns since pipeline start; device stage = precommit+authority+device proof on that lane; occupancy is lane device-stage wall / (lanes * DAG wall), an upper bound on GPU kernel busy", .options = pipe, .lanes = options.lanes.len, .dag_wall_ns = recursion_wall_ns, .concurrent_root_metadata_check_ns = root_check.ns, .root_publication_ns = input.timer.read() - verify_start, .lane_device_stage_ns = lane_busy[0..options.lanes.len], .lane_device_stage_occupancy = occupancy, .peak_leaves_ahead = shared.peak_leaves_ahead, .peak_ready = shared.peak_ready, .nodes = records }, .{ .whitespace = .indent_1 });
    defer a.free(timeline);
    try @import("publication.zig").write(input.dir, "pipeline.json", timeline);
    std.log.info("rv64 OM31 pipelined recursion done: dag_wall_ns={d} lane_device_stage_occupancy={d:.3}", .{ recursion_wall_ns, occupancy });
    return report;
}
