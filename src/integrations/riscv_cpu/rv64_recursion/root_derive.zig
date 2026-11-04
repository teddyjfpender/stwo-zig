//! Parallel full-tree receiver for `derive-vk-tables` (stream fold-v3, M6).
//!
//! Same checks as `execution_wrap.verifyExisting` (the sequential receiver,
//! which stays the `--audit` path): receiver admission, every leaf graph built
//! trace-only from the receiver's own setup and frame words, every leaf and
//! fold proof freshly verified under an authority this process built from
//! source, every fold digest recomputed from its children, the root proof
//! re-verified and compared byte for byte, `services_root.check` run again.
//! Only the schedule differs: the tree is the receiver's own `ready_dag.Plan`
//! (streaming carry, node ids = proof file ids), leaves run on `lanes`
//! threads, and folds run level by level with one authority build per fold
//! class (in-process, receiver-built, never persisted: the FOLD_CLASS_CACHE
//! rule) and every other fold of that class restored and freshly verified
//! under it. Derive's table is the product; its root-only self-check and the
//! `--audit` run cross-check this schedule against the sequential receiver.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const RV = @import("root_verify.zig");
const Bridge = @import("om31_outer.zig");
const Dag = @import("om31_native/ready_dag.zig");
const Graph = @import("om31_native/leaf_graph.zig");
const Outer = @import("om31_native/outer_wrap.zig");
const Root = @import("om31_native/services_root.zig");
const CpuLeaf = @import("om31_native/cpu_leaf.zig");
const TruthLeaf = @import("om31_native/truth_leaf.zig");
const KeccakLeaf = @import("om31_native/keccak_leaf.zig");
const Om31 = @import("stwo_circuit_cpu_integration").om31;
const Prove = Om31.prove;
const Wire = Om31.wire;
const R = @import("../word16_global_execution/services/roster.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const W = @import("../word16_global_execution/services/gkr_local/worker_protocol.zig");
const Coordinator = @import("../word16_global_execution/services/gkr_local/coordinator.zig");
const Execution = @import("../word16_global_execution/services/gkr_local/execution.zig");
const MW = @import("../word16_global_execution/services/gkr_local/manifest_wire.zig");
const M = @import("../word16_global_execution/services/gkr_local/manifest.zig");
const FixedSet = @import("../word16_global_execution/services/gkr_local/fixed_authority_set.zig").Set;
const Publication = @import("om31_native/publication.zig");

pub const Report = struct {
    root_digest: [32]u8,
    root_authority: [32]u8,
    fold_proofs: usize,
    fold_class_builds: usize,
    fold_class_restores: usize,
    lanes: usize,
    leaves_ns: u64,
    folds_ns: u64,
    total_ns: u64,
};

const Slot = struct {
    proof: ?*Outer.Wrapped = null,
    vk: ?RV.VerifierKey = null,
    fn release(self: *Slot, a: std.mem.Allocator) void {
        if (self.proof) |p| {
            p.deinit();
            a.destroy(p);
        }
        self.proof = null;
    }
};
const PP = @import("stwo_circuit_frontend").common.preprocessed.PreprocessedCircuit;
const ClassEntry = struct { key: [32]u8, pp: *PP, authority: *Prove.Authority };

fn child(slot: *const Slot) Bridge.Child {
    const p = slot.proof.?;
    return .{ .authority = p.authority, .produced = &p.produced, .capture = &p.capture };
}
fn readProof(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8) ![]u8 {
    return dir.readFileAlloc(a, name, Wire.MAX_BYTES) catch |err| switch (err) {
        error.FileNotFound => return error.MissingRecursiveNodeProof,
        else => return err,
    };
}
fn requireReceiverTrace(ctx: anytype) !void {
    if (!ctx.trace_only or ctx.value_table.items.len != 0 or ctx.value_table.capacity != 0) return error.RecursiveReceiverWitnessForbidden;
}

/// Runs `func(ctx, i)` for i in 0..count on up to `lanes` threads, each bound
/// to the caller's work pool. Returns the first error.
fn parallel(count: usize, lanes: usize, ctx: anytype, comptime func: fn (@TypeOf(ctx), usize) anyerror!void) !void {
    const Ctx = @TypeOf(ctx);
    const Shared = struct {
        ctx: Ctx,
        pool: ?*engine.work_pool.WorkPool,
        next: std.atomic.Value(usize) = .init(0),
        count: usize,
        failed: std.atomic.Value(bool) = .init(false),
        err: anyerror = error.Unexpected,
        mutex: std.Thread.Mutex = .{},
        fn work(shared: *@This()) void {
            var binding: ?engine.work_pool.ScopedPoolBinding = if (shared.pool) |pool| (engine.work_pool.ScopedPoolBinding.initIfNeeded(pool) catch null) else null;
            defer if (binding) |*b| b.deinit();
            shared.loop();
        }
        fn loop(shared: *@This()) void {
            while (!shared.failed.load(.acquire)) {
                const i = shared.next.fetchAdd(1, .monotonic);
                if (i >= shared.count) return;
                func(shared.ctx, i) catch |e| {
                    shared.mutex.lock();
                    defer shared.mutex.unlock();
                    if (!shared.failed.load(.acquire)) shared.err = e;
                    shared.failed.store(true, .release);
                    return;
                };
            }
        }
    };
    var shared = Shared{ .ctx = ctx, .pool = engine.work_pool.currentScopedPool(), .count = count };
    var threads: [32]std.Thread = undefined;
    var spawned: usize = 0;
    const target = @min(@min(count, lanes), threads.len + 1);
    while (spawned + 1 < target) : (spawned += 1) {
        threads[spawned] = std.Thread.spawn(.{ .stack_size = 256 << 20 }, Shared.work, .{&shared}) catch break;
    }
    shared.loop();
    for (threads[0..spawned]) |t| t.join();
    if (shared.failed.load(.acquire)) return shared.err;
}

pub fn verifyTree(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, bundle: *const Coordinator.Bundle, expected: P.Expected, config: W.PcsConfig, fixed: *const FixedSet, dir: std.fs.Dir, lanes: usize, sink: *RV.Sink) !Report {
    var timer = try std.time.Timer.start();
    const arity = try @import("om31_native/execution_wrap.zig").foldArity();
    var inventory = try Execution.Inventory.initWithAuthority(a, setups, truths, bundle.requests, expected, config, fixed);
    defer inventory.deinit();
    var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, bundle.stage_one_bytes);
    defer stages.deinit();
    var manifest = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
    defer manifest.deinit(a);
    const n = inventory.workers.len;
    if (n == 0 or n > 256 or bundle.cpus.len != setups.len or bundle.truths.len != truths.len) return error.ServicesRootRoster;
    const plan = try Dag.Plan.initArity(n, arity);
    try Publication.requireExisting(dir, plan);

    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // Receiver frame words (exactly runImpl's) and the services_root frames.
    const words = try arena.alloc([]const u32, n);
    const cpus = try arena.alloc(Root.CpuFrame, setups.len);
    for (setups, 0..) |setup, i| {
        const local = manifest.entries[i].local orelse return error.WideCpuLocalRequired;
        words[i] = try CpuLeaf.expectedWords(arena, setup, bundle.requests[i], inventory.first_ids[i], inventory.workers[i], manifest.digest, stages.stages[i].main, local.digest, bundle.cpus[i].claims);
        cpus[i] = .{ .words = words[i], .physical_claims = bundle.cpus[i].claims, .terminal_marginals = local.artifact.claims_to_verify_by_instance };
    }
    for (truths, 0..) |truth, i| {
        const ordinal = setups.len + i;
        const worker = inventory.workers[ordinal];
        const claims = bundle.truths[i].claims;
        if (truth == .keccak) {
            if (claims.len != 5) return error.InvalidWideTruthClaims;
            const public = KeccakLeaf.Public{ .ordinal = worker.ordinal, .statement = worker.statement, .manifest = manifest.digest, .claims = claims[0..5].* };
            words[ordinal] = try arena.dupe(u32, &KeccakLeaf.statementWords(truth, public, stages.stages[ordinal].main));
        } else {
            if (claims.len != 1) return error.InvalidWideTruthClaims;
            const public = TruthLeaf.Public{ .ordinal = worker.ordinal, .statement = worker.statement, .manifest = manifest.digest, .claim = claims[0] };
            words[ordinal] = try arena.dupe(u32, &TruthLeaf.statementWords(truth, public, stages.stages[ordinal].main));
        }
    }
    const frames = Root.Frames{ .cpus = cpus, .truths = words[setups.len..] };
    // Early rejection only; repeated after the root below, as runImpl does.
    _ = try Root.check(a, setups, truths, bundle.requests, expected, config, fixed, bundle.stage_one_bytes, frames, .{});

    const start_ns = timer.lap();
    const slots = try arena.alloc(Slot, plan.count);
    @memset(slots, .{});
    defer for (slots) |*slot| slot.release(a);
    var classes: std.ArrayList(ClassEntry) = .empty;
    defer {
        for (classes.items) |entry| {
            entry.authority.deinit();
            a.destroy(entry.authority);
            entry.pp.deinit(a);
            a.destroy(entry.pp);
        }
        classes.deinit(a);
    }

    // ---- leaves: independent, `lanes` at a time.
    const Leaves = struct {
        a: std.mem.Allocator,
        setups: []const *const R.CpuSetup,
        truths: []const R.Truth,
        bundle: *const Coordinator.Bundle,
        inventory: *const Execution.Inventory,
        stages: *const MW.Owned,
        manifest: *const M.PendingManifest,
        config: W.PcsConfig,
        fixed: *const FixedSet,
        words: []const []const u32,
        slots: []Slot,
        dir: std.fs.Dir,
        fn run(self: *const @This(), ordinal: usize) anyerror!void {
            const al = self.a;
            const worker = self.inventory.workers[ordinal];
            var graph = if (ordinal < self.setups.len)
                try Graph.cpuTraceOnly(al, .{ .setup = self.setups[ordinal], .request = self.bundle.requests[ordinal], .expected = worker, .first = self.inventory.first_ids[ordinal], .manifest = self.manifest, .index = ordinal, .stage = &self.stages.stages[ordinal], .config = self.config, .encoded = &self.bundle.cpus[ordinal], .fixed = self.fixed.at(ordinal) })
            else
                try Graph.truthTraceOnly(al, .{ .truth = self.truths[ordinal - self.setups.len], .expected = worker, .manifest = self.manifest, .config = self.config, .encoded = &self.bundle.truths[ordinal - self.setups.len], .fixed = self.fixed.at(ordinal) });
            defer graph.deinit();
            try requireReceiverTrace(graph.ctx);
            if (!std.mem.eql(u32, graph.words, self.words[ordinal])) return error.RecursiveLeafFrame;
            var name_buffer: [64]u8 = undefined;
            const encoded = try readProof(al, self.dir, try std.fmt.bufPrint(&name_buffer, "leaf-{d:0>6}.proof", .{ordinal}));
            defer al.free(encoded);
            const proof = try al.create(Outer.Wrapped);
            errdefer al.destroy(proof);
            // The node-id argument only keys device precommit (null factory).
            proof.* = try Outer.wrapGraphOrLoadWithFactory(al, graph.ctx, graph.digest, encoded, @intCast(ordinal), null);
            errdefer proof.deinit();
            const vk = try RV.VerifierKey.fromAuthority(proof.authority);
            _ = proof.retireProverData();
            const slot = &self.slots[ordinal];
            slot.* = .{ .proof = proof, .vk = vk };
        }
    };
    // Leaf node ids: plan leaves are appended in ordinal order, but folds are
    // interleaved; map ordinal -> node id.
    const leaf_node = try arena.alloc(usize, n);
    for (plan.nodes[0..plan.count], 0..) |node, id| if (node.isLeaf()) {
        leaf_node[node.first_leaf] = id;
    };
    const leaf_slots = try arena.alloc(Slot, n);
    @memset(leaf_slots, .{});
    defer for (leaf_slots) |*slot| slot.release(a);
    const leaves_ctx = Leaves{ .a = a, .setups = setups, .truths = truths, .bundle = bundle, .inventory = &inventory, .stages = &stages, .manifest = &manifest, .config = config, .fixed = fixed, .words = words, .slots = leaf_slots, .dir = dir };
    try parallel(n, lanes, &leaves_ctx, Leaves.run);
    for (leaf_slots, 0..) |*slot, ordinal| {
        const p = slot.proof orelse return error.RecursiveLeafCoverage;
        try sink.leaves.append(sink.allocator, .{ .ordinal = ordinal, .vk = slot.vk.?, .digest = p.digest });
        slots[leaf_node[ordinal]] = slot.*;
        slot.* = .{};
    }
    const leaves_ns = timer.lap();

    // ---- folds: by height; per height one build per new class, the rest
    // restored under it. Children are released once their parent verified.
    const height = try arena.alloc(usize, plan.count);
    var max_height: usize = 0;
    for (plan.nodes[0..plan.count], 0..) |node, id| {
        height[id] = 0;
        if (node.isLeaf()) continue;
        for (node.kids()) |kid| height[id] = @max(height[id], height[kid] + 1);
        max_height = @max(max_height, height[id]);
    }
    const Fold = struct {
        id: usize,
        class: [32]u8,
        digest: [32]u8,
        build: bool,
        entry: ?ClassEntry = null,
    };
    const Folds = struct {
        a: std.mem.Allocator,
        plan: *const Dag.Plan,
        slots: []Slot,
        folds: []Fold,
        dir: std.fs.Dir,
        fn run(self: *const @This(), index: usize) anyerror!void {
            const al = self.a;
            const job = &self.folds[index];
            const node = self.plan.nodes[job.id];
            var children: [Dag.max_arity]Bridge.Child = undefined;
            for (node.kids(), 0..) |kid, i| children[i] = child(&self.slots[kid]);
            var name_buffer: [64]u8 = undefined;
            const encoded = try readProof(al, self.dir, try std.fmt.bufPrint(&name_buffer, "fold-{d:0>6}.proof", .{job.id}));
            defer al.free(encoded);
            const proof = try al.create(Outer.Wrapped);
            errdefer al.destroy(proof);
            if (job.build) {
                var graph = try Bridge.buildFoldTraceOnly(al, children[0..node.arity]);
                defer graph.deinit();
                try requireReceiverTrace(&graph.ctx);
                if (!std.mem.eql(u8, &job.digest, &graph.output_digest)) return error.RecursiveFoldDigest;
                proof.* = try Outer.wrapGraphOrLoadWithFactory(al, &graph.ctx, job.digest, encoded, @intCast(job.id), null);
                errdefer proof.deinit();
                _ = proof.retireProverData();
                if (!proof.authority.retired) return error.FoldClassAdoptRequiresRetiredOwner;
            } else {
                const entry = job.entry orelse return error.VkDeriveFoldClassMissing;
                proof.* = try Outer.restoreWithAuthority(al, entry.pp, entry.authority, job.digest, encoded);
            }
            self.slots[job.id].proof = proof;
            self.slots[job.id].vk = try RV.VerifierKey.fromAuthority(proof.authority);
        }
    };
    var builds: usize = 0;
    var restores: usize = 0;
    var level: usize = 1;
    while (level <= max_height) : (level += 1) {
        var jobs: std.ArrayList(Fold) = .empty;
        defer jobs.deinit(a);
        for (plan.nodes[0..plan.count], 0..) |node, id| if (!node.isLeaf() and height[id] == level) {
            var children: [Dag.max_arity]Bridge.Child = undefined;
            for (node.kids(), 0..) |kid, i| children[i] = child(&slots[kid]);
            const kids = children[0..node.arity];
            try jobs.append(a, .{ .id = id, .class = try Bridge.classKey(kids), .digest = try Bridge.expectedDigest(kids), .build = false });
        };
        // Phase 1: one fresh build per class not yet held; phase 2: the rest.
        for (0..2) |phase| {
            var selected: std.ArrayList(Fold) = .empty;
            defer selected.deinit(a);
            var picked: std.ArrayList(usize) = .empty;
            defer picked.deinit(a);
            for (jobs.items, 0..) |*job, j| {
                const held: ?ClassEntry = for (classes.items) |entry| {
                    if (std.mem.eql(u8, &entry.key, &job.class)) break entry;
                } else null;
                if (phase == 0) {
                    if (held != null) continue;
                    const dup = for (selected.items) |s| {
                        if (std.mem.eql(u8, &s.class, &job.class)) break true;
                    } else false;
                    if (dup) continue;
                    var copy = job.*;
                    copy.build = true;
                    try selected.append(a, copy);
                    try picked.append(a, j);
                } else if (slots[job.id].proof == null) {
                    var copy = job.*;
                    copy.entry = held orelse return error.VkDeriveFoldClassMissing;
                    try selected.append(a, copy);
                    try picked.append(a, j);
                }
            }
            if (selected.items.len == 0) continue;
            const ctx = Folds{ .a = a, .plan = &plan, .slots = slots, .folds = selected.items, .dir = dir };
            try parallel(selected.items.len, lanes, &ctx, Folds.run);
            for (selected.items) |job| {
                const proof = slots[job.id].proof.?;
                if (job.build) {
                    // derive cross-check of the class/digest re-implementation
                    // and the freshly built class authority, then adopt it.
                    const node = plan.nodes[job.id];
                    if (node.arity == 2) {
                        RV.recordFoldInto(sink, .{ child(&slots[node.children[0]]), child(&slots[node.children[1]]) }, job.class, job.digest, proof.authority) catch |err| return err;
                    } else return error.VkDeriveKaryFoldNotTabled;
                    try classes.append(a, .{ .key = job.class, .pp = proof.pp, .authority = proof.authority });
                    proof.borrowed = true;
                    builds += 1;
                } else restores += 1;
            }
        }
        // Release the children of this level's folds.
        for (jobs.items) |job| for (plan.nodes[job.id].kids()) |kid| slots[kid].release(a);
    }
    const folds_ns = timer.lap();

    const root = plan.root;
    const final = slots[root].proof orelse return error.RecursiveLeafCoverage;
    if (plan.nodes[root].first_leaf != 0 or plan.nodes[root].leaf_count != n) return error.RecursiveLeafCoverage;
    try Outer.requireDigest(final.produced.outputs, final.digest);
    var fresh = try Prove.verify(a, final.authority, final.produced.outputs, final.produced.claims, &final.produced.proof.proof);
    fresh.deinit(a);
    _ = try Root.check(a, setups, truths, bundle.requests, expected, config, fixed, bundle.stage_one_bytes, frames, .{});
    const bytes = try final.serialize(a);
    defer a.free(bytes);
    try Publication.requireBytes(a, dir, "root.proof", bytes);
    const root_ns = timer.read();
    return .{ .root_digest = final.digest, .root_authority = final.authority.identity, .fold_proofs = plan.count - n, .fold_class_builds = builds, .fold_class_restores = restores, .lanes = lanes, .leaves_ns = leaves_ns, .folds_ns = folds_ns, .total_ns = start_ns + leaves_ns + folds_ns + root_ns };
}
