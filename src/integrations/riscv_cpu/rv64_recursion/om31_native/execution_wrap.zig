//! Current services recursion orchestration. Independent native inventory owns
//! topology and statement admission. Leaf proofs and parents use native OM31,
//! never legacy CircuitSerialize/production-registry QM31 proofs.
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
const Graph = @import("leaf_graph.zig");
const Outer = @import("outer_wrap.zig");
pub const Leaf = struct { proof: Outer.Wrapped, words: []u32 };
pub const Leaves = struct {
    allocator: std.mem.Allocator,
    items: []Leaf,
    cpu_frames: []Root.CpuFrame,
    truth_frames: []const []const u32,
    metadata: Root.Metadata,
    graph_ns: u64,
    wrap_ns: u64,
    pub fn deinit(self: *Leaves) void {
        for (self.items) |*leaf| {
            leaf.proof.deinit();
            self.allocator.free(leaf.words);
        }
        self.allocator.free(self.items);
        for (self.cpu_frames) |frame| freeMarginals(self.allocator, frame.terminal_marginals);
        self.allocator.free(self.cpu_frames);
        self.allocator.free(self.truth_frames);
        self.* = undefined;
    }
};
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
/// Captures all CPU and truth proofs once each. Stage-one local transcripts
/// are verified before shared challenges; root metadata is reconstructed from
/// the SAME terminal marginals authenticated inside each CPU circuit.
pub fn wrapLeaves(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, bundle: *const Coordinator.Bundle, expected: P.Expected, config: W.PcsConfig, fixed: ?*const FixedSet, dir: ?std.fs.Dir) !Leaves {
    var inventory = try Execution.Inventory.initWithAuthority(a, setups, truths, bundle.requests, expected, config, fixed);
    defer inventory.deinit();
    var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, bundle.stage_one_bytes);
    defer stages.deinit();
    var manifest = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
    defer manifest.deinit(a);
    if (bundle.cpus.len != setups.len or bundle.truths.len != truths.len or inventory.workers.len > 256) return error.ServicesRootRoster;
    const items = try a.alloc(Leaf, inventory.workers.len);
    errdefer a.free(items);
    var initialized: usize = 0;
    errdefer for (items[0..initialized]) |*leaf| {
        leaf.proof.deinit();
        a.free(leaf.words);
    };
    const cpus = try a.alloc(Root.CpuFrame, setups.len);
    @memset(cpus, .{ .words = &.{}, .physical_claims = &.{}, .terminal_marginals = &.{} });
    errdefer a.free(cpus);
    errdefer for (cpus) |frame| freeMarginals(a, frame.terminal_marginals);
    const truth_frames = try a.alloc([]const u32, truths.len);
    errdefer a.free(truth_frames);
    var timer = try std.time.Timer.start();
    var graph_ns: u64 = 0;
    var wrap_ns: u64 = 0;
    for (items, 0..) |*leaf, ordinal| {
        std.log.info("rv64 OM31 recursion leaf {d}/{d}: admitted graph", .{ ordinal + 1, items.len });
        const graph_start = timer.read();
        var graph = if (ordinal < setups.len) try Graph.cpu(a, .{
            .setup = setups[ordinal],
            .request = bundle.requests[ordinal],
            .expected = inventory.workers[ordinal],
            .first = inventory.first_ids[ordinal],
            .manifest = &manifest,
            .index = ordinal,
            .stage = &stages.stages[ordinal],
            .config = config,
            .encoded = &bundle.cpus[ordinal],
            .fixed = if (fixed) |authority| authority.at(ordinal) else null,
        }) else try Graph.truth(a, .{
            .truth = truths[ordinal - setups.len],
            .expected = inventory.workers[ordinal],
            .manifest = &manifest,
            .config = config,
            .encoded = &bundle.truths[ordinal - setups.len],
            .fixed = if (fixed) |authority| authority.at(ordinal) else null,
        });
        defer graph.deinit();
        graph_ns += timer.read() - graph_start;
        std.log.info("rv64 OM31 recursion leaf {d}/{d}: prove outer (vars={d})", .{ ordinal + 1, items.len, graph.ctx.circuit.n_vars });
        const wrap_start = timer.read();
        var wrapped = try Outer.wrapGraph(a, graph.ctx, graph.digest);
        var wrapped_owned = true;
        errdefer if (wrapped_owned) wrapped.deinit();
        const words = try a.dupe(u32, graph.words);
        leaf.* = .{ .proof = wrapped, .words = words };
        initialized += 1;
        wrapped_owned = false;
        wrap_ns += timer.read() - wrap_start;
        if (ordinal < setups.len) {
            cpus[ordinal] = .{ .words = words, .physical_claims = bundle.cpus[ordinal].claims, .terminal_marginals = try copyMarginals(a, manifest.entries[ordinal].local.?.artifact.claims_to_verify_by_instance) };
        } else truth_frames[ordinal - setups.len] = words;
        if (dir) |output| {
            const bytes = try leaf.proof.serialize(a);
            defer a.free(bytes);
            var name: [64]u8 = undefined;
            const path = try std.fmt.bufPrint(&name, "leaf-{d:0>6}.proof", .{ordinal});
            try output.writeFile(.{ .sub_path = path, .data = bytes });
        }
    }
    // Own the narrow canonical marginals, never the large native GKR witness.
    // The final fresh-root receiver repeats this cheap metadata check.
    const metadata = try Root.check(a, setups, truths, bundle.requests, expected, config, fixed, bundle.stage_one_bytes, .{ .cpus = cpus, .truths = truth_frames }, .{});
    return .{ .allocator = a, .items = items, .cpu_frames = cpus, .truth_frames = truth_frames, .metadata = metadata, .graph_ns = graph_ns, .wrap_ns = wrap_ns };
}

const Bridge = @import("../om31_outer.zig");
const Prove = @import("stwo_circuit_cpu_integration").om31.prove;
pub const Node = struct {
    first_leaf: usize,
    leaf_count: usize,
    left: ?usize,
    right: ?usize,
    authority: [32]u8,
    digest: [32]u8,
};
pub const Report = struct {
    schema: u32 = 1,
    accepted: bool = true,
    leaf_proofs: usize,
    fold_proofs: usize,
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
    /// Receiver here owns the regenerated immutable circuit keys. The wire
    /// artifact does not supply replacement keys or certify a new-process key.
    portable_root_key_admission: bool = false,
};
fn child(proof: *const Outer.Wrapped) Bridge.Child {
    return .{ .authority = proof.authority, .produced = &proof.produced, .capture = &proof.capture };
}
/// Odd nodes are promoted unchanged. Every binary parent verifies BOTH exact
/// children and commits their ordered immutable key identities/public outputs.
/// Metadata closure is accepted only alongside the freshly verified root and
/// the deterministically reconstructed ordered tree over every leaf exactly once.
pub fn run(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, bundle: *const Coordinator.Bundle, expected: P.Expected, config: W.PcsConfig, fixed: ?*const FixedSet, dir: std.fs.Dir) !Report {
    var timer = try std.time.Timer.start();
    var leaves = try wrapLeaves(a, setups, truths, bundle, expected, config, fixed, dir);
    defer leaves.deinit();
    const n = leaves.items.len;
    const node_count = try std.math.sub(usize, try std.math.mul(usize, n, 2), 1);
    const proofs = try a.alloc(*Outer.Wrapped, node_count);
    defer a.free(proofs);
    const nodes = try a.alloc(Node, node_count);
    defer a.free(nodes);
    var owned: usize = n;
    defer for (proofs[n..owned]) |proof| {
        proof.deinit();
        a.destroy(proof);
    };
    const active = try a.alloc(usize, n);
    defer a.free(active);
    for (leaves.items, 0..) |*leaf, i| {
        proofs[i] = &leaf.proof;
        nodes[i] = .{ .first_leaf = i, .leaf_count = 1, .left = null, .right = null, .authority = leaf.proof.authority.identity, .digest = leaf.proof.digest };
        active[i] = i;
    }
    const fold_start = timer.read();
    var count = n;
    while (count > 1) {
        var next: usize = 0;
        var i: usize = 0;
        while (i < count) : (i += 2) {
            if (i + 1 == count) {
                active[next] = active[i];
            } else {
                const left = active[i];
                const right = active[i + 1];
                if (nodes[left].first_leaf + nodes[left].leaf_count != nodes[right].first_leaf) return error.RecursiveLeafAdjacency;
                const children = [2]Bridge.Child{ child(proofs[left]), child(proofs[right]) };
                const digest = try Bridge.expectedDigest(children);
                var graph = try Bridge.buildFold(a, children);
                defer graph.deinit();
                if (!std.mem.eql(u8, &digest, &graph.output_digest)) return error.RecursiveFoldDigest;
                const proof = blk: {
                    const value = try a.create(Outer.Wrapped);
                    errdefer a.destroy(value);
                    value.* = try Outer.wrapGraph(a, &graph.ctx, digest);
                    break :blk value;
                };
                proofs[owned] = proof;
                nodes[owned] = .{ .first_leaf = nodes[left].first_leaf, .leaf_count = nodes[left].leaf_count + nodes[right].leaf_count, .left = left, .right = right, .authority = proof.authority.identity, .digest = digest };
                active[next] = owned;
                owned += 1;
                const bytes = try proof.serialize(a);
                defer a.free(bytes);
                var name: [64]u8 = undefined;
                try dir.writeFile(.{ .sub_path = try std.fmt.bufPrint(&name, "fold-{d:0>6}.proof", .{owned - n - 1}), .data = bytes });
            }
            next += 1;
        }
        count = next;
    }
    const fold_ns = timer.read() - fold_start;
    const root_id = active[0];
    const root = proofs[root_id];
    if (nodes[root_id].first_leaf != 0 or nodes[root_id].leaf_count != n or owned != node_count) return error.RecursiveLeafCoverage;
    const verify_start = timer.read();
    try Outer.requireDigest(root.produced.outputs, nodes[root_id].digest);
    var fresh = try Prove.verify(a, root.authority, root.produced.outputs, root.produced.claims, &root.produced.proof.proof);
    defer fresh.deinit(a);
    _ = try Root.check(a, setups, truths, bundle.requests, expected, config, fixed, bundle.stage_one_bytes, .{ .cpus = leaves.cpu_frames, .truths = leaves.truth_frames }, .{});
    const root_verify_ns = timer.read() - verify_start;
    const root_bytes = try root.serialize(a);
    defer a.free(root_bytes);
    try dir.writeFile(.{ .sub_path = "root.proof", .data = root_bytes });
    const tree_bytes = try std.json.Stringify.valueAlloc(a, .{ .schema = 1, .nodes = nodes, .root = root_id, .cpu_frames = leaves.cpu_frames, .truth_frames = leaves.truth_frames }, .{ .whitespace = .indent_2 });
    defer a.free(tree_bytes);
    try dir.writeFile(.{ .sub_path = "tree.json", .data = tree_bytes });
    const report = Report{ .leaf_proofs = n, .fold_proofs = owned - n, .root_node = root_id, .root_digest = root.digest, .root_authority = root.authority.identity, .manifest = leaves.metadata.manifest.digest, .graph_ns = leaves.graph_ns, .wrap_ns = leaves.wrap_ns, .fold_ns = fold_ns, .root_verify_ns = root_verify_ns, .total_ns = timer.read(), .root_proof_bytes = root_bytes.len };
    const report_bytes = try std.json.Stringify.valueAlloc(a, report, .{ .whitespace = .indent_2 });
    defer a.free(report_bytes);
    try dir.writeFile(.{ .sub_path = "report.json", .data = report_bytes });
    return report;
}
