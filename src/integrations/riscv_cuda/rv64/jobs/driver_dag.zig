//! GPU-native request DAG and static placement (rv64-m8-gpu-native.md §3.8).
//!
//! Host planning only, from cached class constants: no device work, no waits,
//! microseconds per request. The output is, per GPU, the exact enqueue order
//! of that GPU's batch; every per-GPU order is a subsequence of ONE global
//! topological order, so the worker threads' host latches (a consumer waits
//! until its producers' done events were RECORDED) can never deadlock.
//!
//! Graph: stage1(seg) -> seal -> stage2(seg); truth(t) (before or after the
//! seal); recursion nodes on their children (leaves on native segments and
//! truths, folds on nodes, root last).
//!
//! Placement:
//!   - a segment's Stage1 and Stage2 run on the same GPU (MAIN never moves),
//!     longest-processing-time first onto the least-loaded GPU whose
//!     main_resident region still fits the segment's MAIN;
//!   - the seal on the seal GPU (it also holds the request pseudo-proof and
//!     performs the request's single final event);
//!   - truths least-loaded first;
//!   - recursion nodes where most of their children are (child slab
//!     locality: fewer cross-GPU child copies), ties to the least-loaded GPU.
//! Two-phase memory (§3.7): every job a GPU runs after its last Stage2 is a
//! phase-B job (its arena may grow over the freed main_resident region).
const std = @import("std");
const G = @import("gpu_native.zig");

pub const Kind = enum(u8) { stage1, seal, stage2, truth, node };

pub const Node = struct {
    kind: Kind,
    /// Segment (stage1/stage2), truth ordinal, or recursion node id.
    ordinal: u32,
    /// Proof this node publishes (null: stage1 and seal publish exchange slots only).
    proof: ?G.ProofId,
    device: u32 = 0,
    deps: []const u32 = &.{},
    /// Recursion node: its children's proofs in order.
    children: []const G.ProofId = &.{},
    cost: u64 = 1,
    rank: u8 = 0,
    phase_b: bool = false,
};

pub const Segment = struct {
    /// MAIN words this segment keeps resident from witness to PCS (class constant).
    main_words: u64 = 0,
    stage1_cost: u64 = 1,
    stage2_cost: u64 = 1,
};

pub const Truth = struct { cost: u64 = 1 };

/// One recursion node, children before parents (ready_dag order).
pub const RecursionNode = struct {
    /// Children node ids (folds/root); empty for a leaf.
    children: []const u32 = &.{},
    /// Leaf inputs: native segments and truths it verifies.
    segments: []const u32 = &.{},
    truths: []const u32 = &.{},
    cost: u64 = 1,
};

pub const Shape = struct {
    devices: u32,
    seal_device: u32 = 0,
    segments: []const Segment,
    truths: []const Truth = &.{},
    /// Truth/service proofs that need the sealed global relation.
    truth_after_seal: bool = false,
    recursion: []const RecursionNode = &.{},
    /// Recursion root node id (must be the last node). Ignored when empty.
    root: u32 = 0,
    seal_cost: u64 = 1,
    /// Per-device main_resident capacity (words); empty = unbounded.
    main_capacity: []const u64 = &.{},
};

pub const Dag = struct {
    a: std.mem.Allocator,
    nodes: []Node,
    /// Global topological enqueue order (node indices).
    order: []u32,
    /// Per device: node indices in that GPU's enqueue order.
    device_order: [][]u32,
    /// Per device: estimated cost placed there.
    loads: []u64,
    /// Per device: MAIN words placed there.
    main_words: []u64,
    seal: u32,
    stage1: []u32,
    stage2: []u32,
    truth: []u32,
    recursion: []u32,
    final_device: u32,
    edges: []u32,
    child_ids: []G.ProofId,

    pub fn deinit(self: *Dag) void {
        const a = self.a;
        a.free(self.nodes);
        a.free(self.order);
        for (self.device_order) |o| a.free(o);
        a.free(self.device_order);
        a.free(self.loads);
        a.free(self.main_words);
        a.free(self.stage1);
        a.free(self.stage2);
        a.free(self.truth);
        a.free(self.recursion);
        a.free(self.edges);
        a.free(self.child_ids);
    }

    /// The proofs this request publishes, with their device (class constants
    /// filled by the caller through `spec`).
    pub fn proofIds(self: *const Dag, a: std.mem.Allocator) ![]ProofPlacement {
        var n: usize = 1;
        for (self.nodes) |nd| if (nd.proof != null) {
            n += 1;
        };
        const out = try a.alloc(ProofPlacement, n);
        var i: usize = 0;
        for (self.nodes) |nd| if (nd.proof) |p| {
            out[i] = .{ .id = p, .device = nd.device };
            i += 1;
        };
        out[i] = .{ .id = .{ .kind = .request, .ordinal = 0 }, .device = self.final_device };
        return out;
    }
};

pub const ProofPlacement = struct { id: G.ProofId, device: u32 };

pub fn recursionKind(shape: Shape, id: u32) G.ProofKind {
    if (shape.recursion[id].children.len == 0) return .leaf;
    return if (id == shape.root) .root else .fold;
}

pub fn build(a: std.mem.Allocator, shape: Shape) !Dag {
    if (shape.devices == 0) return error.GpuNativeNoDevices;
    if (shape.devices > G.max_devices) return error.GpuNativeTooManyDevices;
    if (shape.seal_device >= shape.devices) return error.GpuNativeSealDeviceOutOfRange;
    if (shape.segments.len == 0) return error.GpuNativeNoSegments;
    if (shape.main_capacity.len != 0 and shape.main_capacity.len != shape.devices) return error.GpuNativeMainCapacityShape;
    if (shape.recursion.len != 0 and shape.root + 1 != shape.recursion.len) return error.GpuNativeRecursionRootNotLast;
    const S: u32 = @intCast(shape.segments.len);
    const T: u32 = @intCast(shape.truths.len);
    const R: u32 = @intCast(shape.recursion.len);
    const n_nodes = 2 * S + 1 + T + R;

    // ---- edges ----
    var n_edges: usize = S + S; // seal <- stage1, stage2 <- seal
    if (shape.truth_after_seal) n_edges += T;
    var n_children: usize = 0;
    for (shape.recursion, 0..) |rn, id| {
        if (rn.children.len == 0) {
            if (rn.segments.len + rn.truths.len == 0) return error.GpuNativeLeafWithoutInputs;
            n_edges += rn.segments.len + rn.truths.len;
            n_children += rn.segments.len + rn.truths.len;
        } else {
            for (rn.children) |c| if (c >= id) return error.GpuNativeRecursionOrder;
            n_edges += rn.children.len;
            n_children += rn.children.len;
        }
        for (rn.segments) |s| if (s >= S) return error.GpuNativeLeafSegmentOutOfRange;
        for (rn.truths) |t| if (t >= T) return error.GpuNativeLeafTruthOutOfRange;
    }
    const nodes = try a.alloc(Node, n_nodes);
    errdefer a.free(nodes);
    const edges = try a.alloc(u32, n_edges);
    errdefer a.free(edges);
    const child_ids = try a.alloc(G.ProofId, n_children);
    errdefer a.free(child_ids);
    const stage1 = try a.alloc(u32, S);
    errdefer a.free(stage1);
    const stage2 = try a.alloc(u32, S);
    errdefer a.free(stage2);
    const truth = try a.alloc(u32, T);
    errdefer a.free(truth);
    const recursion = try a.alloc(u32, R);
    errdefer a.free(recursion);
    const loads = try a.alloc(u64, shape.devices);
    errdefer a.free(loads);
    @memset(loads, 0);
    const mains = try a.alloc(u64, shape.devices);
    errdefer a.free(mains);
    @memset(mains, 0);

    var at: u32 = 0;
    var e: usize = 0;
    var c: usize = 0;
    for (0..S) |s| {
        stage1[s] = at;
        nodes[at] = .{ .kind = .stage1, .ordinal = @intCast(s), .proof = null, .cost = shape.segments[s].stage1_cost, .rank = 0 };
        at += 1;
    }
    const seal = at;
    nodes[seal] = .{ .kind = .seal, .ordinal = 0, .proof = null, .device = shape.seal_device, .deps = edges[e..][0..S], .cost = shape.seal_cost, .rank = 2 };
    @memcpy(edges[e..][0..S], stage1);
    e += S;
    at += 1;
    for (0..S) |s| {
        stage2[s] = at;
        edges[e] = seal;
        nodes[at] = .{ .kind = .stage2, .ordinal = @intCast(s), .proof = .{ .kind = .native_segment, .ordinal = @intCast(s) }, .deps = edges[e..][0..1], .cost = shape.segments[s].stage2_cost, .rank = 3 };
        e += 1;
        at += 1;
    }
    for (0..T) |t| {
        truth[t] = at;
        var deps: []const u32 = &.{};
        if (shape.truth_after_seal) {
            edges[e] = seal;
            deps = edges[e..][0..1];
            e += 1;
        }
        nodes[at] = .{ .kind = .truth, .ordinal = @intCast(t), .proof = .{ .kind = .truth, .ordinal = @intCast(t) }, .deps = deps, .cost = shape.truths[t].cost, .rank = if (shape.truth_after_seal) 3 else 1 };
        at += 1;
    }
    for (shape.recursion, 0..) |rn, id| {
        recursion[id] = at;
        const first_e = e;
        const first_c = c;
        if (rn.children.len == 0) {
            for (rn.segments) |s| {
                edges[e] = stage2[s];
                child_ids[c] = .{ .kind = .native_segment, .ordinal = s };
                e += 1;
                c += 1;
            }
            for (rn.truths) |t| {
                edges[e] = truth[t];
                child_ids[c] = .{ .kind = .truth, .ordinal = t };
                e += 1;
                c += 1;
            }
        } else for (rn.children) |kid| {
            edges[e] = recursion[kid];
            child_ids[c] = .{ .kind = recursionKind(shape, kid), .ordinal = kid };
            e += 1;
            c += 1;
        }
        nodes[at] = .{ .kind = .node, .ordinal = @intCast(id), .proof = .{ .kind = recursionKind(shape, @intCast(id)), .ordinal = @intCast(id) }, .deps = edges[first_e..e], .children = child_ids[first_c..c], .cost = rn.cost, .rank = 3 };
        at += 1;
    }
    std.debug.assert(at == n_nodes and e == n_edges and c == n_children);

    // ---- placement ----
    // Segments: LPT on stage1+stage2 cost, constrained by main capacity.
    const by_cost = try a.alloc(u32, S);
    defer a.free(by_cost);
    for (by_cost, 0..) |*x, i| x.* = @intCast(i);
    const Ctx = struct {
        segs: []const Segment,
        fn less(ctx: @This(), l: u32, r: u32) bool {
            const cl = ctx.segs[l].stage1_cost + ctx.segs[l].stage2_cost;
            const cr = ctx.segs[r].stage1_cost + ctx.segs[r].stage2_cost;
            return if (cl != cr) cl > cr else l < r;
        }
    };
    std.mem.sort(u32, by_cost, Ctx{ .segs = shape.segments }, Ctx.less);
    for (by_cost) |s| {
        const seg = shape.segments[s];
        var best: ?u32 = null;
        for (0..shape.devices) |d| {
            if (shape.main_capacity.len != 0 and mains[d] + seg.main_words > shape.main_capacity[d]) continue;
            if (best == null or loads[d] < loads[best.?]) best = @intCast(d);
        }
        const d = best orelse return error.GpuNativeMainResidentExhausted;
        nodes[stage1[s]].device = d;
        nodes[stage2[s]].device = d;
        loads[d] += seg.stage1_cost + seg.stage2_cost;
        mains[d] += seg.main_words;
    }
    loads[shape.seal_device] += shape.seal_cost;
    for (truth) |id| {
        const d = argmin(loads);
        nodes[id].device = d;
        loads[d] += nodes[id].cost;
    }
    var votes: [G.max_devices]u32 = undefined;
    for (recursion) |id| {
        @memset(votes[0..shape.devices], 0);
        for (nodes[id].deps) |dep| votes[nodes[dep].device] += 1;
        var best: u32 = 0;
        for (1..shape.devices) |d| {
            if (votes[d] > votes[best] or (votes[d] == votes[best] and loads[d] < loads[best])) best = @intCast(d);
        }
        nodes[id].device = best;
        loads[best] += nodes[id].cost;
    }

    // ---- global topological order: Kahn, ready set by (rank, kind, ordinal) ----
    const order = try a.alloc(u32, n_nodes);
    errdefer a.free(order);
    const indegree = try a.alloc(u32, n_nodes);
    defer a.free(indegree);
    const placed = try a.alloc(bool, n_nodes);
    defer a.free(placed);
    @memset(placed, false);
    for (nodes, 0..) |nd, i| indegree[i] = @intCast(nd.deps.len);
    for (0..n_nodes) |k| {
        var pick: ?u32 = null;
        for (nodes, 0..) |nd, i| {
            if (placed[i] or indegree[i] != 0) continue;
            if (pick == null or before(nd, nodes[pick.?], @intCast(i), pick.?)) pick = @intCast(i);
        }
        const p = pick orelse return error.GpuNativeDagCycle;
        placed[p] = true;
        order[k] = p;
        for (nodes, 0..) |nd, i| for (nd.deps) |d| if (d == p) {
            indegree[i] -= 1;
        };
    }

    // ---- per-device orders + phase B ----
    const device_order = try a.alloc([]u32, shape.devices);
    var made: usize = 0;
    errdefer {
        for (device_order[0..made]) |o| a.free(o);
        a.free(device_order);
    }
    for (0..shape.devices) |d| {
        var n: usize = 0;
        for (order) |i| if (nodes[i].device == d) {
            n += 1;
        };
        device_order[d] = try a.alloc(u32, n);
        made += 1;
        var k: usize = 0;
        var last_stage2: ?usize = null;
        for (order) |i| if (nodes[i].device == d) {
            device_order[d][k] = i;
            if (nodes[i].kind == .stage2) last_stage2 = k;
            k += 1;
        };
        for (device_order[d], 0..) |i, pos| {
            const after = if (last_stage2) |l| pos > l else true;
            nodes[i].phase_b = after and (nodes[i].kind == .node or nodes[i].kind == .truth);
        }
    }
    return .{ .a = a, .nodes = nodes, .order = order, .device_order = device_order, .loads = loads, .main_words = mains, .seal = seal, .stage1 = stage1, .stage2 = stage2, .truth = truth, .recursion = recursion, .final_device = shape.seal_device, .edges = edges, .child_ids = child_ids };
}

fn kindRank(k: Kind) u8 {
    return switch (k) {
        .stage1 => 0,
        .truth => 1,
        .seal => 2,
        .stage2 => 3,
        .node => 4,
    };
}

fn before(x: Node, y: Node, xi: u32, yi: u32) bool {
    if (x.rank != y.rank) return x.rank < y.rank;
    const kx = kindRank(x.kind);
    const ky = kindRank(y.kind);
    if (kx != ky) return kx < ky;
    return xi < yi;
}

fn argmin(loads: []const u64) u32 {
    var best: u32 = 0;
    for (loads, 0..) |l, d| if (l < loads[best]) {
        best = @intCast(d);
    };
    return best;
}

/// Binary carry topology over `leaves` leaves, each leaf verifying the
/// artifacts `leaf_inputs[i]` (test and fixture helper; production topology
/// comes from the recursion factory / ready_dag.Plan).
pub const Topology = struct {
    a: std.mem.Allocator,
    nodes: []RecursionNode,
    children: []u32,
    root: u32,
    pub fn deinit(self: *Topology) void {
        self.a.free(self.nodes);
        self.a.free(self.children);
    }
    /// From any ready_dag.Plan-shaped value (nodes, count, root; children
    /// precede parents) plus a leaf-input callback. Node ids are kept.
    pub fn fromPlan(a: std.mem.Allocator, plan: anytype, leaf: anytype) !Topology {
        var n_children: usize = 0;
        for (plan.nodes[0..plan.count]) |nd| n_children += nd.kids().len;
        const nodes = try a.alloc(RecursionNode, plan.count);
        errdefer a.free(nodes);
        const children = try a.alloc(u32, n_children);
        errdefer a.free(children);
        var c: usize = 0;
        for (plan.nodes[0..plan.count], 0..) |nd, id| {
            if (nd.kids().len == 0) {
                const inputs = leaf.of(nd.first_leaf);
                nodes[id] = .{ .segments = inputs.segments, .truths = inputs.truths };
            } else {
                const first = c;
                for (nd.kids()) |k| {
                    children[c] = @intCast(k);
                    c += 1;
                }
                nodes[id] = .{ .children = children[first..c] };
            }
        }
        if (plan.root + 1 != plan.count) return error.GpuNativeRecursionRootNotLast;
        return .{ .a = a, .nodes = nodes, .children = children, .root = @intCast(plan.root) };
    }
};

const testing = std.testing;

fn BinaryPlan(comptime leaves: usize) type {
    return struct { nodes: [2 * leaves - 1]PlanNode, count: usize, root: usize };
}
fn binaryPlan(comptime leaves: usize) BinaryPlan(leaves) {
    var out: BinaryPlan(leaves) = .{ .nodes = undefined, .count = 0, .root = 0 };
    var level: [2 * leaves]usize = undefined;
    var n: usize = 0;
    for (0..leaves) |i| {
        out.nodes[out.count] = .{ .first_leaf = i };
        level[n] = out.count;
        n += 1;
        out.count += 1;
    }
    var lo: usize = 0;
    while (n - lo > 1) {
        const hi = n;
        var i = lo;
        while (i + 1 < hi) : (i += 2) {
            out.nodes[out.count] = .{ .first_leaf = 0, .kid_ids = .{ level[i], level[i + 1] }, .arity = 2 };
            level[n] = out.count;
            n += 1;
            out.count += 1;
        }
        if (i < hi) {
            level[n] = level[i];
            n += 1;
        }
        lo = hi;
    }
    out.root = out.count - 1;
    return out;
}
const PlanNode = struct {
    first_leaf: usize,
    kid_ids: [2]usize = .{ 0, 0 },
    arity: u8 = 0,
    fn kids(self: *const PlanNode) []const usize {
        return self.kid_ids[0..self.arity];
    }
};

test "dag: stage1/stage2 share a GPU, seal after every stage1, global order is topological" {
    const segs = [_]Segment{ .{ .stage1_cost = 5, .stage2_cost = 9 }, .{ .stage1_cost = 4, .stage2_cost = 7 }, .{ .stage1_cost = 6, .stage2_cost = 10 }, .{ .stage1_cost = 1, .stage2_cost = 2 } };
    const plan = binaryPlan(4);
    const Leaf = struct {
        ids: [4]u32 = .{ 0, 1, 2, 3 },
        fn of(self: *const @This(), i: usize) struct { segments: []const u32, truths: []const u32 } {
            return .{ .segments = self.ids[i..][0..1], .truths = &.{} };
        }
    };
    const leaf = Leaf{};
    var topo = try Topology.fromPlan(testing.allocator, plan, &leaf);
    defer topo.deinit();
    var dag = try build(testing.allocator, .{ .devices = 2, .segments = &segs, .truths = &.{.{ .cost = 3 }}, .recursion = topo.nodes, .root = topo.root });
    defer dag.deinit();
    for (dag.stage1, dag.stage2) |s1, s2| try testing.expectEqual(dag.nodes[s1].device, dag.nodes[s2].device);
    // LPT: both GPUs carry native work.
    try testing.expect(dag.loads[0] > 0 and dag.loads[1] > 0);
    // Every dependency precedes its consumer in the global order and per GPU.
    var pos = try testing.allocator.alloc(usize, dag.nodes.len);
    defer testing.allocator.free(pos);
    for (dag.order, 0..) |i, k| pos[i] = k;
    for (dag.nodes, 0..) |nd, i| for (nd.deps) |d| try testing.expect(pos[d] < pos[i]);
    for (dag.device_order) |o| for (o[1..], 1..) |i, k| try testing.expect(pos[o[k - 1]] < pos[i]);
    // Root last, kinds right, leaf children are native segment proofs.
    const root = dag.nodes[dag.recursion[topo.root]];
    try testing.expectEqual(G.ProofKind.root, root.proof.?.kind);
    try testing.expectEqual(dag.order[dag.order.len - 1], dag.recursion[topo.root]);
    try testing.expectEqual(G.ProofKind.native_segment, dag.nodes[dag.recursion[0]].children[0].kind);
    // Phase B: only after the GPU's last stage2.
    for (dag.device_order) |o| {
        var seen_b = false;
        for (o) |i| {
            if (dag.nodes[i].phase_b) seen_b = true;
            if (seen_b) try testing.expect(dag.nodes[i].kind != .stage2 and dag.nodes[i].kind != .stage1);
        }
    }
    // Proof list: 4 natives + 1 truth + 7 nodes + request pseudo-proof.
    const ids = try dag.proofIds(testing.allocator);
    defer testing.allocator.free(ids);
    try testing.expectEqual(@as(usize, 4 + 1 + 7 + 1), ids.len);
    try testing.expectEqual(G.ProofKind.request, ids[ids.len - 1].id.kind);
}

test "dag: main_resident capacity steers segment placement and fails closed when exhausted" {
    const segs = [_]Segment{ .{ .main_words = 6 }, .{ .main_words = 6 }, .{ .main_words = 6 } };
    var dag = try build(testing.allocator, .{ .devices = 2, .segments = &segs, .main_capacity = &.{ 12, 6 } });
    defer dag.deinit();
    try testing.expectEqual(@as(u64, 12), dag.main_words[0]);
    try testing.expectEqual(@as(u64, 6), dag.main_words[1]);
    try testing.expectError(error.GpuNativeMainResidentExhausted, build(testing.allocator, .{ .devices = 2, .segments = &segs, .main_capacity = &.{ 6, 6 } }));
}

test "dag: recursion nodes follow their children; independent truths fill the seal barrier" {
    const segs = [_]Segment{ .{}, .{} };
    const rec = [_]RecursionNode{ .{ .segments = &.{0} }, .{ .segments = &.{1}, .truths = &.{0} }, .{ .children = &.{ 0, 1 } } };
    var dag = try build(testing.allocator, .{ .devices = 2, .segments = &segs, .truths = &.{.{}}, .recursion = &rec, .root = 2 });
    defer dag.deinit();
    // truth (rank 1) is ordered before the seal (rank 2).
    var pos_truth: usize = 0;
    var pos_seal: usize = 0;
    for (dag.order, 0..) |i, k| {
        if (dag.nodes[i].kind == .truth) pos_truth = k;
        if (dag.nodes[i].kind == .seal) pos_seal = k;
    }
    try testing.expect(pos_truth < pos_seal);
    // leaf 0 sits with segment 0.
    try testing.expectEqual(dag.nodes[dag.stage2[0]].device, dag.nodes[dag.recursion[0]].device);
    try testing.expectError(error.GpuNativeRecursionOrder, build(testing.allocator, .{ .devices = 1, .segments = &segs, .recursion = &.{ .{ .children = &.{1} }, .{ .segments = &.{0} } }, .root = 1 }));
}
