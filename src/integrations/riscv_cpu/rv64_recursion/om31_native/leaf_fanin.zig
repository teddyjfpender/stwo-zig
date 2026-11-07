//! M9 fewer-leaves: capacity-fit leaf fan-in. One recursion leaf verifies k >= 1
//! adjacent native proofs, then folds as today. Default OFF.
//!
//! The planner is CPU-only and proof-format neutral until wired. It changes leaf
//! identities, digests and the root, so producer and receiver must read the same
//! policy (as with `STWO_RV64_FOLD_ARITY`).
//!
//! Flag: `STWO_RV64_M9_LEAF_FANIN`:
//!   - unset, 0 or 1: off (exactly `ready_dag.Plan.initArity`);
//!   - 2..4: the largest group size.
//! Companion: `STWO_RV64_M9_LEAF_FANIN_POLICY`: `same` (default: a group holds
//! copies of one native class, so the VK set is bounded by classes x k) or
//! `kind` (CPU-only or truth-only mixes). Any other value fails closed.
//!
//! Cost model: a node's raw rows per variable component are the SUM of its
//! children's verification rows.
//!   - Folds: measured to 0.2% with zero intercept on both M7 D2 receipts.
//!   - k-leaves: the same verifier code path [E].
//! A node is padded per component to a power of two, and the policy caps each
//! component's log (blake_g_gate stays at today's fold envelope, 2^23) plus the
//! whole node's cells. Grouping is a contiguous DP that minimises
//! padded leaf cells + the cost of verifying the group's proof in its parent.
//! See scripts/rv64_m9_leaf_fanin_model.py (mirror) and
//! design/riscv-proving-stack/rv64-m9-fewer-leaves.md.
//!
//! Statement shape: a k-leaf's public statement is `node_summary_v3.combine`
//! of its k native summaries, the same adjacency, bus, mass and counter
//! equalities a fold enforces, applied in-circuit to native children.
//! - Each native proof keeps its own Fiat-Shamir channel.
//! - The leaf's class identity binds (version, k, ordered child class tags).
//!   It must be a T_rec / vk_table member.
//! - The policy words join the topology fingerprint.
const std = @import("std");
const ready_dag = @import("ready_dag.zig");

pub const flag_env = "STWO_RV64_M9_LEAF_FANIN";
pub const policy_env = "STWO_RV64_M9_LEAF_FANIN_POLICY";
pub const max_group = 4;
pub const STATEMENT_VERSION: u32 = 1;

/// Variable components in component_list order (eq, qm31_ops, triple_xor,
/// m_31_to_u_32, blake_g_gate); the six fixed lookup tables are FIXED_CELLS.
pub const Rows = [5]u64;
/// MAIN + 2x-QM31 INTER + gate preprocessed per padded row
/// (component_list.zig component_facts; scripts/rv64_m6_diet_receipt.py).
pub const width = [5]u64{ 12, 28, 73, 31, 167 };
pub const FIXED_CELLS: u64 = 10 * (1 << 16) + 80 * (1 << 20) + 9 * (1 << 8) + 9 * (1 << 14) + 9 * (1 << 18) + 9 * (1 << 16);

pub fn plog(n: u64) u6 {
    if (n <= 1) return 0;
    return @intCast(64 - @clz(n - 1));
}
pub fn cells(rows: Rows) u64 {
    var total: u64 = FIXED_CELLS;
    for (rows, width) |r, w| total += w * (@as(u64, 1) << plog(r));
    return total;
}
pub fn unpaddedCells(rows: Rows) u64 {
    var total: u64 = 0;
    for (rows, width) |r, w| total += w * r;
    return total;
}
pub fn maxLog(rows: Rows) u6 {
    var m: u6 = 0;
    for (rows) |r| m = @max(m, plog(r));
    return m;
}
fn add(a: Rows, b: Rows) Rows {
    var out: Rows = undefined;
    for (&out, a, b) |*o, x, y| o.* = x + y;
    return out;
}

/// Rows to verify one recursion proof as a fold child, by the child's largest
/// padded log [D]:
/// - 23: fold4 / 4;
/// - 22: the 4-truth fold / 4;
/// - 20: fold17 minus its L22 child.
/// All from SRC_D2. 21 is interpolated, 24 is extrapolated by one FRI layer and
/// one path level, and 19 floors at 20 [E].
pub fn childRows(child_log: u6) Rows {
    const c20 = Rows{ 12874, 1554863, 168190, 308160, 1681900 };
    const c22 = Rows{ 14145, 1674037, 186346, 344464, 1863460 };
    const c23 = Rows{ 14261, 1750349, 194178, 358416, 1941780 };
    return switch (@max(child_log, 19)) {
        19, 20 => c20,
        21 => blk: {
            var out: Rows = undefined;
            for (&out, c20, c22) |*o, a, b| o.* = (a + b) / 2;
            break :blk out;
        },
        22 => c22,
        23 => c23,
        else => blk: {
            var out: Rows = undefined;
            for (&out, c22, c23) |*o, b, c| o.* = 2 * c - b;
            break :blk out;
        },
    };
}

/// One native proof as the planner sees it.
/// - `class`: an opaque native verifier class tag (equal tags mean equal
///   verifier circuits).
/// - `cpu`: the family kind.
/// - `rows`: its predicted verification rows (conservative: the class maximum).
pub const Native = struct { class: u32, cpu: bool, rows: Rows };

pub const Grouping = enum { same_class, same_kind };
pub const Policy = struct {
    max_group: u8 = 1,
    grouping: Grouping = .same_class,
    /// Per-component padded log caps. Default: blake_g_gate (about 77% of node
    /// cells) stays at today's fold envelope, and the cheap components may
    /// reach 2^24.
    caps: [5]u6 = .{ 24, 24, 24, 24, 23 },
    /// Whole-node padded cells. 2.2 G is about 26 GB at today's 11.8 B/cell,
    /// under the 28 GiB gate [E].
    cell_cap: u64 = 2_200_000_000,
    /// Headroom on predicted rows, in permille.
    margin_permille: u32 = 30,
    fold_arity: usize = 4,

    pub fn enabled(self: Policy) bool {
        return self.max_group >= 2;
    }
    /// Producer and receiver must agree: these words join the topology fingerprint.
    pub fn words(self: Policy) [10]u32 {
        var out: [10]u32 = undefined;
        out[0] = 0x4d39_4c46; // "M9LF"
        out[1] = STATEMENT_VERSION;
        out[2] = self.max_group;
        out[3] = @intFromEnum(self.grouping);
        for (out[4..9], self.caps) |*o, c| o.* = c;
        out[9] = @intCast(self.fold_arity);
        return out;
    }
    pub fn fits(self: Policy, rows: Rows) bool {
        var padded: Rows = undefined;
        for (&padded, rows) |*p, r| p.* = std.math.divCeil(u64, r * (1000 + self.margin_permille), 1000) catch unreachable;
        for (padded, self.caps) |r, c| if (plog(r) > c) return false;
        return cells(padded) <= self.cell_cap;
    }
};

pub const PolicyError = error{InvalidLeafFanin};

/// Fail-closed parse of the two values; `null` text means unset.
pub fn parsePolicy(fanin: ?[]const u8, grouping: ?[]const u8) PolicyError!Policy {
    var policy = Policy{};
    if (fanin) |text| {
        const k = std.fmt.parseInt(u8, text, 10) catch return error.InvalidLeafFanin;
        if (k > max_group) return error.InvalidLeafFanin;
        policy.max_group = @max(k, 1);
    }
    if (grouping) |text| {
        if (std.mem.eql(u8, text, "same")) policy.grouping = .same_class else if (std.mem.eql(u8, text, "kind")) policy.grouping = .same_kind else return error.InvalidLeafFanin;
    }
    return policy;
}

pub fn policyFromEnv() PolicyError!Policy {
    var buffers: [2][16]u8 = undefined;
    var values: [2]?[]const u8 = .{ null, null };
    for ([_][]const u8{ flag_env, policy_env }, &buffers, &values) |name, *buffer, *value| {
        var fba = std.heap.FixedBufferAllocator.init(buffer);
        value.* = std.process.getEnvVarOwned(fba.allocator(), name) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return error.InvalidLeafFanin,
        };
    }
    return parsePolicy(values[0], values[1]);
}

pub const Group = struct { first: u32, count: u8 };

/// Contiguous grouping DP (mirror: model `group_leaves`). Ties keep the smaller
/// group, so the result is deterministic. k = 1 is always admissible.
pub fn groupNatives(items: []const Native, policy: Policy, out: []Group) error{ InvalidRecursionLeaves, NoSpaceLeft }!usize {
    const n = items.len;
    if (n == 0 or n > ready_dag.max_leaves) return error.InvalidRecursionLeaves;
    var best: [ready_dag.max_leaves + 1]u64 = undefined;
    var choice: [ready_dag.max_leaves + 1]u8 = undefined;
    best[0] = 0;
    for (1..n + 1) |end| {
        best[end] = std.math.maxInt(u64);
        var rows: Rows = @splat(0);
        const kmax = @min(@as(usize, @max(policy.max_group, 1)), end);
        for (1..kmax + 1) |k| {
            const item = items[end - k];
            rows = add(rows, item.rows);
            if (k >= 2) {
                const last = items[end - 1];
                const same = switch (policy.grouping) {
                    .same_class => item.class == last.class and item.cpu == last.cpu,
                    .same_kind => item.cpu == last.cpu,
                };
                if (!same or !policy.fits(rows)) break;
            }
            const cost = best[end - k] + cells(rows) + unpaddedCells(childRows(maxLog(rows)));
            if (cost < best[end]) {
                best[end] = cost;
                choice[end] = @intCast(k);
            }
        }
    }
    var count: usize = 0;
    var end = n;
    while (end > 0) : (count += 1) end -= choice[end];
    if (count > out.len) return error.NoSpaceLeft;
    end = n;
    var i = count;
    while (end > 0) {
        i -= 1;
        const k = choice[end];
        out[i] = .{ .first = @intCast(end - k), .count = k };
        end -= k;
    }
    return count;
}

pub const PlanError = error{ InvalidRecursionLeaves, InvalidRecursiveFoldArity, NoSpaceLeft, LeafFaninNodeOverCapacity };

/// Groups + the unchanged streaming carry over the groups. `dag` leaf ordinal i
/// is group i; `nativeRange` maps any node back to native proof ordinals.
pub const FaninPlan = struct {
    groups: [ready_dag.max_leaves]Group = undefined,
    group_count: usize = 0,
    natives: usize = 0,
    dag: ready_dag.Plan = undefined,
    rows: [ready_dag.max_nodes]Rows = undefined,

    pub fn init(items: []const Native, policy: Policy) PlanError!FaninPlan {
        var self = FaninPlan{ .natives = items.len };
        if (policy.enabled()) {
            self.group_count = try groupNatives(items, policy, &self.groups);
        } else {
            if (items.len == 0 or items.len > ready_dag.max_leaves) return error.InvalidRecursionLeaves;
            for (0..items.len) |i| self.groups[i] = .{ .first = @intCast(i), .count = 1 };
            self.group_count = items.len;
        }
        self.dag = try ready_dag.Plan.initArity(self.group_count, policy.fold_arity);
        // Children precede parents, so one forward sweep fills every node's rows.
        for (0..self.dag.count) |id| {
            const node = self.dag.nodes[id];
            var rows: Rows = @splat(0);
            if (node.isLeaf()) {
                const g = self.groups[node.first_leaf];
                for (items[g.first..][0..g.count]) |item| rows = add(rows, item.rows);
            } else for (node.kids()) |kid| {
                rows = add(rows, childRows(maxLog(self.rows[kid])));
            }
            self.rows[id] = rows;
            // Fail closed: a node outside the envelope is a planning error, not a
            // silent 2^24 padding. A single native (k = 1) is today's leaf and is
            // exempt.
            const single = node.isLeaf() and self.groups[node.first_leaf].count == 1;
            if (policy.enabled() and !single and !policy.fits(rows)) return error.LeafFaninNodeOverCapacity;
        }
        return self;
    }
    pub fn nativeRange(self: *const FaninPlan, id: usize) struct { first: usize, count: usize } {
        const node = self.dag.nodes[id];
        const first = self.groups[node.first_leaf];
        const last = self.groups[node.first_leaf + node.leaf_count - 1];
        return .{ .first = first.first, .count = last.first + last.count - first.first };
    }
    pub fn totalCells(self: *const FaninPlan) u64 {
        var total: u64 = 0;
        for (self.rows[0..self.dag.count]) |rows| total += cells(rows);
        return total;
    }
    pub fn maxNodeCells(self: *const FaninPlan) u64 {
        var m: u64 = 0;
        for (self.rows[0..self.dag.count]) |rows| m = @max(m, cells(rows));
        return m;
    }
};

/// The k-leaf's statement shape. `classDigest` is position independent: it is
/// the leaf circuit class, a T_rec member.
pub const StatementShape = struct {
    k: u8,
    first_native: u32,
    class_tags: [max_group]u32 = @splat(0),

    pub fn of(plan: *const FaninPlan, items: []const Native, group: usize) StatementShape {
        const g = plan.groups[group];
        var self = StatementShape{ .k = g.count, .first_native = g.first };
        for (items[g.first..][0..g.count], 0..) |item, i| self.class_tags[i] = item.class;
        return self;
    }
    pub fn classDigest(self: StatementShape) [32]u8 {
        var h = std.crypto.hash.blake2.Blake2s256.init(.{});
        h.update("rv64-m9-leaf-fanin/class/v1");
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, STATEMENT_VERSION, .little);
        h.update(&buf);
        h.update(&[_]u8{self.k});
        for (self.class_tags[0..self.k]) |tag| {
            std.mem.writeInt(u32, &buf, tag, .little);
            h.update(&buf);
        }
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
};

/// Host mirror of the adjacency part of `node_summary_v3.combine` for native
/// children: each child is one native proof, the children are consecutive, and
/// the output spans them. The circuit enforces the full combine; this is the
/// planner-side precondition checked before a k-leaf is dispatched.
pub const Span = struct { lo: u32, hi: u32, count: u32 };
pub fn combineSpans(children: []const Span) error{ InvalidFoldArity, NonAdjacentNativeChildren }!Span {
    if (children.len < 2 or children.len > max_group) return error.InvalidFoldArity;
    var out = Span{ .lo = children[0].lo, .hi = children[0].hi, .count = 0 };
    for (children, 0..) |child, i| {
        if (child.count != 1 or child.hi < child.lo) return error.NonAdjacentNativeChildren;
        if (i > 0 and child.lo != out.hi + 1) return error.NonAdjacentNativeChildren;
        out.hi = child.hi;
        out.count += 1;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Tests: the 15 basket shapes and the receipts' measured rows.

/// Native verification rows [M]. These are the raw RECURSION_NODE_SHAPE rows of
/// single-proof leaves in
/// vectors/reports/rv64-m7-20261105/d2-composed/combined-d2-package/
/// {24628607,26235156}-combined-d2-coalesce-v1/producer.stderr.
/// The `cpu` row is the maximum over 10 full CPU leaves.
pub const fixture = struct {
    pub const cpu = Native{ .class = 1, .cpu = true, .rows = .{ 179654, 5533212, 337632, 875134, 3376320 } };
    pub const cpu_tail = Native{ .class = 2, .cpu = true, .rows = .{ 139759, 3236107, 201144, 551210, 2011440 } };
    pub const t_a = Native{ .class = 10, .cpu = false, .rows = .{ 7000, 4085155, 228312, 438836, 2283120 } };
    pub const t_b = Native{ .class = 11, .cpu = false, .rows = .{ 5012, 3252622, 273632, 536616, 2736320 } };
    pub const t_c = Native{ .class = 12, .cpu = false, .rows = .{ 5012, 2575364, 226520, 442500, 2265200 } };
    pub const t_d = Native{ .class = 13, .cpu = false, .rows = .{ 4430, 3668414, 278680, 546466, 2786800 } };
    pub const t_s = Native{ .class = 14, .cpu = false, .rows = .{ 4234, 790279, 80000, 150016, 800000 } };

    pub const Shape = struct {
        block: u32,
        segments: u16,
        m3_truths: u16,
        tail: bool,
        base_nodes: u16,
        fanin_leaves: u16,
        fanin_nodes: u16,
    };
    /// segments and m3_truths are [M] (rv64-m3-20261104/summary.json).
    /// The coalesced truth roster is 7 family proofs, plus max(0, m3 - 10) split
    /// t_a proofs [E]. The expected counts come from the model mirror (model.json).
    pub const basket = [_]Shape{
        .{ .block = 26235156, .segments = 4, .m3_truths = 7, .tail = false, .base_nodes = 15, .fanin_leaves = 7, .fanin_nodes = 10 },
        .{ .block = 24647140, .segments = 6, .m3_truths = 9, .tail = true, .base_nodes = 17, .fanin_leaves = 9, .fanin_nodes = 12 },
        .{ .block = 24628607, .segments = 7, .m3_truths = 10, .tail = true, .base_nodes = 19, .fanin_leaves = 9, .fanin_nodes = 12 },
        .{ .block = 25229957, .segments = 7, .m3_truths = 10, .tail = true, .base_nodes = 19, .fanin_leaves = 9, .fanin_nodes = 12 },
        .{ .block = 24628608, .segments = 10, .m3_truths = 10, .tail = true, .base_nodes = 23, .fanin_leaves = 11, .fanin_nodes = 15 },
        .{ .block = 24626900, .segments = 12, .m3_truths = 8, .tail = true, .base_nodes = 26, .fanin_leaves = 12, .fanin_nodes = 16 },
        .{ .block = 24697070, .segments = 14, .m3_truths = 17, .tail = true, .base_nodes = 38, .fanin_leaves = 16, .fanin_nodes = 21 },
        .{ .block = 24697073, .segments = 15, .m3_truths = 13, .tail = true, .base_nodes = 34, .fanin_leaves = 14, .fanin_nodes = 19 },
        .{ .block = 26235168, .segments = 28, .m3_truths = 21, .tail = true, .base_nodes = 62, .fanin_leaves = 24, .fanin_nodes = 33 },
        .{ .block = 25229955, .segments = 30, .m3_truths = 19, .tail = true, .base_nodes = 62, .fanin_leaves = 24, .fanin_nodes = 33 },
        .{ .block = 24628590, .segments = 38, .m3_truths = 18, .tail = true, .base_nodes = 71, .fanin_leaves = 28, .fanin_nodes = 38 },
        .{ .block = 25229951, .segments = 40, .m3_truths = 18, .tail = true, .base_nodes = 74, .fanin_leaves = 29, .fanin_nodes = 39 },
        .{ .block = 24628595, .segments = 42, .m3_truths = 24, .tail = true, .base_nodes = 84, .fanin_leaves = 32, .fanin_nodes = 43 },
        .{ .block = 24628611, .segments = 45, .m3_truths = 22, .tail = true, .base_nodes = 85, .fanin_leaves = 32, .fanin_nodes = 43 },
        .{ .block = 26235159, .segments = 49, .m3_truths = 26, .tail = true, .base_nodes = 97, .fanin_leaves = 36, .fanin_nodes = 48 },
    };
    pub fn natives(shape: Shape, out: []Native) []Native {
        var n: usize = 0;
        const full = if (shape.tail) shape.segments - 1 else shape.segments;
        for (0..full) |_| {
            out[n] = cpu;
            n += 1;
        }
        if (shape.tail) {
            out[n] = cpu_tail;
            n += 1;
        }
        const extra = if (shape.m3_truths > 10) shape.m3_truths - 10 else 0;
        for (0..3 + extra) |_| {
            out[n] = t_a;
            n += 1;
        }
        for ([_]Native{ t_b, t_c, t_d, t_s }) |t| {
            out[n] = t;
            n += 1;
        }
        return out[0..n];
    }
};

test "leaf fanin: off reproduces ready_dag initArity node identities on all 15 basket shapes" {
    var buf: [ready_dag.max_leaves]Native = undefined;
    for (fixture.basket) |shape| {
        const items = fixture.natives(shape, &buf);
        const plan = try FaninPlan.init(items, .{});
        const reference = try ready_dag.Plan.initArity(items.len, 4);
        try std.testing.expectEqual(reference.count, plan.dag.count);
        try std.testing.expectEqual(reference.root, plan.dag.root);
        for (reference.nodes[0..reference.count], plan.dag.nodes[0..plan.dag.count]) |a, b| {
            try std.testing.expectEqual(a.first_leaf, b.first_leaf);
            try std.testing.expectEqual(a.leaf_count, b.leaf_count);
            try std.testing.expectEqualSlices(usize, a.kids(), b.kids());
        }
        try std.testing.expectEqual(@as(usize, shape.base_nodes), plan.dag.count);
    }
}

test "leaf fanin: cost function reproduces the M7 D2 receipts' padded cells" {
    var buf: [ready_dag.max_leaves]Native = undefined;
    // derived-recursive-cells.json: 24628607 = 21658004224 (exact rows); 26235156 = 17844864768
    // (the planner's conservative max-CPU rows pad identically except one eq column: 49152 cells).
    const a = try FaninPlan.init(fixture.natives(fixture.basket[2], &buf), .{});
    try std.testing.expectEqual(@as(u64, 21658004224), a.totalCells());
    const b = try FaninPlan.init(fixture.natives(fixture.basket[0], &buf), .{});
    try std.testing.expect(b.totalCells() - 17844864768 <= 49152);
}

test "leaf fanin: k-grouping on all 15 basket shapes is covering, ordered, homogeneous, in envelope, and cuts nodes" {
    var buf: [ready_dag.max_leaves]Native = undefined;
    const policy = try parsePolicy("4", "same");
    for (fixture.basket) |shape| {
        const items = fixture.natives(shape, &buf);
        const plan = try FaninPlan.init(items, policy);
        // Expected counts from the model mirror.
        try std.testing.expectEqual(@as(usize, shape.fanin_leaves), plan.group_count);
        try std.testing.expectEqual(@as(usize, shape.fanin_nodes), plan.dag.count);
        try std.testing.expect(plan.dag.count < shape.base_nodes);
        var next: usize = 0;
        for (plan.groups[0..plan.group_count], 0..) |g, i| {
            try std.testing.expectEqual(next, @as(usize, g.first));
            try std.testing.expect(g.count >= 1 and g.count <= policy.max_group);
            for (items[g.first..][0..g.count]) |item| try std.testing.expectEqual(items[g.first].class, item.class);
            if (g.count >= 2) try std.testing.expect(policy.fits(plan.rows[blk: {
                for (plan.dag.nodes[0..plan.dag.count], 0..) |node, id| if (node.isLeaf() and node.first_leaf == i) break :blk id;
                unreachable;
            }]));
            next += g.count;
        }
        try std.testing.expectEqual(items.len, next);
        const root = plan.nativeRange(plan.dag.root);
        try std.testing.expectEqual(@as(usize, 0), root.first);
        try std.testing.expectEqual(items.len, root.count);
        try std.testing.expect(plan.maxNodeCells() <= policy.cell_cap);
        // Every fold is still a today-sized fold (blake_g_gate <= 2^23).
        for (plan.rows[0..plan.dag.count]) |rows| try std.testing.expect(plog(rows[4]) <= 23);
        // Fewer cells than the one-native-per-leaf plan.
        const base = try FaninPlan.init(items, .{});
        try std.testing.expect(plan.totalCells() < base.totalCells());
    }
}

test "leaf fanin: groups CPU pairs and t_a triples, never CPU with truth" {
    var buf: [ready_dag.max_leaves]Native = undefined;
    const items = fixture.natives(fixture.basket[14], &buf); // 26235159
    const plan = try FaninPlan.init(items, try parsePolicy("4", "same"));
    for (plan.groups[0..plan.group_count]) |g| {
        const first = items[g.first];
        if (first.class == fixture.cpu.class) try std.testing.expect(g.count <= 2);
        if (first.class == fixture.t_a.class) try std.testing.expect(g.count <= 3);
        for (items[g.first..][0..g.count]) |item| try std.testing.expectEqual(first.cpu, item.cpu);
    }
    // 3 CPU proofs exceed the blake 2^23 envelope (3 x 3.38M rows).
    var three = fixture.cpu.rows;
    for (0..2) |_| three = add(three, fixture.cpu.rows);
    try std.testing.expect(!(Policy{}).fits(three));
    // The all-2^23 envelope cannot even pair CPU proofs (qm31_ops 11.1M rows).
    const env23 = Policy{ .max_group = 4, .caps = .{ 23, 23, 23, 23, 23 } };
    try std.testing.expect(!env23.fits(add(fixture.cpu.rows, fixture.cpu.rows)));
    try std.testing.expect((Policy{}).fits(add(fixture.cpu.rows, fixture.cpu.rows)));
}

test "leaf fanin: env policy parse fails closed" {
    try std.testing.expect(!(try parsePolicy(null, null)).enabled());
    try std.testing.expect(!(try parsePolicy("0", null)).enabled());
    try std.testing.expect(!(try parsePolicy("1", null)).enabled());
    try std.testing.expectEqual(@as(u8, 3), (try parsePolicy("3", "kind")).max_group);
    try std.testing.expectEqual(Grouping.same_kind, (try parsePolicy("3", "kind")).grouping);
    try std.testing.expectError(error.InvalidLeafFanin, parsePolicy("5", null));
    try std.testing.expectError(error.InvalidLeafFanin, parsePolicy("x", null));
    try std.testing.expectError(error.InvalidLeafFanin, parsePolicy("2", "mixed"));
    try std.testing.expect(!std.mem.eql(u32, &(try parsePolicy("2", null)).words(), &(try parsePolicy("3", null)).words()));
}

test "leaf fanin: statement shape binds k and ordered child classes; spans must be adjacent" {
    var buf: [ready_dag.max_leaves]Native = undefined;
    const items = fixture.natives(fixture.basket[2], &buf);
    const plan = try FaninPlan.init(items, try parsePolicy("4", "same"));
    const pair = StatementShape.of(&plan, items, 0);
    try std.testing.expectEqual(@as(u8, 2), pair.k);
    var other = pair;
    other.first_native = 2; // the same class elsewhere in the block: same VK
    try std.testing.expectEqualSlices(u8, &pair.classDigest(), &other.classDigest());
    var single = pair;
    single.k = 1;
    try std.testing.expect(!std.mem.eql(u8, &pair.classDigest(), &single.classDigest()));
    var swapped = StatementShape{ .k = 2, .first_native = 0, .class_tags = .{ 10, 11, 0, 0 } };
    const forward = swapped.classDigest();
    swapped.class_tags = .{ 11, 10, 0, 0 };
    try std.testing.expect(!std.mem.eql(u8, &forward, &swapped.classDigest()));

    const ok = try combineSpans(&.{ .{ .lo = 4, .hi = 4, .count = 1 }, .{ .lo = 5, .hi = 5, .count = 1 } });
    try std.testing.expectEqual(Span{ .lo = 4, .hi = 5, .count = 2 }, ok);
    try std.testing.expectError(error.NonAdjacentNativeChildren, combineSpans(&.{ .{ .lo = 4, .hi = 4, .count = 1 }, .{ .lo = 6, .hi = 6, .count = 1 } }));
    try std.testing.expectError(error.NonAdjacentNativeChildren, combineSpans(&.{ .{ .lo = 4, .hi = 4, .count = 1 }, .{ .lo = 4, .hi = 4, .count = 1 } }));
    try std.testing.expectError(error.InvalidFoldArity, combineSpans(&.{.{ .lo = 4, .hi = 4, .count = 1 }}));
}

test "leaf fanin: over-envelope fold fails closed instead of padding to 2^24" {
    // Hypothetical native with 2.1M blake rows: pairs fit, but 4 L24 children
    // in a fold would exceed 2^23 blake rows if the child cost were larger.
    // Pin the error path with a tight cell cap.
    var buf: [ready_dag.max_leaves]Native = undefined;
    const items = fixture.natives(fixture.basket[14], &buf);
    var policy = try parsePolicy("4", "same");
    policy.cell_cap = 2_000_000_000; // below the 2-CPU leaf (2.11 G): CPU stays single
    const plan = try FaninPlan.init(items, policy);
    for (plan.groups[0..plan.group_count]) |g| if (items[g.first].cpu) try std.testing.expectEqual(@as(u8, 1), g.count);
    policy.caps[4] = 22; // a fold of 4 L23 children needs 2^23 blake rows
    try std.testing.expectError(error.LeafFaninNodeOverCapacity, FaninPlan.init(items, policy));
}
