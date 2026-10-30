//! Cold pruning of the original typed lookup DAG for local-x0 witness work.
//! This is a witness recipe, never new AIR or an alternative proof authority.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const trace = @import("../runner/trace.zig");
const E = @import("x0_native_envelope_v1.zig");
const Runtime = @import("extract/runtime_program.zig");
const Programs = @import("stwo_prover_engine").air.component_prover;
const Hint = @import("x0_local_custody_v1.zig").Hint;
pub const MAX_NODES = 64;
pub const Node = extern struct { op: u32 = 0, lhs: u32 = 0, rhs: u32 = 0, value: u32 = 0 };
pub const Group = extern struct { roots: [13]u32 = @splat(0), predecessor: u32 = 0 };
pub const Recipe = extern struct {
    version: u32 = 1,
    width: u32 = 0,
    node_count: u32 = 0,
    group_count: u32 = 0,
    nodes: [MAX_NODES]Node = @splat(.{}),
    groups: [3]Group = @splat(.{}),
    pub fn derive(a: std.mem.Allocator, family: trace.OpcodeFamily) !Recipe {
        var original = try Runtime.buildLookups(a, family);
        defer original.deinit();
        return fromProgram(a, family, &original);
    }
    pub fn fromProgram(a: std.mem.Allocator, family: trace.OpcodeFamily, p: *const Programs.OwnedLookupPolynomialProgram) !Recipe {
        try p.validate();
        const schedule = try E.schedule(family);
        if (p.column_count != trace.nColumnsForFamily(family)) return error.InvalidX0Plan;
        var result = Recipe{ .width = @intCast(p.column_count), .group_count = schedule.len };
        var roots: [3][13]u32 = undefined;
        const selected = try a.alloc(bool, p.nodes.len);
        defer a.free(selected);
        @memset(selected, false);
        for (schedule.groups[0..schedule.len], 0..) |g, i| {
            const before = p.entries[g.consume];
            const after = p.entries[g.emit];
            if (before.arity != 7 or after.arity != 7) return error.InvalidX0Plan;
            roots[i][0] = after.numerator;
            roots[i][1] = before.values[0];
            roots[i][2] = before.values[1];
            roots[i][3] = after.values[0];
            roots[i][4] = after.values[1];
            @memcpy(roots[i][5..9], before.values[3..7]);
            @memcpy(roots[i][9..13], after.values[3..7]);
            for (roots[i]) |r| selected[r] = true;
            const pred = p.nodes[before.values[2]];
            if (pred.op != .column or pred.value >= p.column_count) return error.InvalidX0Plan;
            result.groups[i].predecessor = pred.value;
        }
        var cursor = p.nodes.len;
        while (cursor > 0) {
            cursor -= 1;
            if (!selected[cursor]) continue;
            const n = p.nodes[cursor];
            switch (n.op) {
                .add, .sub, .mul => {
                    selected[n.lhs] = true;
                    selected[n.rhs] = true;
                },
                .neg => selected[n.lhs] = true,
                else => {},
            }
        }
        const mapping = try a.alloc(u32, p.nodes.len);
        defer a.free(mapping);
        @memset(mapping, std.math.maxInt(u32));
        for (p.nodes, 0..) |n, i| if (selected[i]) {
            if (result.node_count == MAX_NODES) return error.X0PlanCapacity;
            // None of the semantic values may depend on a predecessor cell which this
            // recipe changes; this permits one shared evaluation before normalization.
            if (n.op == .column) for (result.groups[0..result.group_count]) |g| {
                if (n.value == g.predecessor) return error.X0PlanPredecessorDependency;
            };
            const at = result.node_count;
            mapping[i] = at;
            result.nodes[at] = .{ .op = @intFromEnum(n.op), .lhs = if (n.op == .add or n.op == .sub or n.op == .mul or n.op == .neg) mapping[n.lhs] else 0, .rhs = if (n.op == .add or n.op == .sub or n.op == .mul) mapping[n.rhs] else 0, .value = n.value };
            result.node_count += 1;
        };
        for (result.groups[0..result.group_count], 0..) |*g, i| for (&g.roots, roots[i]) |*out, r| {
            out.* = mapping[r];
        };
        return result;
    }
    pub fn apply(self: *const Recipe, physical: []M, hints: []M) !void {
        if (self.version != 1 or self.width != physical.len or self.node_count > MAX_NODES or self.group_count > 3 or hints.len != 2 * self.group_count) return error.InvalidX0Plan;
        var values: [MAX_NODES]M = undefined;
        for (self.nodes[0..self.node_count], 0..) |n, i| {
            values[i] = switch (n.op) {
                0 => blk: {
                    if (n.value >= core.fields.m31.Modulus) return error.InvalidX0Plan;
                    break :blk M.fromCanonical(n.value);
                },
                1 => blk: {
                    if (n.value >= physical.len) return error.InvalidX0Plan;
                    break :blk physical[n.value];
                },
                2, 3, 4 => blk: {
                    if (n.lhs >= i or n.rhs >= i) return error.InvalidX0Plan;
                    break :blk switch (n.op) {
                        2 => values[n.lhs].add(values[n.rhs]),
                        3 => values[n.lhs].sub(values[n.rhs]),
                        else => values[n.lhs].mul(values[n.rhs]),
                    };
                },
                5 => blk: {
                    if (n.lhs >= i) return error.InvalidX0Plan;
                    break :blk values[n.lhs].neg();
                },
                else => return error.InvalidX0Plan,
            };
        }
        for (self.groups[0..self.group_count], 0..) |g, i| {
            for (g.roots) |r| if (r >= self.node_count) return error.InvalidX0Plan;
            const active = values[g.roots[0]].v;
            if (active > 1) return error.InvalidX0ActiveWitness;
            if (active != 0 and values[g.roots[1]].isZero() and values[g.roots[2]].isZero()) {
                for (g.roots[5..13]) |r| if (!values[r].isZero()) return error.NonzeroX0SemanticWitness;
                if (g.predecessor >= physical.len) return error.InvalidX0Plan;
                physical[g.predecessor] = M.zero();
            }
            const hint = if (active == 0) Hint{ .nonzero = M.zero(), .inverse = M.zero() } else try Hint.forAddress(std.math.cast(u1, values[g.roots[3]].v) orelse return error.InvalidX0SpaceWitness, values[g.roots[4]].v);
            hints[2 * i] = hint.nonzero;
            hints[2 * i + 1] = hint.inverse;
        }
    }
};
test "native x0 pruned witness plans preserve exact original tuple roots" {
    const a = std.testing.allocator;
    inline for (comptime std.enums.values(trace.OpcodeFamily)) |family| {
        const plan = try Recipe.derive(a, family);
        try std.testing.expectEqual(trace.nColumnsForFamily(family), plan.width);
        std.debug.print("X0_PLAN family={s} groups={d} nodes={d}\n", .{ @tagName(family), plan.group_count, plan.node_count });
    }
}
