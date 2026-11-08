//! Source-derived signed additive cover for bounded composition residency.
//! A term retains its ORIGINAL constraint index/RLC power and denominator.
//! Physical columns deduplicate masks at different trace-row offsets.
const std = @import("std");
const C = @import("composition_codegen.zig");
pub const Column = struct { tree: u8, column: u32 };
pub const Term = struct { root: u32, node: u32, negative: bool };
pub const Group = struct { first: u32, end: u32, columns: []u32 };
pub const Plan = struct {
    source: [32]u8,
    identity: [32]u8,
    column_cap: u32,
    columns: []Column,
    input_columns: []u32,
    terms: []Term,
    groups: []Group,
    union_columns: usize,
    pub fn deinit(self: *Plan, a: std.mem.Allocator) void {
        for (self.groups) |g| a.free(g.columns);
        a.free(self.groups);
        a.free(self.columns);
        a.free(self.input_columns);
        a.free(self.terms);
        self.* = undefined;
    }
    pub fn validate(self: *const Plan, a: std.mem.Allocator, program: *const C.Program) !void {
        var expected = try init(a, program, self.column_cap);
        defer expected.deinit(a);
        if (!std.mem.eql(u8, &self.identity, &expected.identity) or !std.mem.eql(u8, &self.source, &expected.source) or !std.meta.eql(self.columns.len, expected.columns.len) or self.groups.len != expected.groups.len or self.terms.len != expected.terms.len or self.input_columns.len != expected.input_columns.len or self.union_columns != expected.union_columns) return error.InvalidSparseCompositionPlan;
        for (self.terms, expected.terms) |x, y| if (!std.meta.eql(x, y)) return error.InvalidSparseCompositionPlan;
        for (self.columns, expected.columns) |x, y| if (!std.meta.eql(x, y)) return error.InvalidSparseCompositionPlan;
        if (!std.mem.eql(u32, self.input_columns, expected.input_columns)) return error.InvalidSparseCompositionPlan;
        for (self.groups, expected.groups) |x, y| if (x.first != y.first or x.end != y.end or !std.mem.eql(u32, x.columns, y.columns)) return error.InvalidSparseCompositionPlan;
    }
};
fn count(bits: []const u64) usize {
    var n: usize = 0;
    for (bits) |word| n += @popCount(word);
    return n;
}
fn merge(out: []u64, x: []const u64, y: []const u64) void {
    for (out, x, y) |*z, a, b| z.* = a | b;
}
fn ids(a: std.mem.Allocator, bits: []const u64) ![]u32 {
    const out = try a.alloc(u32, count(bits));
    var n: usize = 0;
    for (bits, 0..) |word, block| {
        var left = word;
        while (left != 0) {
            const bit = @ctz(left);
            out[n] = @intCast(block * 64 + bit);
            n += 1;
            left &= left - 1;
        }
    }
    return out;
}
fn finishGroup(a: std.mem.Allocator, groups: *std.ArrayList(Group), first: usize, end: usize, bits: []const u64) !void {
    const columns = try ids(a, bits);
    errdefer a.free(columns);
    try groups.append(a, .{ .first = @intCast(first), .end = @intCast(end), .columns = columns });
}
pub fn init(a: std.mem.Allocator, p: *const C.Program, cap: u32) !Plan {
    try p.validate();
    if (cap == 0 or cap > 65536) return error.InvalidSparseCompositionCap;
    var columns: std.ArrayList(Column) = .empty;
    defer columns.deinit(a);
    var map: std.AutoHashMap(u64, u32) = .init(a);
    defer map.deinit();
    const input_columns = try a.alloc(u32, p.inputs.len);
    errdefer a.free(input_columns);
    for (p.inputs, input_columns) |input, *id| {
        const key = (@as(u64, input.tree) << 32) | input.column;
        const g = try map.getOrPut(key);
        if (!g.found_existing) {
            g.value_ptr.* = @intCast(columns.items.len);
            try columns.append(a, .{ .tree = input.tree, .column = input.column });
        }
        id.* = g.value_ptr.*;
    }
    const limbs = (columns.items.len + 63) / 64;
    const dependencies = try a.alloc(u64, try std.math.mul(usize, p.nodes.len, limbs));
    defer a.free(dependencies);
    @memset(dependencies, 0);
    for (p.nodes, 0..) |node, i| {
        const out = dependencies[i * limbs ..][0..limbs];
        switch (node.op) {
            .input => {
                const id = input_columns[node.value];
                out[id / 64] |= @as(u64, 1) << @intCast(id % 64);
            },
            .add, .sub, .mul => merge(out, dependencies[node.lhs * limbs ..][0..limbs], dependencies[node.rhs * limbs ..][0..limbs]),
            .neg => @memcpy(out, dependencies[node.lhs * limbs ..][0..limbs]),
            .constant, .parameter => {},
            else => return error.UnsupportedSparseCompositionOp,
        }
    }
    var terms: std.ArrayList(Term) = .empty;
    defer terms.deinit(a);
    var stack: std.ArrayList(Term) = .empty;
    defer stack.deinit(a);
    for (p.roots, 0..) |node, root| {
        try stack.append(a, .{ .root = @intCast(root), .node = node, .negative = false });
        while (stack.pop()) |term| {
            if (terms.items.len > 1 << 20) return error.SparseCompositionTermLimit;
            const bits = dependencies[term.node * limbs ..][0..limbs];
            if (count(bits) <= cap) {
                try terms.append(a, term);
                continue;
            }
            const n = p.nodes[term.node];
            switch (n.op) {
                .add, .sub => {
                    try stack.append(a, .{ .root = term.root, .node = n.rhs, .negative = term.negative != (n.op == .sub) });
                    try stack.append(a, .{ .root = term.root, .node = n.lhs, .negative = term.negative });
                },
                .neg => try stack.append(a, .{ .root = term.root, .node = n.lhs, .negative = !term.negative }),
                else => return error.DenseNonlinearCompositionRoot,
            }
        }
    }
    var groups: std.ArrayList(Group) = .empty;
    errdefer {
        for (groups.items) |g| a.free(g.columns);
        groups.deinit(a);
    }
    const held = try a.alloc(u64, limbs);
    defer a.free(held);
    @memset(held, 0);
    const trial = try a.alloc(u64, limbs);
    defer a.free(trial);
    const all = try a.alloc(u64, limbs);
    defer a.free(all);
    @memset(all, 0);
    var first: usize = 0;
    for (terms.items, 0..) |term, i| {
        const bits = dependencies[term.node * limbs ..][0..limbs];
        merge(trial, held, bits);
        if (count(trial) > cap) {
            try finishGroup(a, &groups, first, i, held);
            first = i;
            @memcpy(held, bits);
        } else @memcpy(held, trial);
        for (all, bits) |*dst, src| dst.* |= src;
    }
    if (first < terms.items.len) try finishGroup(a, &groups, first, terms.items.len, held);
    const cols = try columns.toOwnedSlice(a);
    errdefer a.free(cols);
    const ts = try terms.toOwnedSlice(a);
    errdefer a.free(ts);
    const gs = try groups.toOwnedSlice(a);
    var result = Plan{ .source = p.identity, .identity = undefined, .column_cap = cap, .columns = cols, .input_columns = input_columns, .terms = ts, .groups = gs, .union_columns = count(all) };
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64/signed-sparse-composition/v1");
    hash.update(&p.identity);
    hash.update(&(try C.identity(p)));
    hash.update(@embedFile("composition_sparse.zig"));
    hash.update(@embedFile("composition_sparse_codegen.zig"));
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, cap, .little);
    hash.update(&bytes);
    for (ts) |t| {
        std.mem.writeInt(u32, bytes[0..4], t.root, .little);
        std.mem.writeInt(u32, bytes[4..8], t.node, .little);
        hash.update(&bytes);
        hash.update(&.{@intFromBool(t.negative)});
    }
    for (gs) |g| {
        std.mem.writeInt(u32, bytes[0..4], g.first, .little);
        std.mem.writeInt(u32, bytes[4..8], g.end, .little);
        hash.update(&bytes);
        for (g.columns) |id| {
            std.mem.writeInt(u32, bytes[0..4], id, .little);
            hash.update(bytes[0..4]);
        }
    }
    result.identity = hash.finalResult();
    return result;
}

pub const Load = struct { column: u32, slot: u32 };
pub const Step = struct { loads: []Load, column_slots: []u32 };
pub const Cache = struct {
    plan_identity: [32]u8,
    slots: u32,
    steps: []Step,
    fills: usize,
    pub fn validate(self: *const Cache, a: std.mem.Allocator, p: *const Plan) !void {
        if (!std.mem.eql(u8, &self.plan_identity, &p.identity)) return error.InvalidSparseCachePlan;
        var expected = try cache(a, p, self.slots);
        defer expected.deinit(a);
        if (self.steps.len != expected.steps.len or self.fills != expected.fills) return error.InvalidSparseCachePlan;
        for (self.steps, expected.steps) |x, y| {
            if (x.loads.len != y.loads.len or !std.mem.eql(u32, x.column_slots, y.column_slots)) return error.InvalidSparseCachePlan;
            for (x.loads, y.loads) |u, v| if (!std.meta.eql(u, v)) return error.InvalidSparseCachePlan;
        }
    }
    pub fn deinit(self: *Cache, a: std.mem.Allocator) void {
        for (self.steps) |step| {
            a.free(step.loads);
            a.free(step.column_slots);
        }
        a.free(self.steps);
        self.* = undefined;
    }
};
/// Offline farthest-next-use eviction. Every group's readers are admitted
/// together before overwriting a slot; no live requested column is evicted.
pub fn cache(a: std.mem.Allocator, p: *const Plan, slots: u32) !Cache {
    if (slots < p.column_cap or slots > 65536) return error.InvalidSparseCacheCap;
    const none = std.math.maxInt(u32);
    const nc = p.columns.len;
    const future = try a.alloc(u32, try std.math.mul(usize, p.groups.len + 1, nc));
    defer a.free(future);
    @memset(future, none);
    var g = p.groups.len;
    while (g != 0) {
        g -= 1;
        @memcpy(future[g * nc ..][0..nc], future[(g + 1) * nc ..][0..nc]);
        for (p.groups[g].columns) |col| future[g * nc + col] = @intCast(g);
    }
    const physical = try a.alloc(u32, slots);
    defer a.free(physical);
    @memset(physical, none);
    const mapping = try a.alloc(u32, nc);
    defer a.free(mapping);
    @memset(mapping, none);
    const wanted = try a.alloc(bool, nc);
    defer a.free(wanted);
    var steps: std.ArrayList(Step) = .empty;
    errdefer {
        for (steps.items) |s| {
            a.free(s.loads);
            a.free(s.column_slots);
        }
        steps.deinit(a);
    }
    var fills: usize = 0;
    for (p.groups, 0..) |group, i| {
        @memset(wanted, false);
        for (group.columns) |col| wanted[col] = true;
        var loads: std.ArrayList(Load) = .empty;
        defer loads.deinit(a);
        for (group.columns) |col| {
            if (mapping[col] != none) continue;
            var selected: ?usize = null;
            var farthest: u32 = 0;
            for (physical, 0..) |occupant, slot| {
                if (occupant == none) {
                    selected = slot;
                    break;
                }
                if (wanted[occupant]) continue;
                const next = future[(i + 1) * nc + occupant];
                if (selected == null or next > farthest) {
                    selected = slot;
                    farthest = next;
                }
            }
            const slot = selected orelse return error.SparseCacheLivenessFailure;
            if (physical[slot] != none) mapping[physical[slot]] = none;
            physical[slot] = col;
            mapping[col] = @intCast(slot);
            try loads.append(a, .{ .column = col, .slot = @intCast(slot) });
            fills += 1;
        }
        const column_slots = try a.dupe(u32, mapping);
        errdefer a.free(column_slots);
        for (group.columns) |col| if (column_slots[col] == none or physical[column_slots[col]] != col) return error.SparseCacheLivenessFailure;
        const owned = try loads.toOwnedSlice(a);
        errdefer a.free(owned);
        try steps.append(a, .{ .loads = owned, .column_slots = column_slots });
    }
    return .{ .plan_identity = p.identity, .slots = slots, .steps = try steps.toOwnedSlice(a), .fills = fills };
}
