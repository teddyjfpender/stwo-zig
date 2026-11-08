//! Concrete OM31-to-M31 polynomial lowering for CPU code generation.
//! It optimizes the receiver-owned DAG; it is never a new constraint authority.
//! Zero/one folding and structural CSE remove basis packing before row work.
const std = @import("std");
const core = @import("stwo_core");
const IR = @import("stwo_prover_engine").air.secure_polynomial_program_v2;
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
pub const InputKind = @import("cpu_inputs.zig").Kind;
pub const Op = enum { constant, input, parameter, add, sub, mul, neg };
pub const Node = struct { op: Op, lhs: u32 = 0, rhs: u32 = 0, value: u32 = 0 };
pub const MAX_NODES = 1 << 20;
const Builder = struct {
    a: std.mem.Allocator,
    nodes: std.ArrayList(Node) = .empty,
    interned: std.AutoHashMap(Node, u32),
    fn init(a: std.mem.Allocator) !Builder {
        var self = Builder{ .a = a, .interned = .init(a) };
        errdefer self.deinit();
        const zero = try self.constant(0);
        const one = try self.constant(1);
        if (zero != 0 or one != 1) return error.InvalidCpuLoweringConstants;
        return self;
    }
    fn deinit(self: *Builder) void {
        self.nodes.deinit(self.a);
        self.interned.deinit();
    }
    fn node(self: *Builder, value: Node) !u32 {
        const entry = try self.interned.getOrPut(value);
        if (entry.found_existing) return entry.value_ptr.*;
        if (self.nodes.items.len == MAX_NODES) return error.CpuLoweringTooWide;
        const index: u32 = @intCast(self.nodes.items.len);
        try self.nodes.append(self.a, value);
        entry.value_ptr.* = index;
        return index;
    }
    fn constant(self: *Builder, value: u32) !u32 {
        return self.node(.{ .op = .constant, .value = value });
    }
    fn known(self: *const Builder, index: u32) ?M {
        const n = self.nodes.items[index];
        return if (n.op == .constant) M.fromCanonical(n.value) else null;
    }
    fn add(self: *Builder, a: u32, b: u32) !u32 {
        if (a == 0) return b;
        if (b == 0) return a;
        const x_node = self.nodes.items[a];
        const y_node = self.nodes.items[b];
        if (x_node.op == .sub and x_node.rhs == b) return x_node.lhs;
        if (y_node.op == .sub and y_node.rhs == a) return y_node.lhs;
        if ((x_node.op == .neg and x_node.lhs == b) or (y_node.op == .neg and y_node.lhs == a)) return 0;
        if (self.known(a)) |x| if (self.known(b)) |y| return self.constant(x.add(y).v);
        return self.node(.{ .op = .add, .lhs = @min(a, b), .rhs = @max(a, b) });
    }
    fn sub(self: *Builder, a: u32, b: u32) !u32 {
        if (b == 0) return a;
        if (a == b) return 0;
        if (a == 0) return self.neg(b);
        const x_node = self.nodes.items[a];
        if (x_node.op == .add) {
            if (x_node.lhs == b) return x_node.rhs;
            if (x_node.rhs == b) return x_node.lhs;
        }
        if (self.known(a)) |x| if (self.known(b)) |y| return self.constant(x.sub(y).v);
        return self.node(.{ .op = .sub, .lhs = a, .rhs = b });
    }
    fn mul(self: *Builder, a: u32, b: u32) !u32 {
        if (a == 0 or b == 0) return 0;
        if (a == 1) return b;
        if (b == 1) return a;
        if (self.known(a)) |x| if (self.known(b)) |y| return self.constant(x.mul(y).v);
        return self.node(.{ .op = .mul, .lhs = @min(a, b), .rhs = @max(a, b) });
    }
    fn neg(self: *Builder, a: u32) !u32 {
        if (self.known(a)) |x| return self.constant(x.neg().v);
        const n = self.nodes.items[a];
        if (n.op == .neg) return n.lhs;
        return self.node(.{ .op = .neg, .lhs = a });
    }
    fn cmul(self: *Builder, a: [2]u32, b: [2]u32) ![2]u32 {
        const ac = try self.mul(a[0], b[0]);
        const bd = try self.mul(a[1], b[1]);
        const cross = try self.mul(try self.add(a[0], a[1]), try self.add(b[0], b[1]));
        return .{ try self.sub(ac, bd), try self.sub(try self.sub(cross, ac), bd) };
    }
    fn cmulNonresidue(self: *Builder, a: [2]u32) ![2]u32 {
        return .{ try self.sub(try self.add(a[0], a[0]), a[1]), try self.add(a[0], try self.add(a[1], a[1])) };
    }
    fn qmul(self: *Builder, a: [4]u32, b: [4]u32) ![4]u32 {
        const ac = try self.cmul(a[0..2].*, b[0..2].*);
        const bd = try self.cmul(a[2..4].*, b[2..4].*);
        const cross = try self.cmul(.{ try self.add(a[0], a[2]), try self.add(a[1], a[3]) }, .{ try self.add(b[0], b[2]), try self.add(b[1], b[3]) });
        const nr = try self.cmulNonresidue(bd);
        return .{ try self.add(ac[0], nr[0]), try self.add(ac[1], nr[1]), try self.sub(try self.sub(cross[0], ac[0]), bd[0]), try self.sub(try self.sub(cross[1], ac[1]), bd[1]) };
    }
    fn omul(self: *Builder, a: [8]u32, b: [8]u32) ![8]u32 {
        const ac = try self.qmul(a[0..4].*, b[0..4].*);
        const bd = try self.qmul(a[4..8].*, b[4..8].*);
        var sum_a: [4]u32 = undefined;
        var sum_b: [4]u32 = undefined;
        for (&sum_a, &sum_b, 0..) |*x, *y, i| {
            x.* = try self.add(a[i], a[i + 4]);
            y.* = try self.add(b[i], b[i + 4]);
        }
        const cross = try self.qmul(sum_a, sum_b);
        const nr_low = try self.cmulNonresidue(bd[2..4].*);
        const nr = [4]u32{ nr_low[0], nr_low[1], bd[0], bd[1] };
        var out: [8]u32 = undefined;
        for (0..4) |i| {
            out[i] = try self.add(ac[i], nr[i]);
            out[i + 4] = try self.sub(try self.sub(cross[i], ac[i]), bd[i]);
        }
        return out;
    }
};

pub const Plan = struct {
    a: std.mem.Allocator,
    source_identity: [32]u8,
    nodes: []Node,
    roots: [][8]u32,
    invariant: []bool,
    kinds: []InputKind,
    parameters: usize,
    pub fn init(a: std.mem.Allocator, source: *const IR.ProgramFor(O), kinds: []const InputKind) !Plan {
        try source.validate();
        if (source.inputs.len != kinds.len) return error.InvalidCpuLoweringInputs;
        var b = try Builder.init(a);
        defer b.deinit();
        const values = try a.alloc([8]u32, source.nodes.len);
        defer a.free(values);
        for (source.nodes, values) |n, *v| {
            v.* = @splat(0);
            switch (n.op) {
                .constant => for (v, source.constants[n.value]) |*out, value| {
                    out.* = try b.constant(value);
                },
                .input => switch (kinds[n.value]) {
                    .zero => {},
                    .base => v[0] = try b.node(.{ .op = .input, .value = 8 * n.value }),
                    .secure => for (v, 0..) |*out, j| {
                        out.* = try b.node(.{ .op = .input, .value = 8 * n.value + @as(u32, @intCast(j)) });
                    },
                },
                .parameter => for (v, 0..) |*out, j| {
                    out.* = try b.node(.{ .op = .parameter, .value = 8 * n.value + @as(u32, @intCast(j)) });
                },
                .add, .sub => for (v, values[n.lhs], values[n.rhs]) |*out, x, y| {
                    out.* = if (n.op == .add) try b.add(x, y) else try b.sub(x, y);
                },
                .mul => v.* = try b.omul(values[n.lhs], values[n.rhs]),
                .neg => for (v, values[n.lhs]) |*out, x| {
                    out.* = try b.neg(x);
                },
                .fraction, .range_fraction => unreachable,
            }
        }
        const roots = try a.alloc([8]u32, source.roots.len);
        errdefer a.free(roots);
        for (roots, source.roots) |*out, root| out.* = values[root];
        // Prune intermediate expressions cancelled by the algebraic folds.
        // Keep zero/one at indices0/1 so emitted sparse coordinates are explicit.
        const keep = try a.alloc(bool, b.nodes.items.len);
        defer a.free(keep);
        @memset(keep, false);
        keep[0] = true;
        keep[1] = true;
        for (roots) |root| for (root) |id| {
            keep[id] = true;
        };
        var reverse = b.nodes.items.len;
        while (reverse != 0) {
            reverse -= 1;
            if (!keep[reverse]) continue;
            const n = b.nodes.items[reverse];
            switch (n.op) {
                .add, .sub, .mul => {
                    keep[n.lhs] = true;
                    keep[n.rhs] = true;
                },
                .neg => keep[n.lhs] = true,
                else => {},
            }
        }
        const remap = try a.alloc(u32, keep.len);
        defer a.free(remap);
        var retained: usize = 0;
        for (keep, 0..) |needed, old| {
            if (!needed) continue;
            var n = b.nodes.items[old];
            switch (n.op) {
                .add, .sub, .mul => {
                    n.lhs = remap[n.lhs];
                    n.rhs = remap[n.rhs];
                },
                .neg => n.lhs = remap[n.lhs],
                else => {},
            }
            remap[old] = @intCast(retained);
            b.nodes.items[retained] = n;
            retained += 1;
        }
        b.nodes.shrinkRetainingCapacity(retained);
        for (roots) |*root| for (root) |*id| {
            id.* = remap[id.*];
        };
        const owned_kinds = try a.dupe(InputKind, kinds);
        errdefer a.free(owned_kinds);
        const invariant = try a.alloc(bool, b.nodes.items.len);
        errdefer a.free(invariant);
        for (b.nodes.items, invariant) |n, *fixed| fixed.* = switch (n.op) {
            .constant, .parameter => true,
            .input => false,
            .neg => invariant[n.lhs],
            .add, .sub, .mul => invariant[n.lhs] and invariant[n.rhs],
        };
        return .{ .a = a, .source_identity = source.identity, .nodes = try b.nodes.toOwnedSlice(a), .roots = roots, .invariant = invariant, .kinds = owned_kinds, .parameters = source.parameters.len };
    }
    pub fn deinit(self: *Plan) void {
        self.a.free(self.nodes);
        self.a.free(self.roots);
        self.a.free(self.invariant);
        self.a.free(self.kinds);
        self.* = undefined;
    }
    pub fn evaluate(self: *const Plan, a: std.mem.Allocator, inputs: []const O, parameters: []const O) ![]O {
        if (inputs.len != self.kinds.len or parameters.len != self.parameters) return error.InvalidCpuLoweringInputs;
        for (inputs, self.kinds) |value, kind| {
            const words = value.toM31Array();
            if (kind == .zero and !value.isZero()) return error.InvalidCpuLoweringInputs;
            if (kind == .base) for (words[1..]) |word| if (!word.isZero()) return error.InvalidCpuLoweringInputs;
        }
        const values = try a.alloc(M, self.nodes.len);
        defer a.free(values);
        for (self.nodes, values) |n, *v| v.* = switch (n.op) {
            .constant => M.fromCanonical(n.value),
            .input => inputs[n.value / 8].toM31Array()[n.value % 8],
            .parameter => parameters[n.value / 8].toM31Array()[n.value % 8],
            .add => values[n.lhs].add(values[n.rhs]),
            .sub => values[n.lhs].sub(values[n.rhs]),
            .mul => values[n.lhs].mul(values[n.rhs]),
            .neg => values[n.lhs].neg(),
        };
        const out = try a.alloc(O, self.roots.len);
        for (out, self.roots) |*v, root| {
            var words: [8]M = undefined;
            for (&words, root) |*word, id| word.* = values[id];
            v.* = O.fromM31Array(words);
        }
        return out;
    }
};
