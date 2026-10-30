//! Immutable dependency/routing schedule for the ORIGINAL verifier arithmetic
//! graph. Values are absent; only authenticated graph constants are retained.
const std = @import("std");
pub const Original = @import("../../frontends/riscv/recursion/air/composition_circuit.zig");
pub const Op = enum(u32) { input, constant, add, sub, mul, neg, inverse };
pub const Node = extern struct { op: u32, lhs: u32 = 0, rhs: u32 = 0, input: u32 = 0, constant: [4]u32 = @splat(0) };
pub const Graph = extern struct { node_first: u32, node_count: u32, input_first: u32, input_count: u32, value_word_base: u32, level_first: u32, level_count: u32, output_first: u32, output_count: u32 };
pub const Limits = struct { max_graphs: usize = 64, max_nodes: usize = 4 << 20, max_bytes: usize = 1 << 30 };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    graphs: []Graph,
    graph_ids: [][32]u8,
    nodes: []Node,
    level_nodes: []u32,
    level_offsets: []u32,
    outputs: []u32,
    input_words: usize,
    value_words: usize,
    device_bytes: usize,
    identity: [32]u8,
    pub fn init(backing: std.mem.Allocator, graphs: []const Original.CircuitGraph, limits: Limits) !Plan {
        if (graphs.len == 0 or graphs.len > limits.max_graphs or limits.max_nodes == 0) return error.ResidentArithmeticResourceLimit;
        var total: usize = 0;
        for (graphs) |g| {
            try g.validate();
            total = try std.math.add(usize, total, g.nodes.len);
        }
        if (total > limits.max_nodes or total > std.math.maxInt(u32) / 4) return error.ResidentArithmeticResourceLimit;
        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const a = arena.allocator();
        const gs = try a.alloc(Graph, graphs.len);
        const graph_ids = try a.alloc([32]u8, graphs.len);
        for (graphs, graph_ids) |g, *id| id.* = g.identity_digest;
        const ns = try a.alloc(Node, total);
        const ordered = try a.alloc(u32, total);
        var offsets: std.ArrayList(u32) = .empty;
        var outputs: std.ArrayList(u32) = .empty;
        var node_first: usize = 0;
        var input_first: u32 = 0;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo/resident-parent-original-arithmetic/v1\x00");
        for (graphs, gs) |g, *out| {
            hash.update(&g.identity_digest);
            const depth = try a.alloc(u32, g.nodes.len);
            var max_depth: u32 = 0;
            var input_count: u32 = 0;
            for (g.nodes, 0..) |n, i| {
                var record: Node = .{ .op = @intFromEnum(switch (n.op) {
                    .input => Op.input,
                    .constant => Op.constant,
                    .add => Op.add,
                    .sub => Op.sub,
                    .mul => Op.mul,
                    .neg => Op.neg,
                    .inverse => Op.inverse,
                }) };
                depth[i] = switch (n.op) {
                    .input => blk: {
                        record.input = input_first + input_count;
                        input_count += 1;
                        break :blk 0;
                    },
                    .constant => |v| blk: {
                        record.constant = v;
                        break :blk 0;
                    },
                    .add, .sub, .mul => |b| blk: {
                        record.lhs = @intCast(node_first + b.lhs);
                        record.rhs = @intCast(node_first + b.rhs);
                        break :blk 1 + @max(depth[b.lhs], depth[b.rhs]);
                    },
                    .neg, .inverse => |b| blk: {
                        record.lhs = @intCast(node_first + b);
                        break :blk 1 + depth[b];
                    },
                };
                max_depth = @max(max_depth, depth[i]);
                ns[node_first + i] = record;
            }
            const counts = try a.alloc(u32, max_depth + 1);
            @memset(counts, 0);
            for (depth) |d| counts[d] += 1;
            const positions = try a.alloc(u32, counts.len);
            var next: u32 = @intCast(node_first);
            const level_first = offsets.items.len;
            for (counts, positions) |count, *position| {
                position.* = next;
                try offsets.append(a, next);
                next += count;
            }
            try offsets.append(a, next);
            for (depth, 0..) |d, i| {
                ordered[positions[d]] = @intCast(node_first + i);
                positions[d] += 1;
            }
            const output_first = outputs.items.len;
            for (g.outputs) |index| try outputs.append(a, @intCast(node_first + index));
            out.* = .{ .node_first = @intCast(node_first), .node_count = @intCast(g.nodes.len), .input_first = input_first, .input_count = input_count, .value_word_base = @intCast(4 * node_first), .level_first = @intCast(level_first), .level_count = max_depth + 1, .output_first = @intCast(output_first), .output_count = @intCast(g.outputs.len) };
            node_first += g.nodes.len;
            input_first += input_count;
        }
        const of = try offsets.toOwnedSlice(a);
        const os = try outputs.toOwnedSlice(a);
        var bytes = try std.math.mul(usize, total, @sizeOf(Node) + 4 + 16);
        bytes = try std.math.add(usize, bytes, try std.math.mul(usize, input_first, 16));
        bytes = try std.math.add(usize, bytes, (of.len + os.len) * 4 + gs.len * @sizeOf(Graph) + 4);
        if (bytes > limits.max_bytes) return error.ResidentArithmeticResourceLimit;
        return .{ .allocator = backing, .arena = arena, .graphs = gs, .graph_ids = graph_ids, .nodes = ns, .level_nodes = ordered, .level_offsets = of, .outputs = os, .input_words = @as(usize, input_first) * 4, .value_words = total * 4, .device_bytes = bytes, .identity = hash.finalResult() };
    }
    pub fn valueWord(self: *const Plan, graph_index: usize, node_id: u32, limb: u2) !usize {
        if (graph_index >= self.graphs.len) return error.InvalidResidentArithmeticRoute;
        const g = self.graphs[graph_index];
        if (node_id >= g.node_count) return error.InvalidResidentArithmeticRoute;
        return @as(usize, g.value_word_base) + 4 * @as(usize, node_id) + limb;
    }
    pub fn inputWord(self: *const Plan, graph_index: usize, node_id: u32, limb: u2) !usize {
        if (graph_index >= self.graphs.len) return error.InvalidResidentArithmeticRoute;
        const g = self.graphs[graph_index];
        if (node_id >= g.node_count) return error.InvalidResidentArithmeticRoute;
        const n = self.nodes[g.node_first + node_id];
        if (n.op != @intFromEnum(Op.input)) return error.InvalidResidentArithmeticRoute;
        return 4 * @as(usize, n.input) + limb;
    }
    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
test "resident arithmetic dependency levels preserve exact original nodes and reject altered seals" {
    const a = std.testing.allocator;
    const nodes = [_]Original.Node{ .{ .op = .input }, .{ .op = .{ .constant = .{ 1, 2, 3, 4 } } }, .{ .op = .{ .mul = .{ .lhs = 0, .rhs = 1 } } }, .{ .op = .{ .sub = .{ .lhs = 2, .rhs = 2 } } } };
    const outputs = [_]u32{3};
    const g = try Original.CircuitGraph.authenticate(&nodes, &outputs, Original.computeGraphDigest(&nodes, &outputs));
    var p = try Plan.init(a, &.{g}, .{});
    defer p.deinit();
    try std.testing.expectEqual(@as(u32, 3), p.graphs[0].level_count);
    try std.testing.expectEqual(@as(usize, 4), p.input_words);
    var bad = g;
    bad.identity_digest[0] ^= 1;
    try std.testing.expectError(error.GraphSealMismatch, Plan.init(a, &.{bad}, .{}));
    try std.testing.expectError(error.ResidentArithmeticResourceLimit, Plan.init(a, &.{g}, .{ .max_bytes = 1 }));
}
