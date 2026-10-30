//! Cold derivation of native DEEP answers from the original verifier graph.
//! Only immutable node/binding metadata is inspected. Every quotient is proved
//! independent of ALL supplied answer inputs before an auxiliary GPU replay may
//! derive it. The final original graph still checks every zero-output anchor.
const std = @import("std");
const core = @import("stwo_core");
const Deep = @import("../../frontends/riscv/recursion/air/pcs_deep_circuit.zig");
const Arithmetic = @import("resident_parent_arithmetic_plan_v1.zig");
const Original = Arithmetic.Original;
const Q = core.fields.qm31.QM31;
pub const Answer = struct { input_word: u32, quotient_word: u32, output_word: u32 };
pub const Plan = struct {
    a: std.mem.Allocator,
    answers: []const Answer,
    graph_index: usize,
    output_words: u32,
    graph_identity: [32]u8,
    pub fn init(a: std.mem.Allocator, deep: *const Deep.Prepared, arithmetic: *const Arithmetic.Plan, graph_index: usize) !Plan {
        try deep.validate();
        const graph = deep.graph();
        if (graph_index >= arithmetic.graphs.len or !std.meta.eql(graph.identity_digest, arithmetic.graph_ids[graph_index])) return error.InvalidResidentDeepDerivation;
        const n = deep.profile().query_count;
        if (n == 0 or n > 128) return error.InvalidResidentDeepDerivation;
        const input_nodes = try a.alloc([4]u32, n);
        defer a.free(input_nodes);
        @memset(input_nodes, .{@as(u32, std.math.maxInt(u32))} ** 4);
        var active: ?u32 = null;
        for (deep.view().bindings) |binding| switch (binding.source) {
            .active_selector => {
                if (active != null) return error.InvalidResidentDeepDerivation;
                active = binding.node_id;
            },
            .answer_word => |s| {
                if (s.query >= n or s.word >= 4 or input_nodes[s.query][s.word] != std.math.maxInt(u32)) return error.InvalidResidentDeepDerivation;
                input_nodes[s.query][s.word] = binding.node_id;
            },
            else => {},
        };
        const selector = active orelse return error.InvalidResidentDeepDerivation;
        const dependent = try a.alloc(bool, graph.nodes.len);
        defer a.free(dependent);
        @memset(dependent, false);
        for (input_nodes) |nodes| for (nodes) |node| {
            if (node >= graph.nodes.len or graph.nodes[node].op != .input) return error.InvalidResidentDeepDerivation;
            dependent[node] = true;
        };
        for (graph.nodes, 0..) |node, i| dependent[i] = dependent[i] or switch (node.op) {
            .input, .constant => false,
            .add, .sub, .mul => |b| dependent[b.lhs] or dependent[b.rhs],
            .neg, .inverse => |s| dependent[s],
        };
        const quotients = try a.alloc(?u32, n);
        defer a.free(quotients);
        @memset(quotients, null);
        for (graph.outputs) |output| {
            if (graph.nodes[output].op != .mul) continue;
            const mul = graph.nodes[output].op.mul;
            const difference = if (mul.lhs == selector) mul.rhs else if (mul.rhs == selector) mul.lhs else continue;
            if (graph.nodes[difference].op != .sub) continue;
            const sub = graph.nodes[difference].op.sub;
            for (input_nodes, 0..) |nodes, query| if (isAnswer(graph.nodes, sub.rhs, nodes)) {
                if (dependent[sub.lhs] or quotients[query] != null) return error.DependentResidentDeepQuotient;
                quotients[query] = sub.lhs;
            };
        }
        const routes = try a.alloc(Answer, @as(usize, n) * 4);
        errdefer a.free(routes);
        for (input_nodes, quotients, 0..) |nodes, maybe, query| {
            const quotient = maybe orelse return error.MissingResidentDeepQuotient;
            for (nodes, 0..) |node, limb| routes[query * 4 + limb] = .{ .input_word = @intCast(try arithmetic.inputWord(graph_index, node, 0)), .quotient_word = @intCast(try arithmetic.valueWord(graph_index, quotient, @intCast(limb))), .output_word = @intCast(query * 4 + limb) };
        }
        return .{ .a = a, .answers = routes, .graph_index = graph_index, .output_words = n * 4, .graph_identity = graph.identity_digest };
    }
    pub fn deinit(self: *Plan) void {
        self.a.free(self.answers);
        self.* = undefined;
    }
};
fn isAnswer(nodes: []const Original.Node, node: u32, inputs: [4]u32) bool {
    const coefficients = linear(nodes, node, inputs, 0) orelse return false;
    for (coefficients, 0..) |c, i| {
        var expected: [4]core.fields.m31.M31 = @splat(core.fields.m31.M31.zero());
        expected[i] = core.fields.m31.M31.one();
        if (!c.eql(Q.fromM31Array(expected))) return false;
    }
    return true;
}
fn linear(nodes: []const Original.Node, node: u32, inputs: [4]u32, depth: u32) ?[4]Q {
    if (node >= nodes.len or depth > 12) return null;
    switch (nodes[node].op) {
        .input => {
            var result: [4]Q = @splat(Q.zero());
            for (inputs, 0..) |input, i| if (node == input) {
                result[i] = Q.one();
                return result;
            };
            return null;
        },
        .constant => |words| {
            if (!std.mem.allEqual(u32, &words, 0)) return null;
            return @splat(Q.zero());
        },
        .add => |b| {
            const lhs = linear(nodes, b.lhs, inputs, depth + 1) orelse return null;
            const rhs = linear(nodes, b.rhs, inputs, depth + 1) orelse return null;
            var out: [4]Q = undefined;
            for (&out, lhs, rhs) |*o, l, r| o.* = l.add(r);
            return out;
        },
        .mul => |b| {
            const which = if (nodes[b.lhs].op == .constant) b.lhs else if (nodes[b.rhs].op == .constant) b.rhs else return null;
            const other = if (which == b.lhs) b.rhs else b.lhs;
            const words = nodes[which].op.constant;
            var parts: [4]core.fields.m31.M31 = undefined;
            for (words, &parts) |w, *p| {
                if (w >= core.fields.m31.Modulus) return null;
                p.* = core.fields.m31.M31.fromCanonical(w);
            }
            const factor = Q.fromM31Array(parts);
            var out = linear(nodes, other, inputs, depth + 1) orelse return null;
            for (&out) |*v| v.* = v.mul(factor);
            return out;
        },
        else => return null,
    }
}
test "resident DEEP answers derive only answer-independent quotients from original anchors" {
    const a = std.testing.allocator;
    const logs = [_]u32{4};
    const trees = [_]Deep.TreeProfile{.{ .column_log_sizes = &logs }};
    const layouts = [_]Deep.SamplePointLayout{.current};
    var deep = try Deep.Prepared.init(a, .{ .trees = &trees, .sample_layouts = &layouts, .lifting_log_size = 5, .log_blowup_factor = 1, .query_count = 2 });
    defer deep.deinit();
    var arithmetic = try Arithmetic.Plan.init(a, &.{deep.graph()}, .{});
    defer arithmetic.deinit();
    var derived = try Plan.init(a, &deep, &arithmetic, 0);
    defer derived.deinit();
    try std.testing.expectEqual(@as(usize, 8), derived.answers.len);
    try std.testing.expectEqual(@as(u32, 8), derived.output_words);
    for (derived.answers, 0..) |answer, i| {
        try std.testing.expect(answer.input_word % 4 == 0);
        try std.testing.expectEqual(@as(u32, @intCast(i)), answer.output_word);
        for (derived.answers[0..i]) |previous| try std.testing.expect(previous.input_word != answer.input_word);
    }
    try std.testing.expectError(error.InvalidResidentDeepDerivation, Plan.init(a, &deep, &arithmetic, 1));
    arithmetic.graph_ids[0][0] ^= 1;
    try std.testing.expectError(error.InvalidResidentDeepDerivation, Plan.init(a, &deep, &arithmetic, 0));
}
