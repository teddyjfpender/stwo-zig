//! Arena-bound original arithmetic graph replay. Host-side compilation is cold;
//! input values, node evaluation, inversion and zero anchors are device-only.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
pub const Cold = @import("resident_parent_arithmetic_plan_v1.zig");
pub const FIRST_ID: u32 = (1 << 28) + 8192;
pub const Slot = enum(u32) { graphs, nodes, level_nodes, level_offsets, outputs, selected, inputs, values, auxiliary_graphs };
pub fn id(which: Slot) u32 {
    return FIRST_ID + @intFromEnum(which);
}
extern fn stwo_resident_parent_arithmetic_on([*]const Cold.Graph, [*]const u32, u32, [*]const Cold.Node, [*]const u32, [*]const u32, [*]const u32, [*]const u32, [*]u32, [*]u32, ?*anyopaque) c_int;
pub fn requirements(a: std.mem.Allocator, plan: *const Cold.Plan) ![]cuda.runtime.arena.Requirement {
    const sizes = [_]usize{ plan.graphs.len * @sizeOf(Cold.Graph) / 4, plan.nodes.len * @sizeOf(Cold.Node) / 4, plan.level_nodes.len, plan.level_offsets.len, plan.outputs.len, plan.graphs.len, @max(1, plan.input_words), plan.value_words, plan.graphs.len * @sizeOf(Cold.Graph) / 4 };
    const result = try a.alloc(cuda.runtime.arena.Requirement, sizes.len);
    errdefer a.free(result);
    for (sizes, result, 0..) |size, *r, i| {
        if (size == 0) return error.InvalidResidentArithmeticPlan;
        r.* = .{ .id = id(@enumFromInt(i)), .words = size, .alignment_words = 64, .live_from = .ingress, .live_through = .trace_generation };
    }
    return result;
}
pub const Bound = struct {
    plan: *const Cold.Plan,
    slots: [9]common.Words,
    primed: bool = false,
    completed: [64]bool = @splat(false),
    pub fn init(plan: *const Cold.Plan, tx: anytype) !Bound {
        if (plan.graphs.len > 64) return error.ResidentArithmeticResourceLimit;
        var result = Bound{ .plan = plan, .slots = undefined };
        inline for (std.meta.tags(Slot), 0..) |which, i| result.slots[i] = try tx.slot(id(which));
        return result;
    }
    pub fn slot(self: *const Bound, which: Slot) common.Words {
        return self.slots[@intFromEnum(which)];
    }
    pub fn prime(self: *Bound, session: anytype) !void {
        if (self.primed) return error.InvalidResidentArithmeticState;
        try common.requireStage(session, .ingress);
        try session.context.uploadSlice(Cold.Graph, try self.slot(.graphs).cast(Cold.Graph), self.plan.graphs);
        var auxiliary: [64]Cold.Graph = undefined;
        for (self.plan.graphs, auxiliary[0..self.plan.graphs.len]) |graph, *out| {
            out.* = graph;
            out.output_count = 0;
        }
        try session.context.uploadSlice(Cold.Graph, try self.slot(.auxiliary_graphs).cast(Cold.Graph), auxiliary[0..self.plan.graphs.len]);
        try session.context.uploadSlice(Cold.Node, try self.slot(.nodes).cast(Cold.Node), self.plan.nodes);
        try session.context.uploadSlice(u32, self.slot(.level_nodes), self.plan.level_nodes);
        try session.context.uploadSlice(u32, self.slot(.level_offsets), self.plan.level_offsets);
        try session.context.uploadSlice(u32, self.slot(.outputs), self.plan.outputs);
        var indices: [64]u32 = undefined;
        for (indices[0..self.plan.graphs.len], 0..) |*v, i| v.* = @intCast(i);
        try session.context.uploadSlice(u32, self.slot(.selected), indices[0..self.plan.graphs.len]);
        self.primed = true;
    }
    pub fn evaluateRange(self: *Bound, session: anytype, first: usize, count: usize, status: common.Words) !void {
        if (!self.primed or count == 0 or first > self.plan.graphs.len or count > self.plan.graphs.len - first or status.len != 1) return error.InvalidResidentArithmeticState;
        for (self.completed[first..][0..count]) |done| if (done) return error.InvalidResidentArithmeticState;
        try common.requireStage(session, .trace_generation);
        const g = try self.slot(.graphs).cast(Cold.Graph);
        const n = try self.slot(.nodes).cast(Cold.Node);
        const selected = try self.slot(.selected).sub(first, count);
        try common.record(session, .trace_generation, stwo_resident_parent_arithmetic_on(try session.context.deviceSlicePointer(Cold.Graph, g, g.len), try pointer(session, selected), @intCast(count), try session.context.deviceSlicePointer(Cold.Node, n, n.len), try pointer(session, self.slot(.level_nodes)), try pointer(session, self.slot(.level_offsets)), try pointer(session, self.slot(.outputs)), try pointer(session, self.slot(.inputs)), try pointer(session, self.slot(.values)), try pointer(session, status), session.context.stream));
        @memset(self.completed[first..][0..count], true);
    }
    /// One scalar coordinate of a secure quotient becomes a base-field input
    /// [coordinate,0,0,0] of the ORIGINAL graph. The final graph still verifies
    /// every anchor; this auxiliary pass is numerical construction only.
    pub const Answer = @import("resident_parent_deep_answers_plan_v1.zig").Answer;
    pub fn deriveAnswers(self: *Bound, session: anytype, graph_index: usize, answers: []const Answer, answer_pool: common.Words, status: common.Words) !void {
        if (!self.primed or graph_index >= self.plan.graphs.len or self.completed[graph_index] or answers.len == 0 or status.len != 1) return error.InvalidResidentArithmeticState;
        const graph = self.plan.graphs[graph_index];
        try validateAnswers(graph, answers, answer_pool.len);
        try common.requireStage(session, .trace_generation);
        for (answers) |answer| try session.zeroResidentSlice(u32, .trace_generation, try self.slot(.inputs).sub(answer.input_word, 4));
        const g = try self.slot(.auxiliary_graphs).cast(Cold.Graph);
        const n = try self.slot(.nodes).cast(Cold.Node);
        const selected = try self.slot(.selected).sub(graph_index, 1);
        try common.record(session, .trace_generation, stwo_resident_parent_arithmetic_on(try session.context.deviceSlicePointer(Cold.Graph, g, g.len), try pointer(session, selected), 1, try session.context.deviceSlicePointer(Cold.Node, n, n.len), try pointer(session, self.slot(.level_nodes)), try pointer(session, self.slot(.level_offsets)), try pointer(session, self.slot(.outputs)), try pointer(session, self.slot(.inputs)), try pointer(session, self.slot(.values)), try pointer(session, status), session.context.stream));
        for (answers) |answer| {
            const value = try self.slot(.values).sub(answer.quotient_word, 1);
            try session.context.copyDeviceSlice(u32, try self.slot(.inputs).sub(answer.input_word, 1), value);
            try session.context.copyDeviceSlice(u32, try answer_pool.sub(answer.output_word, 1), value);
        }
        // Deliberately do not mark completed. evaluateRange must replay the original
        // descriptor with every output anchor before requireComplete can succeed.
    }
    pub fn requireComplete(self: *const Bound) !void {
        for (self.completed[0..self.plan.graphs.len]) |done| if (!done) return error.IncompleteResidentArithmetic;
    }
};
fn pointer(s: anytype, w: common.Words) ![*]u32 {
    return s.context.deviceSlicePointer(u32, w, w.len);
}
fn forceNative(b: *Bound, s: *cuda.runtime.NativeSession, status: common.Words) !void {
    try b.prime(s);
    try b.evaluateRange(s, 0, b.plan.graphs.len, status);
    try b.requireComplete();
}
test "resident arithmetic native executor typechecks" {
    _ = &forceNative;
}

fn validateAnswers(graph: Cold.Graph, answers: []const Bound.Answer, output_words: usize) !void {
    for (answers, 0..) |answer, i| {
        const first_input = @as(usize, graph.input_first) * 4;
        const input_end = first_input + @as(usize, graph.input_count) * 4;
        const value_end = @as(usize, graph.value_word_base) + @as(usize, graph.node_count) * 4;
        if (answer.input_word % 4 != 0 or answer.input_word < first_input or answer.input_word >= input_end or answer.quotient_word < graph.value_word_base or answer.quotient_word >= value_end or answer.output_word >= output_words) return error.InvalidResidentArithmeticAnswer;
        for (answers[0..i]) |previous| if (previous.input_word == answer.input_word or previous.output_word == answer.output_word) return error.InvalidResidentArithmeticAnswer;
    }
}
test "resident arithmetic scalar answer routing keeps independent base inputs" {
    const graph = Cold.Graph{ .node_first = 8, .node_count = 12, .input_first = 5, .input_count = 4, .value_word_base = 32, .level_first = 0, .level_count = 1, .output_first = 0, .output_count = 1 };
    const valid = [_]Bound.Answer{ .{ .input_word = 20, .quotient_word = 48, .output_word = 0 }, .{ .input_word = 24, .quotient_word = 49, .output_word = 1 }, .{ .input_word = 28, .quotient_word = 50, .output_word = 2 }, .{ .input_word = 32, .quotient_word = 51, .output_word = 3 } };
    try validateAnswers(graph, &valid, 4);
    var bad = valid;
    bad[1].input_word = 21;
    try std.testing.expectError(error.InvalidResidentArithmeticAnswer, validateAnswers(graph, &bad, 4));
    bad = valid;
    bad[1].input_word = 20;
    try std.testing.expectError(error.InvalidResidentArithmeticAnswer, validateAnswers(graph, &bad, 4));
    bad = valid;
    bad[1].output_word = 0;
    try std.testing.expectError(error.InvalidResidentArithmeticAnswer, validateAnswers(graph, &bad, 4));
    bad = valid;
    bad[1].quotient_word = 80;
    try std.testing.expectError(error.InvalidResidentArithmeticAnswer, validateAnswers(graph, &bad, 4));
}
