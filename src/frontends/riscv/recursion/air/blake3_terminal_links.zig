//! Owned, canonical DEEP-answer and FRI-coefficient input mappings.
const std = @import("std");
const deep = @import("pcs_deep_circuit.zig");
const fri = @import("fri_verifier_circuit.zig");
pub const PACK_CIRCUIT: u32 = 5_000_002;
pub const Answer = struct { deep: u32, fri: u32 };
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    answers: []Answer,
    coefficients: [][4]u32,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
    }
};
pub fn build(backing: std.mem.Allocator, dg: *const deep.Circuit, fg: *const fri.Circuit, queries: usize, coefficients: usize) !Prepared {
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    const missing = std.math.maxInt(u32);
    const answers = try a.alloc(Answer, try std.math.mul(usize, queries, 4));
    @memset(answers, .{ .deep = missing, .fri = missing });
    const terminal = try a.alloc([4]u32, coefficients);
    @memset(terminal, @splat(missing));
    for (dg.bindings) |binding| switch (binding.source) {
        .answer_word => |source| {
            if (source.query >= queries or source.word >= 4) return error.InvalidParentTerminalLink;
            try assign(&answers[source.query * 4 + source.word].deep, binding.node_id);
        },
        else => {},
    };
    for (fg.bindings) |binding| switch (binding.source) {
        .deep_answer_word => |source| {
            if (source.query >= queries or source.word >= 4) return error.InvalidParentTerminalLink;
            try assign(&answers[source.query * 4 + source.word].fri, binding.node_id);
        },
        .last_layer_coefficient_word => |source| {
            if (source.coefficient >= coefficients or source.word >= 4) return error.InvalidParentTerminalLink;
            try assign(&terminal[source.coefficient][source.word], binding.node_id);
        },
        else => {},
    };
    for (answers) |answer| if (answer.deep == missing or answer.fri == missing) return error.InvalidParentTerminalLink;
    for (terminal) |nodes| for (nodes) |node| if (node == missing) return error.InvalidParentTerminalLink;
    return .{ .arena = arena, .answers = answers, .coefficients = terminal };
}
fn assign(destination: *u32, node: u32) !void {
    if (destination.* != std.math.maxInt(u32)) return error.InvalidParentTerminalLink;
    destination.* = node;
}
