//! Structural audit of child-proof witnesses before guess-yield finalization.
//! Each gate is treated as an undirected relation between its variables. A
//! proof wire should reach a public output or a nontrivial equality. This is
//! deliberately weaker than a cryptographic soundness proof: algebraic
//! cancellation can still make a connected wire semantically irrelevant.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");

pub const Stats = struct {
    proof_vars: u32,
    reaches_output: u32,
    reaches_equality: u32,
    reaches_neither: u32,
};

fn root(parents: []u32, index: u32) u32 {
    var cursor = index;
    while (parents[cursor] != cursor) {
        parents[cursor] = parents[parents[cursor]];
        cursor = parents[cursor];
    }
    return cursor;
}

fn join(parents: []u32, constants: []const bool, left: u32, right: u32) void {
    if (constants[left] or constants[right]) return;
    const a = root(parents, left);
    const b = root(parents, right);
    if (a != b) parents[b] = a;
}

fn joinBinary(parents: []u32, constants: []const bool, gates: []const circuit.builder.circuit.BinaryGate) void {
    for (gates) |gate| {
        join(parents, constants, gate.in0, gate.out);
        join(parents, constants, gate.in1, gate.out);
    }
}

pub fn audit(allocator: std.mem.Allocator, gates: *const circuit.builder.Circuit, interned_constants: []const circuit.builder.Var, start: u32, end: u32) !Stats {
    if (start > end or end > gates.n_vars) return error.InvalidWitnessRange;
    const constants = try allocator.alloc(bool, gates.n_vars);
    defer allocator.free(constants);
    @memset(constants, false);
    for (interned_constants) |value| {
        if (value.idx >= gates.n_vars) return error.InvalidConstantIndex;
        constants[value.idx] = true;
    }
    const parents = try allocator.alloc(u32, gates.n_vars);
    defer allocator.free(parents);
    for (parents, 0..) |*parent, index| parent.* = @intCast(index);

    joinBinary(parents, constants, gates.add.items);
    joinBinary(parents, constants, gates.sub.items);
    joinBinary(parents, constants, gates.mul.items);
    joinBinary(parents, constants, gates.pointwise_mul.items);
    for (gates.eq.items) |gate| join(parents, constants, gate.in0, gate.in1);
    for (gates.triple_xor.items) |gate| {
        join(parents, constants, gate.input_a, gate.out);
        join(parents, constants, gate.input_b, gate.out);
        join(parents, constants, gate.input_c, gate.out);
    }
    for (gates.m31_to_u32.items) |gate| join(parents, constants, gate.input, gate.out);
    for (gates.blake_g_gate.items) |gate| {
        for (gate.inputs()) |input| join(parents, constants, input, gate.out_base);
        for (gate.outputs()) |output| join(parents, constants, output, gate.out_base);
    }
    for (0..gates.permutation.len()) |index| {
        const permutation = gates.permutation.get(index);
        var first: ?u32 = null;
        for (permutation.inputs) |input| if (!constants[input]) {
            first = input;
            break;
        };
        if (first == null) for (permutation.outputs) |output| {
            if (!constants[output]) {
                first = output;
                break;
            }
        };
        if (first) |anchor| {
            for (permutation.inputs) |input| join(parents, constants, anchor, input);
            for (permutation.outputs) |output| join(parents, constants, anchor, output);
        }
    }

    const anchors = try allocator.alloc(u8, gates.n_vars);
    defer allocator.free(anchors);
    @memset(anchors, 0);
    for (gates.output.items) |output| anchors[root(parents, output)] |= 1;
    for (gates.eq.items) |gate| {
        if (gate.in0 != gate.in1) anchors[root(parents, gate.in0)] |= 2;
    }
    var stats: Stats = .{ .proof_vars = end - start, .reaches_output = 0, .reaches_equality = 0, .reaches_neither = 0 };
    for (start..end) |index| {
        const flags = anchors[root(parents, @intCast(index))];
        if (flags & 1 != 0) stats.reaches_output += 1;
        if (flags & 2 != 0) stats.reaches_equality += 1;
        if (flags == 0) stats.reaches_neither += 1;
    }
    return stats;
}

test "proof witness connectivity finds a disconnected witness" {
    var gates: circuit.builder.Circuit = .{ .n_vars = 6 };
    defer gates.deinit(std.testing.allocator);
    try gates.add.append(std.testing.allocator, .{ .in0 = 4, .in1 = 1, .out = 3 });
    try gates.output.append(std.testing.allocator, 3);
    try gates.eq.append(std.testing.allocator, .{ .in0 = 4, .in1 = 2 });
    const stats = try audit(std.testing.allocator, &gates, &.{ .{ .idx = 0 }, .{ .idx = 1 }, .{ .idx = 2 } }, 4, 6);
    try std.testing.expectEqual(@as(u32, 2), stats.proof_vars);
    try std.testing.expectEqual(@as(u32, 1), stats.reaches_output);
    try std.testing.expectEqual(@as(u32, 1), stats.reaches_equality);
    try std.testing.expectEqual(@as(u32, 1), stats.reaches_neither);
}

test "shared constants cannot bridge disconnected proof components" {
    var gates: circuit.builder.Circuit = .{ .n_vars = 7 };
    defer gates.deinit(std.testing.allocator);
    try gates.add.append(std.testing.allocator, .{ .in0 = 4, .in1 = 1, .out = 3 });
    try gates.add.append(std.testing.allocator, .{ .in0 = 5, .in1 = 1, .out = 6 });
    try gates.output.append(std.testing.allocator, 3);
    const stats = try audit(std.testing.allocator, &gates, &.{ .{ .idx = 0 }, .{ .idx = 1 }, .{ .idx = 2 } }, 4, 6);
    try std.testing.expectEqual(@as(u32, 2), stats.proof_vars);
    try std.testing.expectEqual(@as(u32, 1), stats.reaches_output);
    try std.testing.expectEqual(@as(u32, 0), stats.reaches_equality);
    try std.testing.expectEqual(@as(u32, 1), stats.reaches_neither);
}
