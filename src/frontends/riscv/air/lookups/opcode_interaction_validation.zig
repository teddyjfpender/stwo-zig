//! Validation and dependency analysis for opcode interaction programs.

const std = @import("std");
const fields = @import("stwo_core").fields;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const trace = @import("../../runner/trace.zig");

const m31 = fields.m31;
const M31 = m31.M31;
const PackedM31 = m31.PackedM31;

fn evaluateNode(
    node: prover_component.BasePolynomialNode,
    values: []PackedM31,
    columns: []const PackedM31,
) PackedM31 {
    return switch (node.op) {
        .constant => @splat(node.value),
        .column => columns[node.value],
        .add => m31.addPacked(values[node.lhs], values[node.rhs]),
        .sub => m31.subPacked(values[node.lhs], values[node.rhs]),
        .mul => m31.mulPacked(values[node.lhs], values[node.rhs]),
        .neg => m31.negPacked(values[node.lhs]),
    };
}

pub const EvaluationPlan = struct {
    allocator: std.mem.Allocator,
    indices: []usize,
    dense: bool,

    pub fn init(
        allocator: std.mem.Allocator,
        program: prover_component.OwnedLookupPolynomialProgram,
    ) !EvaluationPlan {
        const reachable = try lookupReachable(allocator, program);
        defer allocator.free(reachable);
        var count: usize = 0;
        for (reachable) |is_reachable| count += @intFromBool(is_reachable);
        const indices = try allocator.alloc(usize, count);
        var cursor: usize = 0;
        for (reachable, 0..) |is_reachable, index| {
            if (!is_reachable) continue;
            indices[cursor] = index;
            cursor += 1;
        }
        return .{
            .allocator = allocator,
            .indices = indices,
            // A direct walk avoids both the reachability branch and indexed
            // node loads when omitted nodes are too sparse to repay them.
            .dense = count * 8 >= program.nodes.len * 7,
        };
    }

    pub fn deinit(self: *EvaluationPlan) void {
        self.allocator.free(self.indices);
        self.* = undefined;
    }

    pub fn evaluate(
        self: *const EvaluationPlan,
        nodes: []const prover_component.BasePolynomialNode,
        values: []PackedM31,
        columns: []const PackedM31,
    ) void {
        if (self.dense) {
            for (nodes, 0..) |node, index|
                values[index] = evaluateNode(node, values, columns);
            return;
        }
        for (self.indices) |index|
            values[index] = evaluateNode(nodes[index], values, columns);
    }
};

pub fn lookupReachable(
    allocator: std.mem.Allocator,
    program: prover_component.OwnedLookupPolynomialProgram,
) ![]bool {
    const reachable = try allocator.alloc(bool, program.nodes.len);
    @memset(reachable, false);
    for (program.entries) |lookup| {
        reachable[lookup.numerator] = true;
        for (lookup.values[0..lookup.arity]) |value| reachable[value] = true;
    }
    var cursor = program.nodes.len;
    while (cursor != 0) {
        cursor -= 1;
        if (!reachable[cursor]) continue;
        const node = program.nodes[cursor];
        switch (node.op) {
            .constant, .column => {},
            .add, .sub, .mul => {
                reachable[node.lhs] = true;
                reachable[node.rhs] = true;
            },
            .neg => reachable[node.lhs] = true,
        }
    }
    return reachable;
}

pub fn validateColumns(
    family: trace.OpcodeFamily,
    columns: []const []const M31,
    size: usize,
) !void {
    if (columns.len != trace.nColumnsForFamily(family))
        return error.InvalidColumnCount;
    for (columns) |column| {
        if (column.len != size) return error.InvalidColumnLength;
    }
}
