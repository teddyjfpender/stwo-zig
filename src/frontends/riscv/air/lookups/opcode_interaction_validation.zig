//! Validation and dependency analysis for opcode interaction programs.

const std = @import("std");
const fields = @import("stwo_core").fields;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const trace = @import("../../runner/trace.zig");

const m31 = fields.m31;
const M31 = m31.M31;
const PackedM31 = m31.PackedM31;

pub fn evaluateNodes(
    nodes: []const prover_component.BasePolynomialNode,
    reachable: []const bool,
    values: []PackedM31,
    columns: []const PackedM31,
) void {
    for (nodes, reachable, 0..) |node, is_reachable, index| {
        if (!is_reachable) continue;
        values[index] = switch (node.op) {
            .constant => @splat(node.value),
            .column => columns[node.value],
            .add => m31.addPacked(values[node.lhs], values[node.rhs]),
            .sub => m31.subPacked(values[node.lhs], values[node.rhs]),
            .mul => m31.mulPacked(values[node.lhs], values[node.rhs]),
            .neg => m31.negPacked(values[node.lhs]),
        };
    }
}

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
