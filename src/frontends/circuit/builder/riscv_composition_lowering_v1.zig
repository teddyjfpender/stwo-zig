//! Lower an independently authenticated RISC verifier DAG into circuit gates.
//! No AIR equations, claims, transcript challenges or sample values are copied
//! into constants here. Input wires are supplied by the complete leaf wrapper.
const core = @import("stwo_core");
const std = @import("std");
const b = @import("mod.zig");
const Q = core.fields.qm31.QM31;
pub const production_active = false;
pub const Liveness = struct {
    nodes: []bool,
    inputs: []bool,
    pub fn deinit(self: *Liveness, a: std.mem.Allocator) void {
        a.free(self.inputs);
        a.free(self.nodes);
        self.* = undefined;
    }
};
/// Every zero anchor and EVERY inverse is retained. An unused inverse still
/// imposes nonzero input, so it is an effect root rather than dead arithmetic.
pub fn liveness(a: std.mem.Allocator, circuit: anytype) !Liveness {
    try circuit.validate();
    const nodes = try a.alloc(bool, circuit.nodes.len);
    errdefer a.free(nodes);
    @memset(nodes, false);
    const inputs = try a.alloc(bool, circuit.input_count);
    errdefer a.free(inputs);
    for (circuit.outputs) |output| nodes[output] = true;
    for (circuit.nodes, 0..) |node, i| if (node.op == .inverse) {
        nodes[i] = true;
    };
    var i = circuit.nodes.len;
    while (i > 0) {
        i -= 1;
        if (!nodes[i]) continue;
        switch (circuit.nodes[i].op) {
            .add, .sub, .mul => |p| {
                nodes[p.lhs] = true;
                nodes[p.rhs] = true;
            },
            .neg, .inverse => |operand| nodes[operand] = true,
            .input, .constant => {},
        }
    }
    var at: usize = 0;
    for (circuit.nodes, 0..) |node, n| if (node.op == .input) {
        inputs[at] = nodes[n];
        at += 1;
    };
    if (at != inputs.len) return error.InvalidRiscCircuitCompositionInputs;
    return .{ .nodes = nodes, .inputs = inputs };
}

pub fn constrain(comptime V: type, ctx: *b.Context(V), circuit: anytype, inputs: []const b.Var) !void {
    try circuit.validate();
    if (inputs.len != circuit.input_count) return error.InvalidRiscCircuitCompositionInputs;
    const values = try ctx.scratch().alloc(b.Var, circuit.nodes.len);
    const live = try liveness(ctx.scratch(), circuit);
    var next: usize = 0;
    for (circuit.nodes, 0..) |node, index| {
        if (node.op == .input) {
            if (next >= inputs.len) return error.InvalidRiscCircuitCompositionInputs;
            if (live.nodes[index]) values[index] = inputs[next];
            next += 1;
            continue;
        }
        if (!live.nodes[index]) continue;
        values[index] = switch (node.op) {
            .input => unreachable,
            .constant => |coordinates| try ctx.constant(Q.fromU32Unchecked(coordinates[0], coordinates[1], coordinates[2], coordinates[3])),
            .add => |p| try ctx.add(values[p.lhs], values[p.rhs]),
            .sub => |p| try ctx.sub(values[p.lhs], values[p.rhs]),
            .mul => |p| try ctx.mul(values[p.lhs], values[p.rhs]),
            .neg => |operand| try ctx.sub(ctx.zero(), values[operand]),
            .inverse => |operand| try ctx.inv(values[operand]),
        };
    }
    if (next != inputs.len) return error.InvalidRiscCircuitCompositionInputs;
    for (circuit.outputs) |output| try ctx.eq(values[output], ctx.zero());
}
