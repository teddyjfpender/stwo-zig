//! Scalar evaluator for the frozen typed sorted-memory row DAG. The same DAG
//! is used for committed-domain and verifier sampled-point quotient checks.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const lang = @import("../lang/definition.zig");

pub fn evaluate(
    comptime S: type,
    arena: *const lang.ir.Arena,
    inputs: []const S,
    scratch: []S,
    constraints: []S,
) !void {
    if (scratch.len != arena.nodeCount() or constraints.len != arena.constraintsView().len)
        return error.InvalidMemoryEvaluatorShape;
    var input_index: usize = 0;
    for (arena.nodesView(), 0..) |node, index| {
        scratch[index] = switch (node.key.op) {
            .input => blk: {
                if (input_index >= inputs.len) return error.InvalidMemoryEvaluatorShape;
                defer input_index += 1;
                break :blk inputs[input_index];
            },
            .constant => |constant| switch (constant) {
                .field, .unsigned => |value| scalar(S, value),
            },
            .add => |binary| at(S, scratch, binary.lhs).add(at(S, scratch, binary.rhs)),
            .sub => |binary| at(S, scratch, binary.lhs).sub(at(S, scratch, binary.rhs)),
            .mul => |binary| at(S, scratch, binary.lhs).mul(at(S, scratch, binary.rhs)),
            .neg => |value| at(S, scratch, value).neg(),
            .select => |selection| blk: {
                const gate = at(S, scratch, selection.selector);
                const no = at(S, scratch, selection.when_false);
                const yes = at(S, scratch, selection.when_true);
                break :blk no.add(gate.mul(yes.sub(no)));
            },
            else => return error.UnsupportedMemoryEvaluatorNode,
        };
    }
    if (input_index != inputs.len) return error.InvalidMemoryEvaluatorShape;
    for (arena.constraintsView(), constraints) |constraint, *value| value.* = at(S, scratch, constraint.root);
}

fn at(comptime S: type, scratch: []const S, id: lang.types.ValueId) S {
    return scratch[lang.types.idIndex(id)];
}
fn scalar(comptime S: type, value: u64) S {
    if (S == M) return M.fromU64(value);
    if (S == Q) return Q.fromBase(M.fromU64(value));
    @compileError("sorted-memory evaluator requires M31 or QM31");
}

test "typed sorted-memory DAG evaluates identically over M31 and embedded QM31" {
    const component = @import("memory_component.zig");
    const transition = @import("memory_transition.zig");
    const instance = @import("memory_instance.zig");
    const first = transition.Transition{ .space = 1, .address = 4096, .clock = 1, .before = 7, .after = 8 };
    const last = transition.Transition{ .space = 1, .address = 4096, .clock = 5, .before = 8, .after = 9 };
    const claim = try component.Claim.fromSummary(instance.Summary{ .first_row = 0, .rows = 2, .first = first, .last = last }, 2, 1, null);
    var definition = try component.build(std.testing.allocator, claim);
    defer definition.deinit();
    const row = try component.witness(first, last, false, true);
    const qinputs = try std.testing.allocator.alloc(Q, row.len);
    defer std.testing.allocator.free(qinputs);
    for (row, qinputs) |value, *out| out.* = Q.fromBase(value);
    const mwork = try std.testing.allocator.alloc(M, definition.arena.nodeCount());
    defer std.testing.allocator.free(mwork);
    const qwork = try std.testing.allocator.alloc(Q, definition.arena.nodeCount());
    defer std.testing.allocator.free(qwork);
    const mconstraints = try std.testing.allocator.alloc(M, definition.arena.constraintsView().len);
    defer std.testing.allocator.free(mconstraints);
    const qconstraints = try std.testing.allocator.alloc(Q, definition.arena.constraintsView().len);
    defer std.testing.allocator.free(qconstraints);
    try evaluate(M, &definition.arena, &row, mwork, mconstraints);
    try evaluate(Q, &definition.arena, qinputs, qwork, qconstraints);
    for (mconstraints, qconstraints) |m, q| try std.testing.expect(q.eql(Q.fromBase(m)));
}
