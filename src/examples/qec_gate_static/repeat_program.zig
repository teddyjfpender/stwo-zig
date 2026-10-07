//! Rebuild the public gate graph across consecutive circuit applications.

const std = @import("std");
const input = @import("input.zig");

/// A verifier must derive this graph from the same authenticated source bytes.
pub fn repeatProgram(allocator: std.mem.Allocator, base: *const input.Program, repetitions: u32) !input.Program {
    if (base.repetitions != 1 or repetitions == 0 or repetitions > 4) return error.InvalidRepetitionCount;
    const qubits = base.final_columns.len;
    const gate_count = try std.math.mul(usize, base.gates.len, repetitions);
    const gates = try allocator.alloc(input.Gate, gate_count);
    errdefer allocator.free(gates);
    const final_columns = try allocator.alloc(usize, qubits);
    errdefer allocator.free(final_columns);
    const map = try allocator.alloc(usize, base.columnCount());
    defer allocator.free(map);
    for (final_columns, 0..) |*column, index| column.* = index;
    for (0..repetitions) |rep| {
        for (final_columns, 0..) |column, index| map[index] = column;
        for (base.gates, 0..) |gate, index| {
            const output = qubits + rep * base.gates.len + index;
            gates[rep * base.gates.len + index] = .{
                .kind = gate.kind,
                .control1 = map[gate.control1],
                .control2 = map[gate.control2],
                .target_before = map[gate.target_before],
                .output = output,
            };
            map[gate.output] = output;
        }
        for (base.final_columns, final_columns) |column, *out| out.* = map[column];
    }
    return .{
        .allocator = allocator,
        .hash = base.hash,
        .width = base.width,
        .repetitions = repetitions,
        .challenge = base.challenge,
        .first_batch = base.first_batch,
        .gates = gates,
        .final_columns = final_columns,
    };
}
