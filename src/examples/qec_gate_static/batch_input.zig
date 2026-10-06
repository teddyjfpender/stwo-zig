//! Sixty-four distinct SHAKE-derived shots for the pinned public first batch.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const input = @import("input.zig");
const M31 = core.fields.m31.M31;

pub const Statement = struct {
    circuit_hash: [32]u8,
    width: u16,
    gate_count: u32,
    batch_index: u32 = 0,
    log_rows: u32 = 6,
};

pub fn statement(program: *const input.Program) Statement {
    return .{
        .circuit_hash = program.hash,
        .width = @intCast(program.width),
        .gate_count = @intCast(program.gates.len),
    };
}

pub fn validate(program: *const input.Program, s: Statement) !void {
    if (s.log_rows != 6 or s.batch_index != 0 or s.width != program.width or
        s.gate_count != program.gates.len or
        !std.mem.eql(u8, &s.circuit_hash, &program.hash)) return error.InvalidStatement;
}

pub fn generateFixed(allocator: std.mem.Allocator, program: *const input.Program, s: Statement) ![]prover.pcs.ColumnEvaluation {
    try validate(program, s);
    const qubits = program.final_columns.len;
    const columns = try allocateColumns(allocator, qubits * 2, s.log_rows);
    errdefer deinitColumns(allocator, columns);
    for (0..64) |shot| {
        const storage = try core.air.utils.circleBitReversedIndex(s.log_rows, shot);
        for (0..qubits) |q| {
            @constCast(columns[q].values)[storage] = input.pinChallenge(program.first_batch[shot], program.width, q, false);
            @constCast(columns[qubits + q].values)[storage] = input.pinChallenge(program.first_batch[shot], program.width, q, true);
        }
    }
    return columns;
}

pub fn generateMain(allocator: std.mem.Allocator, program: *const input.Program, s: Statement, fixed: []const prover.pcs.ColumnEvaluation) ![]prover.pcs.ColumnEvaluation {
    try validate(program, s);
    const qubits = program.final_columns.len;
    if (fixed.len != qubits * 2) return error.InvalidTrace;
    const columns = try allocateColumns(allocator, program.gates.len, s.log_rows);
    errdefer deinitColumns(allocator, columns);
    for (program.gates, 0..) |gate, i| {
        for (0..64) |storage| {
            const before = sourceValue(fixed, columns, qubits, gate.target_before, storage);
            const control1 = sourceValue(fixed, columns, qubits, gate.control1, storage);
            const control2 = if (gate.kind == .ccx)
                sourceValue(fixed, columns, qubits, gate.control2, storage)
            else
                M31.one();
            @constCast(columns[i].values)[storage] = M31.fromCanonical(before.v ^ (control1.v & control2.v));
        }
    }
    return columns;
}

pub fn sourceValue(fixed: []const prover.pcs.ColumnEvaluation, main: []const prover.pcs.ColumnEvaluation, qubits: usize, column: usize, storage: usize) M31 {
    return if (column < qubits) fixed[column].values[storage] else main[column - qubits].values[storage];
}

fn allocateColumns(allocator: std.mem.Allocator, count: usize, log_rows: u32) ![]prover.pcs.ColumnEvaluation {
    const columns = try allocator.alloc(prover.pcs.ColumnEvaluation, count);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |col| allocator.free(col.values);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = .{ .log_size = log_rows, .values = try allocator.alloc(M31, @as(usize, 1) << @intCast(log_rows)) };
        initialized += 1;
    }
    return columns;
}

pub fn deinitColumns(allocator: std.mem.Allocator, columns: []prover.pcs.ColumnEvaluation) void {
    for (columns) |col| allocator.free(col.values);
    allocator.free(columns);
}

test "first batch has distinct exact SHAKE shots and correct bit-reversed public columns" {
    const bytes = @embedFile("fixtures/iadd256.kmx");
    var program = try input.parse(std.testing.allocator, bytes);
    defer program.deinit();
    const s = statement(&program);
    const columns = try generateFixed(std.testing.allocator, &program, s);
    defer deinitColumns(std.testing.allocator, columns);
    try std.testing.expect(program.first_batch[0].target != program.first_batch[1].target);
    for (0..64) |shot| {
        const storage = try core.air.utils.circleBitReversedIndex(6, shot);
        for (0..512) |q| {
            try std.testing.expect(columns[q].values[storage].eql(input.pinChallenge(program.first_batch[shot], 256, q, false)));
            try std.testing.expect(columns[512 + q].values[storage].eql(input.pinChallenge(program.first_batch[shot], 256, q, true)));
        }
    }
    const main = try generateMain(std.testing.allocator, &program, s, columns);
    defer deinitColumns(std.testing.allocator, main);
    for (0..64) |shot| {
        const storage = try core.air.utils.circleBitReversedIndex(6, shot);
        for (program.final_columns, 0..) |column, q| {
            const actual = sourceValue(columns, main, 512, column, storage);
            try std.testing.expect(actual.eql(columns[512 + q].values[storage]));
        }
    }
}
