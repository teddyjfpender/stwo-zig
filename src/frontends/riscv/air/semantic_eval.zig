//! Uniform direct-constraint view of the canonical opcode-family program.
//!
//! `constraint_program.Builder` owns construction of the active-row
//! expression, direct constraints, and lookup events.  This compatibility
//! facade requests only its direct section so the shipped per-row evaluator
//! does not construct lookup arrays it will not consume.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const constraint_program = @import("constraint_program.zig");
const semantics = @import("semantics/mod.zig");
const trace = @import("../runner/trace.zig");

pub fn Eval(comptime S: type) type {
    return struct {
        const Self = @This();
        const program = constraint_program.Builder(S);

        pub const MAX_CONSTRAINTS: usize = program.MAX_DIRECT_CONSTRAINTS;
        pub const Evaluation = program.DirectConstraints;

        pub fn mainColumnCount(family: trace.OpcodeFamily) usize {
            return program.mainColumnCount(family);
        }

        pub fn constraintCount(family: trace.OpcodeFamily) usize {
            return program.constraintCount(family);
        }

        pub fn evaluate(
            family: trace.OpcodeFamily,
            columns: []const S,
            is_active: S,
        ) !Self.Evaluation {
            if (!isTraceCompatible(family)) return error.IncompatibleCommittedTrace;
            return (try program.buildDirect(family, columns, is_active)).direct_constraints;
        }
    };
}

const shipped = Eval(QM31);

pub const MAX_CONSTRAINTS = shipped.MAX_CONSTRAINTS;
pub const Evaluation = shipped.Evaluation;
pub const mainColumnCount = shipped.mainColumnCount;
pub const constraintCount = shipped.constraintCount;
pub const evaluate = shipped.evaluate;

pub fn isTraceCompatible(family: trace.OpcodeFamily) bool {
    return switch (family) {
        .base_alu_reg,
        .base_alu_imm,
        .branch_eq,
        .branch_lt,
        .lui,
        .auipc,
        .jalr,
        .jal,
        .fence,
        => true,
        .shifts_reg => semantics.shifts_reg.CURRENT_TRACE_COMPATIBLE,
        .shifts_imm => semantics.shifts_imm.CURRENT_TRACE_COMPATIBLE,
        .lt_reg => semantics.lt_reg.CURRENT_TRACE_COMPATIBLE,
        .lt_imm => semantics.lt_imm.CURRENT_TRACE_COMPATIBLE,
        .load_store => semantics.load_store.CURRENT_TRACE_COMPATIBLE,
        .mul => semantics.mul.CURRENT_TRACE_COMPATIBLE,
        .mulh => semantics.mulh.CURRENT_TRACE_COMPATIBLE,
        .div => semantics.div.CURRENT_TRACE_COMPATIBLE,
    };
}

pub fn clockColumn(family: trace.OpcodeFamily) usize {
    return switch (family) {
        .lui, .auipc, .jalr, .jal, .mul, .fence => 1,
        else => 0,
    };
}

pub fn pcColumn(family: trace.OpcodeFamily) usize {
    return clockColumn(family) + 1;
}

/// Every direct constraint remains degree three or lower.  In particular,
/// x0 writes use committed boolean write-enables and address inverses rather
/// than multiplying an already-cubic semantic equation by `rd`.
pub fn constraintLogDegreeBound(
    family: trace.OpcodeFamily,
    trace_log_size: u32,
) u32 {
    _ = family;
    return trace_log_size + 1;
}

test "semantic evaluator covers every family without exceeding its bound" {
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        try std.testing.expect(constraintCount(family) <= MAX_CONSTRAINTS);
        try std.testing.expectEqual(
            @as(usize, trace.nColumnsForFamily(family)),
            mainColumnCount(family),
        );
    }
}

test "semantic evaluator exposes schema-driven clock and pc columns" {
    try std.testing.expectEqual(@as(usize, 1), clockColumn(.lui));
    try std.testing.expectEqual(@as(usize, 2), pcColumn(.jalr));
    try std.testing.expectEqual(@as(usize, 1), clockColumn(.mul));
    try std.testing.expectEqual(@as(usize, 0), clockColumn(.base_alu_reg));
    try std.testing.expectEqual(@as(usize, 1), pcColumn(.load_store));
}

test "semantic evaluator accepts canonical inactive padding for compatible families" {
    var columns = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        if (!isTraceCompatible(family)) continue;
        const result = try evaluate(
            family,
            columns[0..mainColumnCount(family)],
            QM31.zero(),
        );
        try std.testing.expectEqual(constraintCount(family), result.len);
        try std.testing.expect(result.allZero());
    }
}

test "semantic evaluator rejects active placement for a padding row" {
    var columns = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        if (!isTraceCompatible(family)) continue;
        const result = try evaluate(
            family,
            columns[0..mainColumnCount(family)],
            QM31.one(),
        );
        try std.testing.expect(!result.allZero());
    }
}

test {
    // Keep the canonical builder's contract tests in the frontend test root;
    // Zig does not recursively collect tests from an implementation import.
    _ = @import("constraint_program.zig");
    _ = @import("lookups/opcode_entries.zig");
}
