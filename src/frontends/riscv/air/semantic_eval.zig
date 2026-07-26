//! Uniform direct-constraint evaluation for committed opcode-family rows.
//!
//! Relation requests remain in the family semantic modules and are placed by
//! the interaction layer. This module owns only direct constraints plus the
//! exact component-placement equality used identically on-domain and OODS.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const semantics = @import("semantics/mod.zig");
const trace = @import("../runner/trace.zig");

pub const MAX_CONSTRAINTS: usize = semantics.div.N_CONSTRAINTS + 1;

pub const Evaluation = struct {
    values: [MAX_CONSTRAINTS]QM31 = .{QM31.zero()} ** MAX_CONSTRAINTS,
    len: usize = 0,

    pub fn allZero(self: Evaluation) bool {
        for (self.values[0..self.len]) |value| {
            if (!value.isZero()) return false;
        }
        return true;
    }
};

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

pub fn mainColumnCount(family: trace.OpcodeFamily) usize {
    return switch (family) {
        .base_alu_reg => moduleColumnCount(semantics.base_alu_reg),
        .base_alu_imm => moduleColumnCount(semantics.base_alu_imm),
        .shifts_reg => moduleColumnCount(semantics.shifts_reg),
        .shifts_imm => moduleColumnCount(semantics.shifts_imm),
        .lt_reg => moduleColumnCount(semantics.lt_reg),
        .lt_imm => moduleColumnCount(semantics.lt_imm),
        .branch_eq => moduleColumnCount(semantics.branch_eq),
        .branch_lt => moduleColumnCount(semantics.branch_lt),
        .lui => moduleColumnCount(semantics.lui),
        .auipc => moduleColumnCount(semantics.auipc),
        .jalr => moduleColumnCount(semantics.jalr),
        .jal => moduleColumnCount(semantics.jal),
        .load_store => moduleColumnCount(semantics.load_store),
        .mul => moduleColumnCount(semantics.mul),
        .mulh => moduleColumnCount(semantics.mulh),
        .div => moduleColumnCount(semantics.div),
        .fence => moduleColumnCount(semantics.fence),
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

pub fn constraintCount(family: trace.OpcodeFamily) usize {
    return switch (family) {
        .base_alu_reg => moduleConstraintCount(semantics.base_alu_reg),
        .base_alu_imm => moduleConstraintCount(semantics.base_alu_imm),
        .shifts_reg => moduleConstraintCount(semantics.shifts_reg),
        .shifts_imm => moduleConstraintCount(semantics.shifts_imm),
        .lt_reg => moduleConstraintCount(semantics.lt_reg),
        .lt_imm => moduleConstraintCount(semantics.lt_imm),
        .branch_eq => moduleConstraintCount(semantics.branch_eq),
        .branch_lt => moduleConstraintCount(semantics.branch_lt),
        .lui => moduleConstraintCount(semantics.lui),
        .auipc => moduleConstraintCount(semantics.auipc),
        .jalr => moduleConstraintCount(semantics.jalr),
        .jal => moduleConstraintCount(semantics.jal),
        .load_store => moduleConstraintCount(semantics.load_store),
        .mul => moduleConstraintCount(semantics.mul),
        .mulh => moduleConstraintCount(semantics.mulh),
        .div => moduleConstraintCount(semantics.div),
        .fence => moduleConstraintCount(semantics.fence),
    };
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

pub fn evaluate(
    family: trace.OpcodeFamily,
    columns: []const QM31,
    is_active: QM31,
) !Evaluation {
    if (!isTraceCompatible(family)) return error.IncompatibleCommittedTrace;
    return switch (family) {
        .base_alu_reg => evaluateModule(semantics.base_alu_reg, columns, is_active),
        .base_alu_imm => evaluateModule(semantics.base_alu_imm, columns, is_active),
        .shifts_reg => evaluateModule(semantics.shifts_reg, columns, is_active),
        .shifts_imm => evaluateModule(semantics.shifts_imm, columns, is_active),
        .lt_reg => evaluateModule(semantics.lt_reg, columns, is_active),
        .lt_imm => evaluateModule(semantics.lt_imm, columns, is_active),
        .branch_eq => evaluateModule(semantics.branch_eq, columns, is_active),
        .branch_lt => evaluateModule(semantics.branch_lt, columns, is_active),
        .lui => evaluateModule(semantics.lui, columns, is_active),
        .auipc => evaluateModule(semantics.auipc, columns, is_active),
        .jalr => evaluateModule(semantics.jalr, columns, is_active),
        .jal => evaluateModule(semantics.jal, columns, is_active),
        .load_store => evaluateModule(semantics.load_store, columns, is_active),
        .mul => evaluateModule(semantics.mul, columns, is_active),
        .mulh => evaluateModule(semantics.mulh, columns, is_active),
        .div => evaluateModule(semantics.div, columns, is_active),
        .fence => evaluateModule(semantics.fence, columns, is_active),
    };
}

fn moduleColumnCount(comptime Module: type) usize {
    return if (@hasDecl(Module, "N_ORACLE_COLUMNS"))
        Module.N_ORACLE_COLUMNS
    else
        Module.N_MAIN_COLUMNS;
}

fn moduleConstraintCount(comptime Module: type) usize {
    return Module.N_CONSTRAINTS + 1;
}

fn evaluateModule(
    comptime Module: type,
    columns: []const QM31,
    is_active: QM31,
) !Evaluation {
    const n_columns = comptime moduleColumnCount(Module);
    if (columns.len != n_columns) return error.InvalidMainTraceShape;
    var sampled: [n_columns]QM31 = undefined;
    @memcpy(&sampled, columns);
    const row = if (@hasDecl(Module.Row, "fromOracleColumns"))
        try Module.Row.fromOracleColumns(&sampled)
    else
        try Module.Row.fromMainColumns(&sampled);
    const constraints = Module.evaluate(row);
    var result = Evaluation{};
    for (constraints.values) |constraint| {
        result.values[result.len] = constraint;
        result.len += 1;
    }
    result.values[result.len] = Module.placementConstraint(row, is_active);
    result.len += 1;
    std.debug.assert(result.len == moduleConstraintCount(Module));
    return result;
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
