//! Uniform direct-constraint evaluation for committed opcode-family rows.
//!
//! Relation requests remain in the family semantic modules and are placed by
//! the interaction layer. This module owns only direct constraints plus the
//! exact component-placement equality used identically on-domain and OODS.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const semantics = @import("semantics/mod.zig");
const trace = @import("../runner/trace.zig");

pub fn Eval(comptime S: type) type {
    return struct {
        // `Self`-qualified inside: the file re-exports these names for the
        // shipped QM31 instantiation, and a name that resolves both inside and
        // outside the generic is a compile error.
        const Self = @This();
        const sem = semantics.Families(S);

        pub const MAX_CONSTRAINTS: usize = sem.div.N_CONSTRAINTS + 1;

        pub const Evaluation = struct {
            // Only `values[0..len]` is meaningful; the tail is never read.
            values: [Self.MAX_CONSTRAINTS]S = undefined,
            len: usize = 0,

            pub fn allZero(self: @This()) bool {
                for (self.values[0..self.len]) |value| {
                    if (!value.isZero()) return false;
                }
                return true;
            }
        };

        pub fn mainColumnCount(family: trace.OpcodeFamily) usize {
            return switch (family) {
                .base_alu_reg => moduleColumnCount(sem.base_alu_reg),
                .base_alu_imm => moduleColumnCount(sem.base_alu_imm),
                .shifts_reg => moduleColumnCount(sem.shifts_reg),
                .shifts_imm => moduleColumnCount(sem.shifts_imm),
                .lt_reg => moduleColumnCount(sem.lt_reg),
                .lt_imm => moduleColumnCount(sem.lt_imm),
                .branch_eq => moduleColumnCount(sem.branch_eq),
                .branch_lt => moduleColumnCount(sem.branch_lt),
                .lui => moduleColumnCount(sem.lui),
                .auipc => moduleColumnCount(sem.auipc),
                .jalr => moduleColumnCount(sem.jalr),
                .jal => moduleColumnCount(sem.jal),
                .load_store => moduleColumnCount(sem.load_store),
                .mul => moduleColumnCount(sem.mul),
                .mulh => moduleColumnCount(sem.mulh),
                .div => moduleColumnCount(sem.div),
                .fence => moduleColumnCount(sem.fence),
            };
        }

        pub fn constraintCount(family: trace.OpcodeFamily) usize {
            return switch (family) {
                .base_alu_reg => moduleConstraintCount(sem.base_alu_reg),
                .base_alu_imm => moduleConstraintCount(sem.base_alu_imm),
                .shifts_reg => moduleConstraintCount(sem.shifts_reg),
                .shifts_imm => moduleConstraintCount(sem.shifts_imm),
                .lt_reg => moduleConstraintCount(sem.lt_reg),
                .lt_imm => moduleConstraintCount(sem.lt_imm),
                .branch_eq => moduleConstraintCount(sem.branch_eq),
                .branch_lt => moduleConstraintCount(sem.branch_lt),
                .lui => moduleConstraintCount(sem.lui),
                .auipc => moduleConstraintCount(sem.auipc),
                .jalr => moduleConstraintCount(sem.jalr),
                .jal => moduleConstraintCount(sem.jal),
                .load_store => moduleConstraintCount(sem.load_store),
                .mul => moduleConstraintCount(sem.mul),
                .mulh => moduleConstraintCount(sem.mulh),
                .div => moduleConstraintCount(sem.div),
                .fence => moduleConstraintCount(sem.fence),
            };
        }

        pub fn evaluate(
            family: trace.OpcodeFamily,
            columns: []const S,
            is_active: S,
        ) !Self.Evaluation {
            if (!isTraceCompatible(family)) return error.IncompatibleCommittedTrace;
            return switch (family) {
                .base_alu_reg => evaluateModule(sem.base_alu_reg, columns, is_active),
                .base_alu_imm => evaluateModule(sem.base_alu_imm, columns, is_active),
                .shifts_reg => evaluateModule(sem.shifts_reg, columns, is_active),
                .shifts_imm => evaluateModule(sem.shifts_imm, columns, is_active),
                .lt_reg => evaluateModule(sem.lt_reg, columns, is_active),
                .lt_imm => evaluateModule(sem.lt_imm, columns, is_active),
                .branch_eq => evaluateModule(sem.branch_eq, columns, is_active),
                .branch_lt => evaluateModule(sem.branch_lt, columns, is_active),
                .lui => evaluateModule(sem.lui, columns, is_active),
                .auipc => evaluateModule(sem.auipc, columns, is_active),
                .jalr => evaluateModule(sem.jalr, columns, is_active),
                .jal => evaluateModule(sem.jal, columns, is_active),
                .load_store => evaluateModule(sem.load_store, columns, is_active),
                .mul => evaluateModule(sem.mul, columns, is_active),
                .mulh => evaluateModule(sem.mulh, columns, is_active),
                .div => evaluateModule(sem.div, columns, is_active),
                .fence => evaluateModule(sem.fence, columns, is_active),
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
            columns: []const S,
            is_active: S,
        ) !Self.Evaluation {
            const n_columns = comptime moduleColumnCount(Module);
            if (columns.len != n_columns) return error.InvalidMainTraceShape;
            var sampled: [n_columns]S = undefined;
            @memcpy(&sampled, columns);
            const row = if (@hasDecl(Module.Row, "fromOracleColumns"))
                try Module.Row.fromOracleColumns(&sampled)
            else
                try Module.Row.fromMainColumns(&sampled);
            const constraints = Module.evaluate(row);
            var result = Self.Evaluation{};
            for (constraints.values) |constraint| {
                result.values[result.len] = constraint;
                result.len += 1;
            }
            result.values[result.len] = Module.placementConstraint(row, is_active);
            result.len += 1;
            std.debug.assert(result.len == moduleConstraintCount(Module));
            return result;
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
