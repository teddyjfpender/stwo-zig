//! Uniform direct-constraint view of the canonical opcode-family program.
//!
//! `constraint_program.Builder` owns construction of the active-row
//! expression, direct constraints, and lookup events.  This compatibility
//! facade requests only its direct section so the shipped per-row evaluator
//! does not construct lookup arrays it will not consume.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const constraint_program = @import("constraint_program.zig");
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
            var result: Self.Evaluation = undefined;
            try Self.evaluateInto(family, columns, is_active, &result);
            return result;
        }

        /// Caller-owned production row evaluator. This prevents the maximum
        /// family result buffer from crossing a return boundary on every row.
        pub fn evaluateInto(
            family: trace.OpcodeFamily,
            columns: []const S,
            is_active: S,
            result: *Self.Evaluation,
        ) !void {
            @setEvalBranchQuota(100_000);
            if (!isTraceCompatible(family)) return error.IncompatibleCommittedTrace;
            return switch (family) {
                .base_alu_imm => program.buildBaseAluImmDirectInto(columns, is_active, result),
                .base_alu_reg => program.buildBaseAluRegDirectInto(columns, is_active, result),
                .branch_eq => program.buildBranchEqDirectInto(columns, is_active, result),
                .branch_lt => program.buildBranchLtDirectInto(columns, is_active, result),
                .lt_imm => program.buildLtImmDirectInto(columns, is_active, result),
                .lt_reg => program.buildLtRegDirectInto(columns, is_active, result),
                .shifts_imm => program.buildShiftsImmDirectInto(columns, is_active, result),
                .shifts_reg => program.buildShiftsRegDirectInto(columns, is_active, result),
                .load_store => program.buildLoadStoreDirectInto(columns, is_active, result),
                .mul => program.buildMulDirectInto(columns, is_active, result),
                .mulh => program.buildMulhDirectInto(columns, is_active, result),
                .div => program.buildDivDirectInto(columns, is_active, result),
                .lui => program.buildLuiDirectInto(columns, is_active, result),
                .auipc => program.buildAuipcDirectInto(columns, is_active, result),
                .jalr => program.buildJalrDirectInto(columns, is_active, result),
                .jal => program.buildJalDirectInto(columns, is_active, result),
                .fence => program.buildFenceDirectInto(columns, is_active, result),
            };
        }
    };
}

/// Minimal base-field scalar adapter for the lifted-domain prover path.
///
/// Direct opcode constraints contain only base-field constants and operations.
/// Evaluating those polynomials in QM31 therefore performs four-coordinate
/// extension arithmetic on values whose upper three coordinates are known to
/// be zero. This wrapper preserves the generic semantics interface while
/// keeping the hot row loop in M31; the resulting residuals are embedded only
/// when they are folded by the transcript's secure random coefficients.
pub const BaseScalar = struct {
    value: M31,

    pub inline fn zero() BaseScalar {
        return fromBase(M31.zero());
    }

    pub inline fn one() BaseScalar {
        return fromBase(M31.one());
    }

    pub inline fn fromBase(value: M31) BaseScalar {
        return .{ .value = value };
    }

    pub inline fn isZero(self: BaseScalar) bool {
        return self.value.isZero();
    }

    pub inline fn add(lhs: BaseScalar, rhs: BaseScalar) BaseScalar {
        return fromBase(lhs.value.add(rhs.value));
    }

    pub inline fn sub(lhs: BaseScalar, rhs: BaseScalar) BaseScalar {
        return fromBase(lhs.value.sub(rhs.value));
    }

    pub inline fn mul(lhs: BaseScalar, rhs: BaseScalar) BaseScalar {
        return fromBase(lhs.value.mul(rhs.value));
    }
};

pub const BaseEval = Eval(BaseScalar);

const shipped = Eval(QM31);

pub const MAX_CONSTRAINTS = shipped.MAX_CONSTRAINTS;
pub const Evaluation = shipped.Evaluation;
pub const mainColumnCount = shipped.mainColumnCount;
pub const constraintCount = shipped.constraintCount;
pub const evaluate = shipped.evaluate;
pub const evaluateInto = shipped.evaluateInto;

pub fn isTraceCompatible(family: trace.OpcodeFamily) bool {
    _ = family;
    return true;
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

test "base-field domain evaluator matches QM31 embedding for every family" {
    var base_columns = [_]BaseScalar{BaseScalar.zero()} ** trace.MAX_FAMILY_COLUMNS;
    var secure_columns = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    for (&base_columns, &secure_columns, 0..) |*base, *secure, index| {
        const value = M31.fromU64(index *% 0x9e3779b1 +% 0x12345);
        base.* = BaseScalar.fromBase(value);
        secure.* = QM31.fromBase(value);
    }
    const base_active = BaseScalar.fromBase(M31.fromCanonical(7));
    const secure_active = QM31.fromBase(base_active.value);

    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        if (!isTraceCompatible(family)) continue;
        const n_columns = mainColumnCount(family);
        const base = try BaseEval.evaluate(
            family,
            base_columns[0..n_columns],
            base_active,
        );
        const secure = try evaluate(
            family,
            secure_columns[0..n_columns],
            secure_active,
        );
        try std.testing.expectEqual(base.len, secure.len);
        for (base.values[0..base.len], secure.values[0..secure.len]) |base_value, secure_value| {
            try std.testing.expect(secure_value.eql(QM31.fromBase(base_value.value)));
        }
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
