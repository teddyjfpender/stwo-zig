//! PCS column and coefficient ownership policy.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const prover_circle = @import("../../poly/circle/mod.zig");
const commitment_tree = @import("../commitment_tree.zig");

const M31 = m31.M31;
const ColumnEvaluation = commitment_tree.ColumnEvaluation;
const coefficient_storage_auto_max_bytes: usize = 8 * 1024 * 1024;

pub const CoefficientRetentionPolicy = enum {
    auto,
    always,
    never,
};

pub const PreparedCommitmentColumns = struct {
    columns: []ColumnEvaluation,
    coefficients: ?[]prover_circle.CircleCoefficients,
    column_backing_buffers: ?[][]M31 = null,
    column_backing_alignment: std.mem.Alignment = .of(M31),
    /// Contiguous buffers borrowed by coefficient entries.
    coefficient_backing_buffers: ?[][]M31 = null,

    pub fn deinit(self: *PreparedCommitmentColumns, allocator: std.mem.Allocator) void {
        if (self.column_backing_buffers) |buffers| {
            allocator.free(self.columns);
            @import("../backed_columns.zig").freeBuffers(allocator, buffers, self.column_backing_alignment);
        } else {
            freeOwnedColumnEvaluations(allocator, self.columns);
        }
        if (self.coefficients) |coefficients| {
            deinitOwnedCoefficientColumns(allocator, coefficients);
        }
        if (self.coefficient_backing_buffers) |buffers| {
            for (buffers) |buffer| allocator.free(buffer);
            allocator.free(buffers);
        }
        self.* = undefined;
    }
};

pub fn shouldRetainCoefficients(
    columns: []const ColumnEvaluation,
    retention_policy: CoefficientRetentionPolicy,
) bool {
    return switch (retention_policy) {
        .always => true,
        .never => false,
        .auto => blk: {
            var total_bytes: usize = 0;
            for (columns) |column| {
                const column_bytes = std.math.mul(
                    usize,
                    column.values.len,
                    @sizeOf(M31),
                ) catch break :blk false;
                total_bytes = std.math.add(usize, total_bytes, column_bytes) catch
                    break :blk false;
                if (total_bytes > coefficient_storage_auto_max_bytes) break :blk false;
            }
            break :blk true;
        },
    };
}

pub fn shouldRetainPolynomialCoefficients(
    polynomials: []const prover_circle.CircleCoefficients,
    retention_policy: CoefficientRetentionPolicy,
) bool {
    return switch (retention_policy) {
        .always => true,
        .never => false,
        .auto => blk: {
            var total_bytes: usize = 0;
            for (polynomials) |polynomial| {
                const polynomial_bytes = std.math.mul(
                    usize,
                    polynomial.coefficients().len,
                    @sizeOf(M31),
                ) catch break :blk false;
                total_bytes = std.math.add(usize, total_bytes, polynomial_bytes) catch
                    break :blk false;
                if (total_bytes > coefficient_storage_auto_max_bytes) break :blk false;
            }
            break :blk true;
        },
    };
}

pub fn deinitOwnedCoefficientColumns(
    allocator: std.mem.Allocator,
    columns: []prover_circle.CircleCoefficients,
) void {
    for (columns) |*coefficient| coefficient.deinit(allocator);
    allocator.free(columns);
}

pub fn freeOwnedColumnEvaluations(
    allocator: std.mem.Allocator,
    columns: []const ColumnEvaluation,
) void {
    for (columns) |column| {
        if (column.values.len != 0) allocator.free(column.values);
    }
    allocator.free(columns);
}
