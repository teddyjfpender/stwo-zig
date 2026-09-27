//! Genuine physical PCS frame for an authenticated caller-only native shape.
//! These rows prove invariant protocol geometry, never invented retirements.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
pub const TAG: u32 = 0x42354e46; // B5NF
pub const VERSION: u32 = 1;
pub const LOG_SIZE: u32 = 2;
pub const FIXED_COLUMNS: usize = 1;
pub const MAIN_COLUMNS: usize = 4;
pub const INTERACTION_COLUMNS: usize = 1;
pub const N_CONSTRAINTS: usize = MAIN_COLUMNS + 2;
pub const Expected = struct { values: [MAIN_COLUMNS]M };

/// Empty logical execution geometry remains unchanged. Host admission binds
/// public machine endpoints; real caller state proofs close the PC/clock bus.
pub fn required(shape: *const Shape) bool {
    return shape.n_components == 0 and shape.n_infra == 0;
}
pub fn expected(shape: *const Shape, external_retirements: u32) !Expected {
    try shape.validateBlake3ExecutionWithExternal(external_retirements);
    if (!required(shape) or external_retirements == 0 or
        external_retirements != shape.total_steps) return error.InvalidV5NativeFrameShape;
    const words = [_]u32{ TAG, VERSION, shape.total_steps, external_retirements };
    var values: [MAIN_COLUMNS]M = undefined;
    for (words, &values) |word, *value| {
        if (word >= core.fields.m31.Modulus) return error.InvalidV5NativeFrameWord;
        value.* = M.fromCanonical(word);
    }
    return .{ .values = values };
}

/// Pure semantic constraints shared by scalar PCS and recursive recorder.
/// Every expected value is template geometry, so it may be a setup constant.
pub fn evaluateGeneric(comptime S: type, selector: S, row: [MAIN_COLUMNS]S, pad: S, pinned: [MAIN_COLUMNS]S) [N_CONSTRAINTS]S {
    var checks: [N_CONSTRAINTS]S = undefined;
    checks[0] = selector.sub(S.one());
    for (row, pinned, checks[1 .. MAIN_COLUMNS + 1]) |value, target, *check| check.* = selector.mul(value.sub(target));
    checks[N_CONSTRAINTS - 1] = pad;
    return checks;
}
pub fn symbols(comptime S: type, pinned: Expected) [MAIN_COLUMNS]S {
    var values: [MAIN_COLUMNS]S = undefined;
    for (pinned.values, &values) |value, *out| out.* = S.fromBase(value);
    return values;
}

/// Arena allocation is suitable: commitBorrowedStreaming owns its LDE copy.
pub fn fixedColumns(a: std.mem.Allocator) ![]Column {
    return constantColumns(a, &.{M.one()});
}
pub fn mainColumns(a: std.mem.Allocator, pinned: Expected) ![]Column {
    return constantColumns(a, &pinned.values);
}
/// A constrained physical pad is not a relation claim or synthetic event.
pub fn interactionColumns(a: std.mem.Allocator) ![]Column {
    return constantColumns(a, &.{M.zero()});
}
pub fn freeColumns(a: std.mem.Allocator, columns: []Column) void {
    for (columns) |column| a.free(column.values);
    a.free(columns);
}
fn constantColumns(a: std.mem.Allocator, constants: []const M) ![]Column {
    const columns = try a.alloc(Column, constants.len);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| a.free(column.values);
        a.free(columns);
    }
    for (columns, constants) |*column, value| {
        const values = try a.alloc(M, 1 << LOG_SIZE);
        @memset(values, value);
        column.* = .{ .log_size = LOG_SIZE, .values = values };
        initialized += 1;
    }
    return columns;
}

pub fn mixGeometry(channel: anytype) void {
    channel.mixU32s(&.{ TAG, VERSION, LOG_SIZE, FIXED_COLUMNS, MAIN_COLUMNS, INTERACTION_COLUMNS, N_CONSTRAINTS });
}
