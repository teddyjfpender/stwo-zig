//! Selected trace spans recovered from a retained immutable PCS prefix.
//! Unselected columns retain geometry only; no witness matrix is regenerated.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Column = engine.pcs.ColumnEvaluation;
const Recover = @import("block_v5_committed_trace_column_v1.zig");
pub const Range = struct {
    fixed_offset: usize,
    fixed_width: usize,
    main_offset: usize,
    main_width: usize,
    log_size: u32,
};
pub const Columns = struct {
    fixed: []Column,
    main: []Column,
    pub fn deinit(self: *Columns, a: std.mem.Allocator) void {
        free(a, self.fixed);
        free(a, self.main);
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, scheme: anytype, fixed_logs: []const u32, main_logs: []const u32, ranges: []const Range) !Columns {
        try validateTrees(scheme, fixed_logs, main_logs);
        if (ranges.len == 0) return error.EmptyV5CommittedProjection;
        const fixed = try placeholders(a, fixed_logs);
        errdefer free(a, fixed);
        const main = try placeholders(a, main_logs);
        errdefer free(a, main);
        var maximum_log: u32 = 0;
        for (ranges) |range| {
            if (range.log_size == 0 or range.log_size > 24)
                return error.InvalidV5CommittedProjectionRange;
            maximum_log = @max(maximum_log, try transformLog(fixed, scheme.trees.items[0].columns, range.fixed_offset, range.fixed_width, range.log_size));
            maximum_log = @max(maximum_log, try transformLog(main, scheme.trees.items[1].columns, range.main_offset, range.main_width, range.log_size));
        }
        // Every selected interpolation and trace evaluation borrows one tower.
        // No unselected column increases its bounded transform footprint.
        var batch: ?Recover.Batch = if (maximum_log == 0) null else try Recover.Batch.init(a, maximum_log);
        defer if (batch) |*owned| owned.deinit();
        for (ranges) |range| {
            if (range.log_size == 0 or range.log_size > 24)
                return error.InvalidV5CommittedProjectionRange;
            try recoverSpan(if (batch) |*owned| owned else null, fixed, scheme.trees.items[0].columns, range.fixed_offset, range.fixed_width, range.log_size);
            try recoverSpan(if (batch) |*owned| owned else null, main, scheme.trees.items[1].columns, range.main_offset, range.main_width, range.log_size);
        }
        return .{ .fixed = fixed, .main = main };
    }
};
/// Independent profile geometry must match every retained first-round column,
/// even those the selected quotient does not open. This checks no proof claim.
pub fn validateTrees(scheme: anytype, fixed_logs: []const u32, main_logs: []const u32) !void {
    if (scheme.trees.items.len != 2 or
        scheme.trees.items[0].columns.len != fixed_logs.len or
        scheme.trees.items[1].columns.len != main_logs.len)
        return error.InvalidV5CommittedProjectionGeometry;
    inline for (.{ fixed_logs, main_logs }, 0..) |logs, tree| {
        for (logs, scheme.trees.items[tree].columns) |log, column| {
            if (log == 0 or log > 24 or
                column.log_size != try std.math.add(u32, log, scheme.config.fri_config.log_blowup_factor))
                return error.InvalidV5CommittedProjectionGeometry;
            try column.validateRetained();
        }
    }
}
fn transformLog(output: []const Column, source: []const Column, offset: usize, width: usize, log: u32) !u32 {
    const end = std.math.add(usize, offset, width) catch return error.InvalidV5CommittedProjectionRange;
    if (end > output.len or end > source.len) return error.InvalidV5CommittedProjectionRange;
    var maximum: u32 = 0;
    for (offset..end) |index| {
        if (output[index].log_size != log) return error.InvalidV5CommittedProjectionRange;
        maximum = @max(maximum, try Recover.requiredTransformLog(source[index], log));
    }
    return maximum;
}
fn recoverSpan(batch: ?*const Recover.Batch, output: []Column, source: []const Column, offset: usize, width: usize, log: u32) !void {
    const end = std.math.add(usize, offset, width) catch return error.InvalidV5CommittedProjectionRange;
    if (end > output.len or end > source.len) return error.InvalidV5CommittedProjectionRange;
    for (offset..end) |index| {
        if (output[index].log_size != log) return error.InvalidV5CommittedProjectionRange;
        if (output[index].values.len == 0) output[index] = try (batch orelse return error.InvalidV5CommittedProjectionRange).recover(source[index], log);
    }
}
fn placeholders(a: std.mem.Allocator, logs: []const u32) ![]Column {
    const result = try a.alloc(Column, logs.len);
    for (result, logs) |*column, log| column.* = .{ .log_size = log, .values = &.{} };
    return result;
}
fn free(a: std.mem.Allocator, columns: []Column) void {
    for (columns) |column| a.free(column.values);
    a.free(columns);
}
