//! Compact mixed-height trace geometry and authenticated writer ownership.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const trace_schedule = @import("../trace_schedule.zig");
const types = @import("types.zig");

pub const Geometry = struct {
    cohorts: []types.Cohort,
    column_logs: []u32,
    column_offsets: []u32,

    pub fn deinit(self: Geometry, allocator: std.mem.Allocator) void {
        allocator.free(self.column_offsets);
        allocator.free(self.column_logs);
        allocator.free(self.cohorts);
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    columns: []const proof_ir.TraceColumn,
    tree: proof_ir.CommitmentTree,
) !Geometry {
    if (columns.len == 0) return error.InvalidTraceCommitPlan;
    var max_trace_log: u32 = 0;
    for (columns) |trace_column| {
        max_trace_log = @max(max_trace_log, trace_column.log_rows);
    }
    if (tree.evaluation_log_rows <= max_trace_log)
        return error.InvalidTraceCommitPlan;
    const blowup = tree.evaluation_log_rows - max_trace_log;
    const logs = try allocator.alloc(u32, columns.len);
    errdefer allocator.free(logs);
    const offsets = try allocator.alloc(u32, columns.len + 1);
    errdefer allocator.free(offsets);
    var cohorts = std.ArrayList(types.Cohort).empty;
    errdefer cohorts.deinit(allocator);

    var coefficient_offset: usize = 0;
    var evaluation_offset: usize = 0;
    var first: usize = 0;
    offsets[0] = 0;
    while (first < columns.len) {
        const trace_log = columns[first].log_rows;
        const evaluation_log = std.math.add(u32, trace_log, blowup) catch
            return error.TraceCommitGeometryOverflow;
        var end = first + 1;
        while (end < columns.len and columns[end].log_rows == trace_log)
            end += 1;
        const column_count = end - first;
        const coefficient_stride = try pow2usize(trace_log);
        const evaluation_stride = try pow2usize(evaluation_log);
        const coefficient_words = try mul(column_count, coefficient_stride);
        const evaluation_words = try mul(column_count, evaluation_stride);
        try cohorts.append(allocator, .{
            .first_column = @intCast(first),
            .column_count = @intCast(column_count),
            .trace_log_rows = trace_log,
            .evaluation_log_rows = evaluation_log,
            .coefficient_offset_words = coefficient_offset,
            .coefficient_words = coefficient_words,
            .evaluation_offset_words = evaluation_offset,
            .evaluation_words = evaluation_words,
        });
        for (first..end) |index| {
            logs[index] = columns[index].log_rows;
            offsets[index + 1] = std.math.cast(
                u32,
                coefficient_offset + (index - first + 1) * coefficient_stride,
            ) orelse return error.TraceCommitGeometryOverflow;
        }
        coefficient_offset = try add(coefficient_offset, coefficient_words);
        evaluation_offset = try add(evaluation_offset, evaluation_words);
        first = end;
    }
    return .{
        .cohorts = try cohorts.toOwnedSlice(allocator),
        .column_logs = logs,
        .column_offsets = offsets,
    };
}

pub fn compileWriterSpans(
    allocator: std.mem.Allocator,
    columns: []const proof_ir.TraceColumn,
    offsets: []const u32,
    schedule: trace_schedule.Schedule,
) ![]types.WriterSpan {
    const output = try allocator.alloc(types.WriterSpan, schedule.entries.len);
    errdefer allocator.free(output);
    const covered = try allocator.alloc(bool, columns.len);
    defer allocator.free(covered);
    @memset(covered, false);

    for (schedule.entries, output) |entry, *span| {
        var first: ?usize = null;
        var count: usize = 0;
        var trace_log: u32 = 0;
        for (columns, 0..) |trace_column, index| {
            if (trace_column.component != entry.component_index) continue;
            if (covered[index] or
                (first != null and index != first.? + count))
            {
                return error.InvalidTraceWriterSpan;
            }
            if (first == null) {
                first = index;
                trace_log = trace_column.log_rows;
            } else if (trace_column.log_rows != trace_log) {
                return error.InvalidTraceWriterSpan;
            }
            covered[index] = true;
            count += 1;
        }
        const begin = first orelse return error.MissingTraceWriterSpan;
        span.* = .{
            .schedule_ordinal = entry.canonical_ordinal,
            .component_index = entry.component_index,
            .first_column = @intCast(begin),
            .column_count = @intCast(count),
            .trace_log_rows = trace_log,
            .coefficient_offset_words = offsets[begin],
            .coefficient_words = @as(usize, offsets[begin + count]) -
                offsets[begin],
        };
    }
    for (covered) |is_covered| {
        if (!is_covered) return error.UnownedTraceColumn;
    }
    return output;
}

fn pow2usize(log_rows: u32) !usize {
    if (log_rows >= @bitSizeOf(usize))
        return error.TraceCommitGeometryOverflow;
    return @as(usize, 1) << @intCast(log_rows);
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch
        error.TraceCommitGeometryOverflow;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.TraceCommitGeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.TraceCommitGeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch
        error.TraceCommitGeometryOverflow;
}
