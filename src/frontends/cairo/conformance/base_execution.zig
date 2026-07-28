//! Rust-checkpoint comparison for backend-neutral Cairo witness executions.

const std = @import("std");
const checkpoint = @import("checkpoint.zig");
const component_executor = @import("../witness/component_executor.zig");
const component_layout = @import("../witness/component_layout.zig");

pub const MismatchKind = enum {
    column_count,
    column_digest,
};

pub const Mismatch = struct {
    kind: MismatchKind,
    component_ordinal: u32,
    component_label: []const u8,
    column_ordinal: ?u32 = null,
    expected_count: ?u64 = null,
    actual_count: ?u64 = null,
    expected_digest: ?checkpoint.Digest = null,
    actual_digest: ?checkpoint.Digest = null,
};

pub fn layout(expected: checkpoint.Component) !component_layout.ComponentLayout {
    if (expected.columns.len == 0 or expected.columns.len > std.math.maxInt(u32))
        return error.InvalidReceiptGeometry;
    const row_count = std.math.cast(u32, expected.columns[0].row_count) orelse
        return error.InvalidReceiptGeometry;
    for (expected.columns, 0..) |column, column_index| {
        if (column.ordinal != column_index or column.row_count != row_count)
            return error.InvalidReceiptGeometry;
    }
    const result = component_layout.ComponentLayout{
        .ordinal = expected.ordinal,
        .label = expected.label,
        .row_count = row_count,
        .column_count = @intCast(expected.columns.len),
    };
    result.validate() catch return error.InvalidReceiptGeometry;
    return result;
}

pub fn compare(
    expected: checkpoint.Component,
    execution: component_executor.Execution,
) !?Mismatch {
    if (expected.columns.len != execution.output_columns.len) return .{
        .kind = .column_count,
        .component_ordinal = expected.ordinal,
        .component_label = expected.label,
        .expected_count = expected.columns.len,
        .actual_count = execution.output_columns.len,
    };
    for (expected.columns, execution.output_columns) |expected_column, values| {
        const actual_digest = try checkpoint.digestColumn(
            expected.ordinal,
            expected.label,
            expected_column.ordinal,
            values,
        );
        if (!std.mem.eql(u8, &expected_column.sha256, &actual_digest)) return .{
            .kind = .column_digest,
            .component_ordinal = expected.ordinal,
            .component_label = expected.label,
            .column_ordinal = expected_column.ordinal,
            .expected_digest = expected_column.sha256,
            .actual_digest = actual_digest,
        };
    }
    return null;
}
