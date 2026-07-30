//! Variable-stride resident tree views for exact mixed-height Blake columns.

const std = @import("std");
const geometry_mod = @import("geometry.zig");
const air_geometry = @import("stwo_native_examples").blake.geometry;

pub const GroupView = struct {
    component: geometry_mod.Component,
    column_offset: usize,
    column_count: usize,
    log_rows: u32,
    row_count: usize,
    arena_offset_words: usize,
    column_stride_words: usize,

    pub fn wordCount(self: GroupView) !usize {
        return std.math.mul(
            usize,
            self.column_count,
            self.column_stride_words,
        ) catch error.GeometryOverflow;
    }
};

pub const XorGroupView = struct {
    component: geometry_mod.Component,
    column_offset: usize,
    column_count: usize,
    log_rows: u32,
    row_count: usize,
    arena_offset_words: usize,
    column_stride_words: usize,
};

pub const TreeViews = struct {
    preprocessed: [air_geometry.XOR_TABLES.len]XorGroupView,
    main: [geometry_mod.component_count]GroupView,
    interaction: [geometry_mod.component_count]GroupView,
    composition: GroupView,

    pub fn init(geometry: geometry_mod.Geometry) !TreeViews {
        const logs = geometry.component_logs;
        const main = try groups(
            logs,
            geometry_mod.mainWidths(),
        );
        const interaction = try groups(
            logs,
            geometry_mod.interactionWidths(),
        );

        var preprocessed: [air_geometry.XOR_TABLES.len]XorGroupView =
            undefined;
        var preprocessed_column: usize = 0;
        var preprocessed_words: usize = 0;
        for (
            air_geometry.XOR_TABLES,
            preprocessed[0..],
            0..,
        ) |table, *view, index| {
            const log_rows = table.logSize();
            const row_count = try rowsAtLog(log_rows);
            view.* = .{
                .component = geometry_mod.component_order[index + 3],
                .column_offset = preprocessed_column,
                .column_count = 3,
                .log_rows = log_rows,
                .row_count = row_count,
                .arena_offset_words = preprocessed_words,
                .column_stride_words = row_count,
            };
            preprocessed_column += 3;
            preprocessed_words = try addWords(
                preprocessed_words,
                3,
                row_count,
            );
        }

        const composition_rows = try rowsAtLog(
            geometry.composition_column_log,
        );
        return .{
            .preprocessed = preprocessed,
            .main = main,
            .interaction = interaction,
            .composition = .{
                .component = .scheduler,
                .column_offset = 0,
                .column_count = geometry_mod.composition_columns,
                .log_rows = geometry.composition_column_log,
                .row_count = composition_rows,
                .arena_offset_words = 0,
                .column_stride_words = composition_rows,
            },
        };
    }

    pub fn validate(self: TreeViews, geometry: geometry_mod.Geometry) !void {
        try validateGroups(
            &self.main,
            geometry_mod.main_columns,
            geometry.main_words,
        );
        try validateGroups(
            &self.interaction,
            geometry_mod.interaction_columns,
            geometry.interaction_words,
        );
        var preprocessed_columns: usize = 0;
        var preprocessed_words: usize = 0;
        for (self.preprocessed) |view| {
            if (view.column_offset != preprocessed_columns or
                view.arena_offset_words != preprocessed_words or
                view.row_count != view.column_stride_words)
            {
                return error.InvalidResidentView;
            }
            preprocessed_columns += view.column_count;
            preprocessed_words = try addWords(
                preprocessed_words,
                view.column_count,
                view.column_stride_words,
            );
        }
        if (preprocessed_columns != geometry_mod.preprocessed_columns or
            preprocessed_words !=
                geometry.treeWords(.preprocessed))
        {
            return error.InvalidResidentView;
        }
        if (try self.composition.wordCount() != geometry.composition_words)
            return error.InvalidResidentView;
    }
};

fn groups(
    logs: [geometry_mod.component_count]u32,
    widths: [geometry_mod.component_count]usize,
) ![geometry_mod.component_count]GroupView {
    var result: [geometry_mod.component_count]GroupView = undefined;
    var column_offset: usize = 0;
    var arena_offset: usize = 0;
    for (
        geometry_mod.component_order,
        logs,
        widths,
        &result,
    ) |component, log_rows, column_count, *view| {
        const row_count = try rowsAtLog(log_rows);
        view.* = .{
            .component = component,
            .column_offset = column_offset,
            .column_count = column_count,
            .log_rows = log_rows,
            .row_count = row_count,
            .arena_offset_words = arena_offset,
            .column_stride_words = row_count,
        };
        column_offset = std.math.add(
            usize,
            column_offset,
            column_count,
        ) catch return error.GeometryOverflow;
        arena_offset = try addWords(
            arena_offset,
            column_count,
            row_count,
        );
    }
    return result;
}

fn validateGroups(
    groups_value: []const GroupView,
    expected_columns: usize,
    expected_words: usize,
) !void {
    var columns: usize = 0;
    var words: usize = 0;
    for (groups_value, geometry_mod.component_order) |view, component| {
        if (view.component != component or
            view.column_offset != columns or
            view.arena_offset_words != words or
            view.row_count != view.column_stride_words)
        {
            return error.InvalidResidentView;
        }
        columns += view.column_count;
        words = try addWords(
            words,
            view.column_count,
            view.column_stride_words,
        );
    }
    if (columns != expected_columns or words != expected_words)
        return error.InvalidResidentView;
}

fn rowsAtLog(log_rows: u32) !usize {
    if (log_rows >= @bitSizeOf(usize)) return error.GeometryOverflow;
    return @as(usize, 1) << @intCast(log_rows);
}

fn addWords(
    base: usize,
    columns: usize,
    rows: usize,
) !usize {
    const words = std.math.mul(usize, columns, rows) catch
        return error.GeometryOverflow;
    return std.math.add(usize, base, words) catch error.GeometryOverflow;
}

test "exact views pack variable-height columns without max-height padding" {
    const geometry = try geometry_mod.admit(.{
        .statement = .{ .log_n_rows = 4 },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
    });
    const value = try TreeViews.init(geometry);
    try value.validate(geometry);

    try std.testing.expectEqual(@as(usize, 0), value.main[0].column_offset);
    try std.testing.expectEqual(@as(usize, 384), value.main[1].column_offset);
    try std.testing.expectEqual(@as(usize, 1152), value.main[3].column_offset);
    try std.testing.expectEqual(@as(usize, 0), value.interaction[0].column_offset);
    try std.testing.expectEqual(@as(usize, 24), value.interaction[1].column_offset);
    try std.testing.expectEqual(@as(usize, 544), value.interaction[3].column_offset);
    try std.testing.expectEqual(@as(usize, 12), value.preprocessed[4].column_offset);
    try std.testing.expectEqual(@as(u32, 8), value.preprocessed[4].log_rows);

    const padded_main = geometry_mod.main_columns *
        (@as(usize, 1) << @intCast(geometry.max_trace_log));
    try std.testing.expect(geometry.main_words < padded_main);
}
