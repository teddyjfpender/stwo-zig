//! Base-trace arena layout tests.
//!
//! These live in the frontend test root rather than beside the planner because
//! `zig build addTest` only collects tests from its root module's own files;
//! tests inside the `cairo_frontend` dependency module compile but never run.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_impl");
const cairo = @import("cairo_frontend");

const trace_arena = cairo.proving.trace_arena;
const composition_bundle = cairo.witness.composition_bundle;
const Error = trace_arena.Error;
const M31 = core.fields.m31.M31;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;

fn pageWords() usize {
    const page = std.heap.pageSize();
    return @max(@as(usize, 1), page / @sizeOf(M31));
}

fn testComponent(
    allocator: std.mem.Allocator,
    label: []const u8,
    trace_log_size: u32,
    base: [2]u32,
    interaction: [2]u32,
) !composition_bundle.Component {
    const spans = try allocator.alloc(composition_bundle.TraceSpan, 2);
    spans[0] = .{ .tree = 1, .start = base[0], .end = base[1] };
    spans[1] = .{ .tree = 2, .start = interaction[0], .end = interaction[1] };
    return .{
        .label = try allocator.dupe(u8, label),
        .instance = 0,
        .trace_log_size = trace_log_size,
        .evaluation_log_size = trace_log_size + 1,
        .n_constraints = 1,
        .random_coefficient_offset = 0,
        .trace_spans = spans,
        .preprocessed_indices = &.{},
        .denominator_inverses = &.{},
        .ext_sources = &.{},
        .parts = &.{},
    };
}

fn freeTestComponents(
    allocator: std.mem.Allocator,
    components: []composition_bundle.Component,
) void {
    for (components) |component| {
        allocator.free(component.trace_spans);
        allocator.free(component.label);
    }
    allocator.free(components);
}

test "layout groups columns by log size in first-appearance order" {
    const allocator = std.testing.allocator;
    const components = try allocator.alloc(composition_bundle.Component, 3);
    components[0] = try testComponent(allocator, "a", 18, .{ 0, 2 }, .{ 0, 4 });
    components[1] = try testComponent(allocator, "b", 17, .{ 2, 3 }, .{ 4, 8 });
    components[2] = try testComponent(allocator, "c", 18, .{ 3, 5 }, .{ 8, 12 });
    defer freeTestComponents(allocator, components);

    var layout = try trace_arena.plan(allocator, components);
    defer layout.deinit();

    try std.testing.expectEqual(@as(usize, 5), layout.columnCount());
    try std.testing.expectEqual(@as(usize, 2), layout.groups.len);
    try std.testing.expectEqual(@as(u32, 18), layout.groups[0].log_size);
    try std.testing.expectEqual(@as(usize, 4), layout.groups[0].column_count);
    try std.testing.expectEqual(@as(u32, 17), layout.groups[1].log_size);
    try std.testing.expectEqual(@as(usize, 1), layout.groups[1].column_count);

    // Flat columns 0,1 (component a) and 3,4 (component c) share group 0 and
    // must be contiguous in flat order inside it.
    const rows18 = @as(usize, 1) << 18;
    try std.testing.expectEqual(layout.groups[0].offset, layout.offsets[0]);
    try std.testing.expectEqual(layout.groups[0].offset + rows18, layout.offsets[1]);
    try std.testing.expectEqual(layout.groups[0].offset + 2 * rows18, layout.offsets[3]);
    try std.testing.expectEqual(layout.groups[0].offset + 3 * rows18, layout.offsets[4]);
    try std.testing.expectEqual(layout.groups[1].offset, layout.offsets[2]);

    try std.testing.expectEqual(@as(usize, 0), layout.component_starts[0]);
    try std.testing.expectEqual(@as(usize, 2), layout.component_starts[1]);
    try std.testing.expectEqual(@as(usize, 3), layout.component_starts[2]);
    try std.testing.expectEqual(@as(usize, 2), layout.component_widths[2]);
}

test "every group starts on a page boundary and ranges are disjoint" {
    const allocator = std.testing.allocator;
    const components = try allocator.alloc(composition_bundle.Component, 3);
    components[0] = try testComponent(allocator, "a", 16, .{ 0, 3 }, .{ 0, 4 });
    components[1] = try testComponent(allocator, "b", 12, .{ 3, 5 }, .{ 4, 8 });
    components[2] = try testComponent(allocator, "c", 20, .{ 5, 6 }, .{ 8, 12 });
    defer freeTestComponents(allocator, components);

    var layout = try trace_arena.plan(allocator, components);
    defer layout.deinit();

    const page_words = pageWords();
    for (layout.groups) |group|
        try std.testing.expectEqual(@as(usize, 0), group.offset % page_words);

    for (layout.offsets, layout.log_sizes, 0..) |offset, log_size, index| {
        const rows = @as(usize, 1) << @intCast(log_size);
        try std.testing.expect(offset + rows <= layout.base_words);
        for (layout.offsets, layout.log_sizes, 0..) |other, other_log, other_index| {
            if (index == other_index) continue;
            const other_rows = @as(usize, 1) << @intCast(other_log);
            const disjoint = offset + rows <= other or other + other_rows <= offset;
            try std.testing.expect(disjoint);
        }
    }
    try std.testing.expectEqual(@as(usize, 0), layout.base_words % page_words);
}

test "the interaction region is reserved after the base region" {
    const allocator = std.testing.allocator;
    const components = try allocator.alloc(composition_bundle.Component, 2);
    components[0] = try testComponent(allocator, "a", 18, .{ 0, 2 }, .{ 0, 4 });
    components[1] = try testComponent(allocator, "b", 18, .{ 2, 3 }, .{ 4, 12 });
    defer freeTestComponents(allocator, components);

    var layout = try trace_arena.plan(allocator, components);
    defer layout.deinit();

    try std.testing.expectEqual(layout.base_words, layout.interaction_offset);
    const rows = @as(usize, 1) << 18;
    try std.testing.expect(layout.interaction_words >= 12 * rows);
    try std.testing.expect(layout.totalWords() > layout.base_words);
}

test "planning declines geometry it cannot express" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(
        Error.UnsupportedArenaGeometry,
        trace_arena.plan(allocator, &.{}),
    );

    // Non-contiguous base spans: the flat commit order is not a concatenation.
    const gap = try allocator.alloc(composition_bundle.Component, 2);
    gap[0] = try testComponent(allocator, "a", 18, .{ 0, 2 }, .{ 0, 4 });
    gap[1] = try testComponent(allocator, "b", 18, .{ 3, 4 }, .{ 4, 8 });
    defer freeTestComponents(allocator, gap);
    try std.testing.expectError(Error.UnsupportedArenaGeometry, trace_arena.plan(allocator, gap));

    // Below the structural size floor: keep the fragmented path.
    const tiny = try allocator.alloc(composition_bundle.Component, 1);
    tiny[0] = try testComponent(allocator, "a", 4, .{ 0, 1 }, .{ 0, 4 });
    defer freeTestComponents(allocator, tiny);
    try std.testing.expectError(Error.UnsupportedArenaGeometry, trace_arena.plan(allocator, tiny));

    // Out-of-range row counts.
    const wide = try allocator.alloc(composition_bundle.Component, 1);
    wide[0] = try testComponent(allocator, "a", 31, .{ 0, 1 }, .{ 0, 4 });
    defer freeTestComponents(allocator, wide);
    try std.testing.expectError(Error.UnsupportedArenaGeometry, trace_arena.plan(allocator, wide));
}

test "allocated arena addresses every planned column exactly once" {
    const allocator = std.testing.allocator;
    const components = try allocator.alloc(composition_bundle.Component, 2);
    components[0] = try testComponent(allocator, "a", 16, .{ 0, 2 }, .{ 0, 4 });
    components[1] = try testComponent(allocator, "b", 15, .{ 2, 4 }, .{ 4, 8 });
    defer freeTestComponents(allocator, components);

    const layout = try trace_arena.plan(allocator, components);
    var arena = try trace_arena.allocate(allocator, layout);
    defer arena.deinit();

    const columns = try allocator.alloc(ColumnEvaluation, arena.layout.columnCount());
    defer allocator.free(columns);
    for (columns, 0..) |*column, index| {
        const values = try arena.columnValues(index);
        for (values, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(row + index));
        column.* = .{ .log_size = arena.layout.log_sizes[index], .values = values };
    }
    try std.testing.expect(trace_arena.columnsMatchPlan(&arena, columns));

    // A column that does not live at its planned offset breaks the binding.
    const stray = try allocator.alloc(M31, @as(usize, 1) << 16);
    defer allocator.free(stray);
    const saved = columns[0].values;
    columns[0].values = stray;
    try std.testing.expect(!trace_arena.columnsMatchPlan(&arena, columns));
    columns[0].values = saved;
    try std.testing.expect(trace_arena.columnsMatchPlan(&arena, columns));
}
