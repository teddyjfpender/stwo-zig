//! Exact OODS, quotient, FRI, and opening topology for mixed-height Blake.

const std = @import("std");
const geometry_mod = @import("geometry.zig");
const views_mod = @import("views.zig");

pub const Point = enum(u8) {
    current,
    previous,
};

pub const Sample = struct {
    tree: geometry_mod.Tree,
    column: u32,
    source_index: u32,
    output_index: u32,
    column_log: u32,
    point: Point,
};

pub const Source = struct {
    tree: geometry_mod.Tree,
    column: u32,
    column_log: u32,
};

pub const FriLayer = struct {
    index: u32,
    evaluation_log: u32,
    fold_step: u32,
    cumulative_fold: u32,
    row_count: usize,
};

pub const OpeningTree = struct {
    tree: geometry_mod.Tree,
    first_source: u32,
    source_count: u32,
    commitment_log: u32,
};

pub const Plan = struct {
    samples: []Sample,
    sources: []Source,
    fri_layers: []FriLayer,
    trace_openings: [geometry_mod.trace_tree_count]OpeningTree,

    pub fn init(
        allocator: std.mem.Allocator,
        geometry: geometry_mod.Geometry,
        tree_views: views_mod.TreeViews,
    ) !Plan {
        try tree_views.validate(geometry);
        const sources = try allocator.alloc(
            Source,
            geometry_mod.source_column_count,
        );
        errdefer allocator.free(sources);
        const samples = try allocator.alloc(
            Sample,
            geometry_mod.sampled_value_count,
        );
        errdefer allocator.free(samples);

        var source_cursor: usize = 0;
        var sample_cursor: usize = 0;
        try appendPreprocessed(
            sources,
            samples,
            &source_cursor,
            &sample_cursor,
            tree_views,
        );
        try appendGroups(
            .main,
            sources,
            samples,
            &source_cursor,
            &sample_cursor,
            &tree_views.main,
            false,
        );
        try appendGroups(
            .interaction,
            sources,
            samples,
            &source_cursor,
            &sample_cursor,
            &tree_views.interaction,
            true,
        );
        try appendComposition(
            sources,
            samples,
            &source_cursor,
            &sample_cursor,
            tree_views.composition,
        );
        if (source_cursor != sources.len or sample_cursor != samples.len)
            return error.InvalidExactBlakeTopology;

        const fri_layers = try allocator.alloc(
            FriLayer,
            geometry.fri_tree_count,
        );
        errdefer allocator.free(fri_layers);
        var layer_log = geometry.query_log;
        for (fri_layers, 0..) |*layer, index| {
            layer.* = .{
                .index = @intCast(index),
                .evaluation_log = layer_log,
                .fold_step = geometry.protocol.fri_config.fold_step,
                .cumulative_fold = @intCast(index),
                .row_count = try rowsAtLog(layer_log),
            };
            layer_log -= geometry.protocol.fri_config.fold_step;
        }
        if (layer_log != 1) return error.InvalidExactBlakeTopology;

        const preprocessed_count = geometry_mod.preprocessed_columns;
        const main_first = preprocessed_count;
        const interaction_first = main_first + geometry_mod.main_columns;
        const composition_first =
            interaction_first + geometry_mod.interaction_columns;
        return .{
            .samples = samples,
            .sources = sources,
            .fri_layers = fri_layers,
            .trace_openings = .{
                opening(
                    .preprocessed,
                    0,
                    preprocessed_count,
                    geometry.treeCommitmentLog(.preprocessed),
                ),
                opening(
                    .main,
                    main_first,
                    geometry_mod.main_columns,
                    geometry.treeCommitmentLog(.main),
                ),
                opening(
                    .interaction,
                    interaction_first,
                    geometry_mod.interaction_columns,
                    geometry.treeCommitmentLog(.interaction),
                ),
                opening(
                    .composition,
                    composition_first,
                    geometry_mod.composition_columns,
                    geometry.treeCommitmentLog(.composition),
                ),
            },
        };
    }

    pub fn deinit(self: *Plan, allocator: std.mem.Allocator) void {
        allocator.free(self.samples);
        allocator.free(self.sources);
        allocator.free(self.fri_layers);
        self.* = undefined;
    }

    pub fn validate(self: Plan, geometry: geometry_mod.Geometry) !void {
        if (self.samples.len != geometry_mod.sampled_value_count or
            self.sources.len != geometry_mod.source_column_count or
            self.fri_layers.len != geometry.fri_tree_count)
        {
            return error.InvalidExactBlakeTopology;
        }
        var expected_output: u32 = 0;
        for (self.samples) |sample| {
            if (sample.output_index != expected_output or
                sample.source_index >= self.sources.len)
            {
                return error.InvalidExactBlakeTopology;
            }
            const source = self.sources[sample.source_index];
            if (sample.tree != source.tree or
                sample.column != source.column or
                sample.column_log != source.column_log)
            {
                return error.InvalidExactBlakeTopology;
            }
            expected_output += 1;
        }
        var previous_count: usize = 0;
        for (self.samples) |sample| {
            previous_count += @intFromBool(sample.point == .previous);
        }
        if (previous_count != geometry_mod.previous_row_sample_columns)
            return error.InvalidExactBlakeTopology;
    }
};

fn appendPreprocessed(
    sources: []Source,
    samples: []Sample,
    source_cursor: *usize,
    sample_cursor: *usize,
    tree_views: views_mod.TreeViews,
) !void {
    for (tree_views.preprocessed) |group| {
        for (0..group.column_count) |local| {
            try appendSourceSample(
                .preprocessed,
                group.column_offset + local,
                group.log_rows,
                .current,
                sources,
                samples,
                source_cursor,
                sample_cursor,
            );
        }
    }
}

fn appendGroups(
    tree: geometry_mod.Tree,
    sources: []Source,
    samples: []Sample,
    source_cursor: *usize,
    sample_cursor: *usize,
    groups: []const views_mod.GroupView,
    include_previous: bool,
) !void {
    for (groups) |group| {
        for (0..group.column_count) |local| {
            const column = group.column_offset + local;
            const previous = include_previous and
                local + 4 >= group.column_count;
            if (previous) {
                try appendSourceSample(
                    tree,
                    column,
                    group.log_rows,
                    .previous,
                    sources,
                    samples,
                    source_cursor,
                    sample_cursor,
                );
                const source_index = source_cursor.* - 1;
                try appendSampleOnly(
                    tree,
                    column,
                    group.log_rows,
                    .current,
                    source_index,
                    samples,
                    sample_cursor,
                );
            } else {
                try appendSourceSample(
                    tree,
                    column,
                    group.log_rows,
                    .current,
                    sources,
                    samples,
                    source_cursor,
                    sample_cursor,
                );
            }
        }
    }
}

fn appendComposition(
    sources: []Source,
    samples: []Sample,
    source_cursor: *usize,
    sample_cursor: *usize,
    group: views_mod.GroupView,
) !void {
    for (0..group.column_count) |column| {
        try appendSourceSample(
            .composition,
            column,
            group.log_rows,
            .current,
            sources,
            samples,
            source_cursor,
            sample_cursor,
        );
    }
}

fn appendSourceSample(
    tree: geometry_mod.Tree,
    column: usize,
    log_size: u32,
    point: Point,
    sources: []Source,
    samples: []Sample,
    source_cursor: *usize,
    sample_cursor: *usize,
) !void {
    if (source_cursor.* >= sources.len)
        return error.InvalidExactBlakeTopology;
    const source_index = source_cursor.*;
    sources[source_index] = .{
        .tree = tree,
        .column = @intCast(column),
        .column_log = log_size,
    };
    source_cursor.* += 1;
    try appendSampleOnly(
        tree,
        column,
        log_size,
        point,
        source_index,
        samples,
        sample_cursor,
    );
}

fn appendSampleOnly(
    tree: geometry_mod.Tree,
    column: usize,
    log_size: u32,
    point: Point,
    source_index: usize,
    samples: []Sample,
    sample_cursor: *usize,
) !void {
    if (sample_cursor.* >= samples.len)
        return error.InvalidExactBlakeTopology;
    samples[sample_cursor.*] = .{
        .tree = tree,
        .column = @intCast(column),
        .source_index = @intCast(source_index),
        .output_index = @intCast(sample_cursor.*),
        .column_log = log_size,
        .point = point,
    };
    sample_cursor.* += 1;
}

fn opening(
    tree: geometry_mod.Tree,
    first: usize,
    count: usize,
    log_size: u32,
) OpeningTree {
    return .{
        .tree = tree,
        .first_source = @intCast(first),
        .source_count = @intCast(count),
        .commitment_log = log_size,
    };
}

fn rowsAtLog(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize))
        return error.InvalidExactBlakeTopology;
    return @as(usize, 1) << @intCast(log_size);
}

test "exact Blake topology repeats only component accumulator coordinates" {
    const geometry = try geometry_mod.admit(.{
        .statement = .{ .log_n_rows = 4 },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
    });
    const tree_views = try views_mod.TreeViews.init(geometry);
    var plan = try Plan.init(
        std.testing.allocator,
        geometry,
        tree_views,
    );
    defer plan.deinit(std.testing.allocator);
    try plan.validate(geometry);

    var repeated_sources: usize = 0;
    for (plan.samples[1..], plan.samples[0 .. plan.samples.len - 1]) |
        sample,
        previous,
    | {
        repeated_sources += @intFromBool(
            sample.source_index == previous.source_index,
        );
    }
    try std.testing.expectEqual(
        geometry_mod.previous_row_sample_columns,
        repeated_sources,
    );
    try std.testing.expectEqual(@as(u32, 17), plan.fri_layers[0].evaluation_log);
    try std.testing.expectEqual(@as(u32, 2), plan.fri_layers[15].evaluation_log);
}
