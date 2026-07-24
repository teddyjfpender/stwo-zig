//! Sealed logical proof layout derived from an admitted request.

const std = @import("std");
const request_mod = @import("request.zig");

pub const TraceRole = enum(u32) {
    preprocessed = 0,
    main = 1,
    composition = 2,
};

pub const TraceTree = struct {
    role: TraceRole,
    column_count: usize,
    column_log_size: u32,
    commitment_log_size: u32,
    decommitted: bool,
};

pub const FriTree = struct {
    tree_index: usize,
    evaluation_log_size: u32,
    cumulative_fold: u32,
    fold_step: u32,
    log_rows_per_leaf: u32,
};

pub const Quotient = struct {
    sample_count: usize,
    term_count: usize,
    structural_group_count: usize,
    source_column_count: usize,
    source_stride_words: usize,
    output_rows: usize,
};

pub const Layout = struct {
    geometry: request_mod.Geometry,
    trace_trees: [3]TraceTree,
    fri_trees: []FriTree,
    quotient: Quotient,

    pub fn init(
        allocator: std.mem.Allocator,
        geometry: request_mod.Geometry,
    ) (std.mem.Allocator.Error || request_mod.Error)!Layout {
        const statement = geometry.statement;
        const commitment_log_size = statement.log_n_rows +
            geometry.protocol.log_blowup_factor;
        const fri_trees = try allocator.alloc(FriTree, geometry.fri_tree_count);
        errdefer allocator.free(fri_trees);
        for (fri_trees, 0..) |*tree, index| {
            const fold = std.math.cast(u32, index) orelse
                return error.GeometryOverflow;
            tree.* = .{
                .tree_index = geometry.decommitted_trace_tree_count + index,
                .evaluation_log_size = if (index == 0)
                    commitment_log_size
                else
                    commitment_log_size - fold,
                .cumulative_fold = fold,
                .fold_step = geometry.protocol.fold_step,
                .log_rows_per_leaf = 0,
            };
        }
        const source_column_count = try checkedAdd(
            geometry.main_columns,
            request_mod.composition_column_count,
        );
        return .{
            .geometry = geometry,
            .trace_trees = .{
                .{
                    .role = .preprocessed,
                    .column_count = 0,
                    .column_log_size = 0,
                    .commitment_log_size = 0,
                    .decommitted = false,
                },
                .{
                    .role = .main,
                    .column_count = geometry.main_columns,
                    .column_log_size = statement.log_n_rows,
                    .commitment_log_size = commitment_log_size,
                    .decommitted = true,
                },
                .{
                    .role = .composition,
                    .column_count = request_mod.composition_column_count,
                    .column_log_size = statement.log_n_rows,
                    .commitment_log_size = commitment_log_size,
                    .decommitted = true,
                },
            },
            .fri_trees = fri_trees,
            .quotient = .{
                .sample_count = geometry.sampled_value_count,
                .term_count = geometry.sampled_value_count,
                // Every wide-Fibonacci mask is the same OODS point and every
                // committed polynomial has degree log N after splitting.
                .structural_group_count = 1,
                .source_column_count = source_column_count,
                .source_stride_words = geometry.commitment_rows,
                .output_rows = geometry.commitment_rows,
            },
        };
    }

    pub fn deinit(self: *Layout, allocator: std.mem.Allocator) void {
        allocator.free(self.fri_trees);
        self.* = undefined;
    }

    pub fn validate(self: Layout) request_mod.Error!void {
        if (self.trace_trees[0].decommitted or
            self.trace_trees[0].column_count != 0 or
            !self.trace_trees[1].decommitted or
            !self.trace_trees[2].decommitted)
        {
            return error.UnsupportedProtocol;
        }
        if (self.fri_trees.len != self.geometry.fri_tree_count or
            self.quotient.sample_count != self.geometry.sampled_value_count or
            self.quotient.term_count != self.quotient.sample_count)
        {
            return error.UnsupportedProtocol;
        }
        for (self.fri_trees, 0..) |tree, index| {
            if (tree.tree_index !=
                self.geometry.decommitted_trace_tree_count + index or
                tree.cumulative_fold != index or
                tree.fold_step != 1 or
                tree.log_rows_per_leaf != 0)
            {
                return error.UnsupportedProtocol;
            }
            if (index != 0 and
                self.fri_trees[index - 1].evaluation_log_size !=
                    tree.evaluation_log_size + 1)
            {
                return error.UnsupportedProtocol;
            }
        }
        if (self.fri_trees[self.fri_trees.len - 1].evaluation_log_size != 2)
            return error.UnsupportedProtocol;
    }
};

fn checkedAdd(left: usize, right: usize) request_mod.Error!usize {
    return std.math.add(usize, left, right) catch error.GeometryOverflow;
}

test "logical layout preserves every committed and opened tree" {
    const allocator = std.testing.allocator;
    const geometry = try request_mod.admit(.{
        .statement = .{ .log_n_rows = 14, .sequence_len = 100 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    });
    var layout = try Layout.init(allocator, geometry);
    defer layout.deinit(allocator);
    try layout.validate();

    try std.testing.expectEqual(@as(usize, 3), layout.trace_trees.len);
    try std.testing.expectEqual(@as(usize, 0), layout.trace_trees[0].column_count);
    try std.testing.expectEqual(@as(usize, 100), layout.trace_trees[1].column_count);
    try std.testing.expectEqual(@as(usize, 8), layout.trace_trees[2].column_count);
    try std.testing.expectEqual(@as(usize, 14), layout.fri_trees.len);
    try std.testing.expectEqual(@as(u32, 15), layout.fri_trees[0].evaluation_log_size);
    try std.testing.expectEqual(@as(u32, 2), layout.fri_trees[13].evaluation_log_size);
    try std.testing.expectEqual(@as(usize, 15), layout.fri_trees[13].tree_index);
    try std.testing.expectEqual(@as(usize, 108), layout.quotient.term_count);
}
