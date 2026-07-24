//! Wide-Fibonacci policy for the shared uniform three-tree layout.

const std = @import("std");
const common = @import("../common/uniform_layout.zig");
const request = @import("request.zig");

pub const TraceRole = common.TraceRole;
pub const TraceTree = common.TraceTree;
pub const FriTree = common.FriTree;
pub const Quotient = common.Quotient;

const Descriptor = struct {
    pub fn describe(
        geometry: request.Geometry,
    ) request.Error!common.Description {
        const commitment_log = geometry.queryLogSize();
        const source_columns = std.math.add(
            usize,
            geometry.main_columns,
            request.composition_column_count,
        ) catch return error.GeometryOverflow;
        return .{
            .trace_trees = .{
                .{
                    .role = .preprocessed,
                    .column_count = 0,
                    .column_log_size = 0,
                    .commitment_log_size = 0,
                    .sampled = false,
                    .decommitted = false,
                },
                .{
                    .role = .main,
                    .column_count = geometry.main_columns,
                    .column_log_size = geometry.statement.log_n_rows,
                    .commitment_log_size = commitment_log,
                    .sampled = true,
                    .decommitted = true,
                },
                .{
                    .role = .composition,
                    .column_count = request.composition_column_count,
                    .column_log_size = geometry.statement.log_n_rows,
                    .commitment_log_size = commitment_log,
                    .sampled = true,
                    .decommitted = true,
                },
            },
            .fri_tree_count = geometry.fri_tree_count,
            .first_fri_tree_index = geometry.decommitted_trace_tree_count,
            .first_fri_evaluation_log = commitment_log,
            .last_fri_evaluation_log = 2,
            .fri_fold_step = geometry.protocol.fold_step,
            .fri_log_rows_per_leaf = 0,
            .quotient = .{
                .sample_count = geometry.sampled_value_count,
                .term_count = geometry.sampled_value_count,
                .structural_group_count = 1,
                .source_column_count = source_columns,
                .source_stride_words = geometry.commitment_rows,
                .output_rows = geometry.commitment_rows,
            },
        };
    }
};

pub const Layout = common.LayoutFor(request.Geometry, Descriptor);

test "wide policy preserves committed and opened trees" {
    const geometry = try request.admit(.{
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
    var layout = try Layout.init(std.testing.allocator, geometry);
    defer layout.deinit(std.testing.allocator);
    try layout.validate();

    try std.testing.expectEqual(@as(usize, 0), layout.trace_trees[0].column_count);
    try std.testing.expectEqual(@as(usize, 100), layout.trace_trees[1].column_count);
    try std.testing.expectEqual(@as(usize, 8), layout.trace_trees[2].column_count);
    try std.testing.expectEqual(@as(usize, 14), layout.fri_trees.len);
    try std.testing.expectEqual(@as(u32, 15), layout.fri_trees[0].evaluation_log_size);
    try std.testing.expectEqual(@as(u32, 2), layout.fri_trees[13].evaluation_log_size);
    try std.testing.expectEqual(@as(usize, 15), layout.fri_trees[13].tree_index);
    try std.testing.expectEqual(@as(usize, 108), layout.quotient.term_count);
}
