//! Plonk policy for the shared uniform three-tree proof layout.

const common = @import("../common/uniform_layout.zig");
const geometry_mod = @import("geometry.zig");

pub const TraceRole = common.TraceRole;
pub const TraceTree = common.TraceTree;
pub const FriTree = common.FriTree;
pub const Quotient = common.Quotient;

const Descriptor = struct {
    pub fn describe(
        geometry: geometry_mod.Geometry,
    ) geometry_mod.Error!common.Description {
        return .{
            .trace_trees = .{
                .{
                    .role = .preprocessed,
                    .column_count = geometry_mod.preprocessed_columns,
                    .column_log_size = geometry.statement.log_n_rows,
                    .commitment_log_size = geometry.commitment_log_rows,
                    .sampled = true,
                    .decommitted = true,
                },
                .{
                    .role = .main,
                    .column_count = geometry_mod.main_columns,
                    .column_log_size = geometry.statement.log_n_rows,
                    .commitment_log_size = geometry.commitment_log_rows,
                    .sampled = true,
                    .decommitted = true,
                },
                .{
                    .role = .composition,
                    .column_count = geometry_mod.composition_columns,
                    .column_log_size = geometry.statement.log_n_rows,
                    .commitment_log_size = geometry.commitment_log_rows,
                    .sampled = true,
                    .decommitted = true,
                },
            },
            .fri_tree_count = geometry.fri_tree_count,
            .first_fri_tree_index = geometry.decommitted_trace_tree_count,
            .first_fri_evaluation_log = geometry.commitment_log_rows,
            .last_fri_evaluation_log = 2,
            .fri_fold_step = geometry.protocol.fri_config.fold_step,
            .fri_log_rows_per_leaf = 0,
            .quotient = .{
                .sample_count = geometry_mod.sampled_mask_points,
                .term_count = geometry_mod.sampled_mask_points,
                .structural_group_count = 1,
                .source_column_count = geometry_mod.sampled_mask_points,
                .source_stride_words = geometry.commitment_rows,
                .output_rows = geometry.commitment_rows,
            },
        };
    }
};

pub const Layout = common.LayoutFor(geometry_mod.Geometry, Descriptor);

test "Plonk layout retains every CPU proof tree and sampled column" {
    const std = @import("std");
    const pcs = @import("stwo_core").pcs;
    const allocator = std.testing.allocator;
    const geometry = try geometry_mod.admit(
        .{ .log_n_rows = 16 },
        pcs.PcsConfig.default(),
    );
    var logical = try Layout.init(allocator, geometry);
    defer logical.deinit(allocator);
    try logical.validate();

    try std.testing.expectEqual(@as(usize, 4), logical.trace_trees[0].column_count);
    try std.testing.expectEqual(@as(usize, 4), logical.trace_trees[1].column_count);
    try std.testing.expectEqual(@as(usize, 8), logical.trace_trees[2].column_count);
    for (logical.trace_trees) |tree| {
        try std.testing.expect(tree.sampled);
        try std.testing.expect(tree.decommitted);
    }
    try std.testing.expectEqual(@as(usize, 16), logical.fri_trees.len);
    try std.testing.expectEqual(@as(usize, 3), logical.fri_trees[0].tree_index);
    try std.testing.expectEqual(@as(u32, 17), logical.fri_trees[0].evaluation_log_size);
    try std.testing.expectEqual(@as(u32, 2), logical.fri_trees[15].evaluation_log_size);
    try std.testing.expectEqual(@as(usize, 16), logical.quotient.term_count);
}
