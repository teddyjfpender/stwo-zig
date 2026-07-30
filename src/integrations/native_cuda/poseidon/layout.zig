//! Exact four-tree Native Poseidon proof layout.

const common = @import("../common/uniform_layout.zig");
const geometry_mod = @import("geometry.zig");

const Descriptor = struct {
    pub fn describe(
        geometry: geometry_mod.Geometry,
    ) geometry_mod.Error!common.DescriptionFor(4) {
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
                    .column_log_size = geometry.log_n_rows,
                    .commitment_log_size = geometry.commitment_log_rows,
                    .sampled = true,
                    .decommitted = true,
                },
                .{
                    .role = .interaction,
                    .column_count = geometry_mod.interaction_columns,
                    .column_log_size = geometry.log_n_rows,
                    .commitment_log_size = geometry.commitment_log_rows,
                    .sampled = true,
                    .decommitted = true,
                },
                .{
                    .role = .composition,
                    .column_count = geometry_mod.composition_columns,
                    .column_log_size = geometry.log_n_rows,
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
                .source_column_count = geometry_mod.source_columns,
                .source_stride_words = geometry.commitment_rows,
                .output_rows = geometry.commitment_rows,
            },
        };
    }
};

pub const Layout = common.LayoutForTreeCount(
    geometry_mod.Geometry,
    Descriptor,
    4,
);

test "Poseidon layout preserves empty preprocessed and wide main trees" {
    const std = @import("std");
    const pcs = @import("stwo_core").pcs;
    const allocator = std.testing.allocator;
    const geometry = try geometry_mod.admit(
        .{ .log_n_instances = 13 },
        pcs.PcsConfig.default(),
    );
    var logical = try Layout.init(allocator, geometry);
    defer logical.deinit(allocator);
    try logical.validate();

    try std.testing.expectEqual(
        @as(usize, 0),
        logical.trace_trees[0].column_count,
    );
    try std.testing.expectEqual(
        @as(usize, 1264),
        logical.trace_trees[1].column_count,
    );
    try std.testing.expectEqual(
        @as(usize, 32),
        logical.trace_trees[2].column_count,
    );
    try std.testing.expectEqual(
        @as(usize, 16),
        logical.trace_trees[3].column_count,
    );
    try std.testing.expectEqual(
        @as(usize, 1316),
        logical.quotient.term_count,
    );
    try std.testing.expectEqual(
        @as(usize, 10),
        logical.fri_trees.len,
    );
    try std.testing.expectEqual(
        @as(usize, 3),
        logical.fri_trees[0].tree_index,
    );
}
