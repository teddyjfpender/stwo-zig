//! Four-tree resident layout for exact mixed-height State Machine v2.

const common = @import("../common/uniform_layout.zig");
const geometry_mod = @import("geometry.zig");

pub const TraceRole = common.TraceRole;
pub const TraceTree = common.TraceTree;
pub const FriTree = common.FriTree;
pub const Quotient = common.Quotient;

const Descriptor = struct {
    pub fn describe(
        geometry: geometry_mod.Geometry,
    ) geometry_mod.Error!common.DescriptionFor(4) {
        const trace_log = geometry.statement.log_n_rows;
        const commitment_log = geometry.commitment_log_rows;
        return .{
            .trace_trees = .{
                .{
                    .role = .preprocessed,
                    .column_count = geometry_mod.preprocessed_columns,
                    .column_log_size = trace_log,
                    .commitment_log_size = commitment_log,
                    .sampled = false,
                    .decommitted = false,
                },
                .{
                    .role = .main,
                    .column_count = geometry_mod.main_columns,
                    // The tree contains log n and log n-1 columns. This field
                    // is the tree's maximum logical log; topology.zig carries
                    // the exact per-column logs.
                    .column_log_size = trace_log,
                    .commitment_log_size = commitment_log,
                    .sampled = true,
                    .decommitted = true,
                },
                .{
                    .role = .interaction,
                    .column_count = geometry_mod.interaction_columns,
                    .column_log_size = trace_log,
                    .commitment_log_size = commitment_log,
                    .sampled = true,
                    .decommitted = true,
                },
                .{
                    .role = .composition,
                    .column_count = geometry_mod.composition_columns,
                    .column_log_size = trace_log,
                    .commitment_log_size = commitment_log,
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

    pub fn columnLogSize(
        geometry: geometry_mod.Geometry,
        role: TraceRole,
        column_index: usize,
    ) geometry_mod.Error!u32 {
        const n = geometry.statement.log_n_rows;
        return switch (role) {
            .preprocessed => error.UnsupportedProtocol,
            .main => if (column_index < 2) n else n - 1,
            .interaction => if (column_index < 4) n else n - 1,
            .composition => n,
        };
    }
};

pub const Layout = common.LayoutForTreeCount(
    geometry_mod.Geometry,
    Descriptor,
    4,
);

test "State Machine v2 layout retains all four proof trees" {
    const std = @import("std");
    const pcs = @import("stwo_core").pcs;
    const allocator = std.testing.allocator;
    const geometry = try geometry_mod.admit(
        .{
            .log_n_rows = 16,
            .initial_state = .{
                @import("stwo_core").fields.m31.M31.fromU64(9),
                @import("stwo_core").fields.m31.M31.fromU64(3),
            },
        },
        pcs.PcsConfig.default(),
    );
    var logical = try Layout.init(allocator, geometry);
    defer logical.deinit(allocator);
    try logical.validate();

    try std.testing.expectEqual(@as(usize, 0), logical.trace_trees[0].column_count);
    try std.testing.expectEqual(@as(usize, 4), logical.trace_trees[1].column_count);
    try std.testing.expectEqual(@as(usize, 8), logical.trace_trees[2].column_count);
    try std.testing.expectEqual(@as(usize, 8), logical.trace_trees[3].column_count);
    try std.testing.expect(!logical.trace_trees[0].sampled);
    try std.testing.expect(!logical.trace_trees[0].decommitted);
    for (logical.trace_trees[1..]) |tree| try std.testing.expect(tree.sampled);
    for (logical.trace_trees[1..]) |tree| try std.testing.expect(tree.decommitted);
    try std.testing.expectEqual(@as(usize, 16), logical.fri_trees.len);
    try std.testing.expectEqual(@as(usize, 3), logical.fri_trees[0].tree_index);
    try std.testing.expectEqual(@as(u32, 17), logical.fri_trees[0].evaluation_log_size);
    try std.testing.expectEqual(@as(u32, 2), logical.fri_trees[15].evaluation_log_size);
    try std.testing.expectEqual(@as(usize, 28), logical.quotient.term_count);
    try std.testing.expectEqual(@as(usize, 20), logical.quotient.source_column_count);
}
