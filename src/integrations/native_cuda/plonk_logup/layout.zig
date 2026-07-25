//! Four-tree exact Plonk/LogUp resident proof layout.

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
                tree(.preprocessed, geometry_mod.preprocessed_columns, trace_log, commitment_log),
                tree(.main, geometry_mod.main_columns, trace_log, commitment_log),
                tree(.interaction, geometry_mod.interaction_columns, trace_log, commitment_log),
                tree(.composition, geometry_mod.composition_columns, trace_log, commitment_log),
            },
            .fri_tree_count = geometry.fri_tree_count,
            .first_fri_tree_index = geometry.decommitted_trace_tree_count,
            .first_fri_evaluation_log = commitment_log,
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

fn tree(
    role: TraceRole,
    columns: usize,
    column_log: u32,
    commitment_log: u32,
) TraceTree {
    return .{
        .role = role,
        .column_count = columns,
        .column_log_size = column_log,
        .commitment_log_size = commitment_log,
        .sampled = true,
        .decommitted = true,
    };
}

test "exact layout separates source columns from mask samples" {
    const std = @import("std");
    const geometry = try geometry_mod.admit(
        .{ .log_n_rows = 16 },
        @import("stwo_core").pcs.PcsConfig.default(),
    );
    var value = try Layout.init(std.testing.allocator, geometry);
    defer value.deinit(std.testing.allocator);
    try value.validate();
    try std.testing.expectEqual(@as(usize, 4), value.trace_trees.len);
    try std.testing.expectEqual(
        TraceRole.interaction,
        value.trace_trees[2].role,
    );
    try std.testing.expectEqual(@as(usize, 24), value.quotient.source_column_count);
    try std.testing.expectEqual(@as(usize, 28), value.quotient.sample_count);
}
