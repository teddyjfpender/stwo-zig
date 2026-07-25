//! Immutable fraction-completion geometry for exact mixed-height Blake.

const std = @import("std");
const relation_abi = @import(
    "../../../../backends/cuda/abi/stages/relation.zig",
);
const completion = @import(
    "../../../../backends/cuda/runtime/stages/relation_completion.zig",
);
const interaction_plan = @import("interaction_plan.zig");

pub const Plan = struct {
    geometry: [8]relation_abi.Geometry,
    total_pair_blocks: u32,
    total_inverse_blocks: u32,
    total_row_blocks: u32,

    pub fn init(interaction: interaction_plan.Plan) !Plan {
        var result = Plan{
            .geometry = undefined,
            .total_pair_blocks = 0,
            .total_inverse_blocks = 0,
            .total_row_blocks = 0,
        };
        for (&result.geometry, interaction.components) |*output, component| {
            const rows = try u32Count(component.rows);
            const columns = try u32Count(component.secure_columns);
            const row_blocks = ceilDiv(rows, relation_abi.launch_block);
            const pair_blocks = try mul(row_blocks, columns);
            const inverse_blocks = ceilDiv(
                try mul(rows, columns),
                relation_abi.inverse_block_values,
            );
            output.* = .{
                .pair_first = result.total_pair_blocks,
                .pair_blocks = pair_blocks,
                .inverse_first = result.total_inverse_blocks,
                .inverse_blocks = inverse_blocks,
                .row_first = result.total_row_blocks,
                .row_blocks = row_blocks,
                .rows = rows,
                .columns = columns,
                .real_rows = rows,
                .source_offset_rows = 0,
                .inverse_rows = inverseRows(component.log_rows),
            };
            result.total_pair_blocks = try add(
                result.total_pair_blocks,
                pair_blocks,
            );
            result.total_inverse_blocks = try add(
                result.total_inverse_blocks,
                inverse_blocks,
            );
            result.total_row_blocks = try add(
                result.total_row_blocks,
                row_blocks,
            );
        }
        try result.topology().validate();
        return result;
    }

    pub fn topology(self: *const Plan) completion.Topology {
        return .{
            .geometry = &self.geometry,
            .max_alpha_powers = 1,
            .total_pair_blocks = self.total_pair_blocks,
            .total_inverse_blocks = self.total_inverse_blocks,
            .total_chain_blocks = self.total_row_blocks,
            .total_row_blocks = self.total_row_blocks,
        };
    }

    pub fn scratchWords(self: *const Plan) !usize {
        return @intCast(try self.topology().scratchWords());
    }
};

fn inverseRows(log_rows: u32) u32 {
    return if (log_rows == 0) 1 else @as(u32, 1) << @intCast(31 - log_rows);
}

fn ceilDiv(value: u32, divisor: u32) u32 {
    return (value + divisor - 1) / divisor;
}

fn u32Count(value: usize) !u32 {
    return std.math.cast(u32, value) orelse error.GeometryOverflow;
}

fn add(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch error.GeometryOverflow;
}

fn mul(left: u32, right: u32) !u32 {
    return std.math.mul(u32, left, right) catch error.GeometryOverflow;
}

test "exact completion topology seals all eight ragged domains" {
    const geometry_mod = @import("geometry.zig");
    const views_mod = @import("views.zig");
    const geometry = try geometry_mod.admit(.{
        .statement = .{ .log_n_rows = 4 },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
    });
    const interaction = try interaction_plan.Plan.init(
        geometry,
        try views_mod.TreeViews.init(geometry),
    );
    const plan = try Plan.init(interaction);
    try std.testing.expectEqual(@as(usize, 8), plan.geometry.len);
    try std.testing.expectEqual(@as(u32, 16), plan.geometry[0].rows);
    try std.testing.expectEqual(@as(u32, 65), plan.geometry[1].columns);
    try std.testing.expectEqual(@as(usize, 1_376), try plan.scratchWords());
}
