//! Immutable component placement for the exact mixed-height LogUp tree.

const std = @import("std");
const geometry_mod = @import("geometry.zig");
const views_mod = @import("views.zig");

pub const Component = struct {
    kind: geometry_mod.Component,
    log_rows: u32,
    rows: usize,
    main_first_word: usize,
    main_columns: usize,
    preprocessed_first_word: ?usize,
    preprocessed_columns: usize,
    interaction_first_word: usize,
    interaction_columns: usize,
    secure_columns: usize,
    workspace_first_word: usize,
    workspace_words: usize,
    public_claim_index: usize,
    relation_mask: u8,
};

pub const Plan = struct {
    components: [geometry_mod.component_count]Component,
    workspace_words: usize,

    pub fn init(
        geometry: geometry_mod.Geometry,
        views: views_mod.TreeViews,
    ) !Plan {
        try views.validate(geometry);
        const secure_widths = geometry_mod.relationFractionWidths();
        var components: [geometry_mod.component_count]Component = undefined;
        var workspace_first: usize = 0;
        for (&components, 0..) |*component, index| {
            const main = views.main[index];
            const interaction = views.interaction[index];
            const secure_columns = secure_widths[index];
            const workspace_words = try mul(
                try mul(main.row_count, secure_columns),
                4,
            );
            const xor_index = if (index >= 3) index - 3 else null;
            component.* = .{
                .kind = geometry_mod.component_order[index],
                .log_rows = main.log_rows,
                .rows = main.row_count,
                .main_first_word = geometry.treeWords(.preprocessed) +
                    main.arena_offset_words,
                .main_columns = main.column_count,
                .preprocessed_first_word = if (xor_index) |table|
                    views.preprocessed[table].arena_offset_words
                else
                    null,
                .preprocessed_columns = if (xor_index) |table|
                    views.preprocessed[table].column_count
                else
                    0,
                .interaction_first_word = interaction.arena_offset_words,
                .interaction_columns = interaction.column_count,
                .secure_columns = secure_columns,
                .workspace_first_word = workspace_first,
                .workspace_words = workspace_words,
                .public_claim_index = publicClaimIndex(index),
                .relation_mask = relationMask(index),
            };
            workspace_first = try add(workspace_first, workspace_words);
        }
        const result = Plan{
            .components = components,
            .workspace_words = workspace_first,
        };
        try result.validate(geometry);
        return result;
    }

    pub fn validate(self: Plan, geometry: geometry_mod.Geometry) !void {
        var workspace_first: usize = 0;
        var claims_seen: u8 = 0;
        for (self.components, 0..) |component, index| {
            const expected_rows = try rowsAtLog(geometry.component_logs[index]);
            const claim_bit = @as(u8, 1) <<
                @intCast(component.public_claim_index);
            if (component.kind != geometry_mod.component_order[index] or
                component.log_rows != geometry.component_logs[index] or
                component.rows != expected_rows or
                component.interaction_columns != 4 * component.secure_columns or
                component.workspace_first_word != workspace_first or
                component.workspace_words !=
                    try mul(try mul(expected_rows, component.secure_columns), 4) or
                component.public_claim_index >= geometry_mod.claimed_sum_count or
                claims_seen & claim_bit != 0 or
                component.relation_mask == 0)
            {
                return error.InvalidInteractionPlan;
            }
            if ((index < 3) != (component.preprocessed_first_word == null) or
                (index < 3) != (component.preprocessed_columns == 0))
            {
                return error.InvalidInteractionPlan;
            }
            claims_seen |= claim_bit;
            workspace_first = try add(
                workspace_first,
                component.workspace_words,
            );
        }
        if (claims_seen != 0xff or workspace_first != self.workspace_words or
            self.workspace_words !=
                try geometry_mod.relationFractionWorkspaceWords(
                    geometry.statement.log_n_rows,
                ))
        {
            return error.InvalidInteractionPlan;
        }
    }
};

/// Component execution order differs from Statement1 transcript order.
fn publicClaimIndex(component_index: usize) usize {
    const mapping = [geometry_mod.component_count]usize{
        0, 6, 7, 1, 2, 3, 4, 5,
    };
    return mapping[component_index];
}

/// Relation draw order is Blake, round, XOR-12, XOR-9, XOR-8, XOR-7, XOR-4.
fn relationMask(component_index: usize) u8 {
    const mapping = [geometry_mod.component_count]u8{
        0b000_0011,
        0b111_1110,
        0b111_1110,
        0b000_0100,
        0b000_1000,
        0b001_0000,
        0b010_0000,
        0b100_0000,
    };
    return mapping[component_index];
}

fn rowsAtLog(log_rows: u32) !usize {
    if (log_rows >= @bitSizeOf(usize)) return error.GeometryOverflow;
    return @as(usize, 1) << @intCast(log_rows);
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.GeometryOverflow;
}

fn mul(left: usize, right: usize) !usize {
    return std.math.mul(usize, left, right) catch error.GeometryOverflow;
}

test "exact interaction plan pins public claim and relation order" {
    const geometry = try geometry_mod.admit(.{
        .statement = .{ .log_n_rows = 4 },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
    });
    const views = try views_mod.TreeViews.init(geometry);
    const plan = try Plan.init(geometry, views);
    try std.testing.expectEqual(
        @as(usize, 34_285_568),
        plan.workspace_words,
    );
    try std.testing.expectEqual(
        @as(usize, 6),
        plan.components[1].public_claim_index,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        plan.components[3].public_claim_index,
    );
    try std.testing.expectEqual(
        @as(u8, 0b111_1110),
        plan.components[2].relation_mask,
    );
}
