//! Prevalidated device views for the exact Blake interaction authority.

const field = @import(
    "../../../../backends/cuda/abi/field.zig",
);
const column = @import(
    "../../../../backends/cuda/runtime/column.zig",
);
const common = @import(
    "../../../../backends/cuda/runtime/stages/common.zig",
);
const geometry_mod = @import("geometry.zig");
const interaction_plan = @import("interaction_plan.zig");
const slots = @import("slots.zig");
const views_mod = @import("views.zig");

const Words = column.DeviceSlice(u32);

pub const Component = struct {
    kind: geometry_mod.Component,
    log_rows: u32,
    main: common.WordMatrix,
    preprocessed: ?common.WordMatrix,
    interaction: common.WordMatrix,
    denominators: common.SecureFields,
    claim: common.SecureFields,
    relation_mask: u8,
};

pub const Bound = struct {
    relation_elements: common.SecureFields,
    public_claims: common.SecureFields,
    components: [geometry_mod.component_count]Component,
};

pub fn bind(
    provider: anytype,
    geometry: geometry_mod.Geometry,
    views: views_mod.TreeViews,
) !Bound {
    const plan = try interaction_plan.Plan.init(geometry, views);
    const preprocessed_sources = try exactWords(
        provider,
        slots.preprocessed_evaluations,
        geometry.treeWords(.preprocessed),
    );
    const main_sources = try exactWords(
        provider,
        slots.main_evaluations,
        geometry.main_words,
    );
    const interaction = try exactWords(
        provider,
        slots.interaction_evaluations,
        geometry.interaction_words,
    );
    const denominator_words = try exactWords(
        provider,
        slots.interaction_denominators,
        plan.workspace_words,
    );
    const public_claims = try exactAs(
        provider,
        field.SecureField,
        slots.statement1_claims,
        geometry_mod.claimed_sum_count,
    );

    var components: [geometry_mod.component_count]Component = undefined;
    for (&components, plan.components) |*output, component| {
        const main_words = try mul(component.main_columns, component.rows);
        const interaction_words = try mul(
            component.interaction_columns,
            component.rows,
        );
        const fraction_count = component.workspace_words / 4;
        output.* = .{
            .kind = component.kind,
            .log_rows = component.log_rows,
            .main = .{
                .storage = try main_sources.sub(
                    component.main_first_word,
                    main_words,
                ),
                .column_stride_words = component.rows,
            },
            .preprocessed = if (component.preprocessed_first_word) |first|
                .{
                    .storage = try preprocessed_sources.sub(
                        first,
                        try mul(component.preprocessed_columns, component.rows),
                    ),
                    .column_stride_words = component.rows,
                }
            else
                null,
            .interaction = .{
                .storage = try interaction.sub(
                    component.interaction_first_word,
                    interaction_words,
                ),
                .column_stride_words = component.rows,
            },
            .denominators = try (try denominator_words.sub(
                component.workspace_first_word,
                component.workspace_words,
            )).cast(field.SecureField),
            .claim = try public_claims.sub(
                component.public_claim_index,
                1,
            ),
            .relation_mask = component.relation_mask,
        };
        if (output.denominators.len != fraction_count) {
            return error.InvalidInteractionBinding;
        }
    }
    return .{
        .relation_elements = try exactAs(
            provider,
            field.SecureField,
            slots.relation_elements,
            geometry_mod.relation_pair_count * 2,
        ),
        .public_claims = public_claims,
        .components = components,
    };
}

fn exactWords(provider: anytype, id: slots.SlotId, expected: usize) !Words {
    const value = try provider.slot(id);
    if (value.len != expected) return error.InvalidInteractionBinding;
    return value;
}

fn exactAs(
    provider: anytype,
    comptime F: type,
    id: slots.SlotId,
    expected: usize,
) !column.DeviceSlice(F) {
    const words = try exactWords(
        provider,
        id,
        try mul(expected, @sizeOf(F) / @sizeOf(u32)),
    );
    const result = try words.cast(F);
    if (result.len != expected) return error.InvalidInteractionBinding;
    return result;
}

fn mul(left: usize, right: usize) !usize {
    return @import("std").math.mul(usize, left, right) catch
        error.SizeOverflow;
}

test "exact interaction binding preserves ragged sources and public claims" {
    const std = @import("std");
    const arena_plan = @import("arena_plan.zig");
    const geometry = try geometry_mod.admit(.{
        .statement = .{ .log_n_rows = 4 },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
    });
    var prepared = try arena_plan.Prepared.init(
        std.testing.allocator,
        geometry,
    );
    defer prepared.deinit(std.testing.allocator);
    const Provider = struct {
        prepared: *const arena_plan.Prepared,

        pub fn slot(self: @This(), id: slots.SlotId) !Words {
            const placement = try self.prepared.placement(id);
            return .{
                .address = 0x1_0000_0000 +
                    placement.offset_words * @sizeOf(u32),
                .len = placement.requirement.words,
                .owner = 7,
                .generation = 11,
            };
        }
    };
    const bound = try bind(
        Provider{ .prepared = &prepared },
        geometry,
        prepared.views,
    );
    try std.testing.expectEqual(
        @as(usize, geometry_mod.relation_pair_count * 2),
        bound.relation_elements.len,
    );
    try std.testing.expect(bound.components[0].preprocessed == null);
    try std.testing.expect(bound.components[3].preprocessed != null);
    try std.testing.expectEqual(
        @as(usize, 6),
        (bound.components[1].claim.address -
            bound.public_claims.address) / @sizeOf(field.SecureField),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        (bound.components[3].claim.address -
            bound.public_claims.address) / @sizeOf(field.SecureField),
    );
}
