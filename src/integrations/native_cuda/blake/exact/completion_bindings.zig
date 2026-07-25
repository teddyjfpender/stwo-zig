//! Resident pointer graph for exact Blake LogUp completion.

const completion = @import(
    "../../../../backends/cuda/runtime/stages/relation_completion.zig",
);
const common = @import(
    "../../../../backends/cuda/runtime/stages/common.zig",
);
const column = @import(
    "../../../../backends/cuda/runtime/column.zig",
);
const completion_plan = @import("completion_plan.zig");
const geometry_mod = @import("geometry.zig");
const interaction_plan = @import("interaction_plan.zig");
const resident = @import("resident_bindings.zig");
const slots = @import("slots.zig");

const Words = column.DeviceSlice(u32);
const pointer_words = @sizeOf(usize) / @sizeOf(u32);

pub const Bound = struct {
    buffers: completion.DeviceBuffers,
    output_pointer_table: Words,
    output_coordinates: [geometry_mod.interaction_columns]Words,
    output_first: [geometry_mod.component_count]usize,
    resident: resident.Bound,

    pub fn instances(
        self: *const Bound,
    ) ![geometry_mod.component_count]completion.InstanceBinding {
        var result: [geometry_mod.component_count]completion.InstanceBinding =
            undefined;
        for (&result, self.resident.components, 0..) |*output, component, index| {
            const first = self.output_first[index];
            const count = component.interaction.storage.len /
                component.interaction.column_stride_words;
            output.* = .{
                .output_pointer_table = try self.output_pointer_table.sub(
                    first * pointer_words,
                    count * pointer_words,
                ),
                .output_coordinates = self.output_coordinates[first..][0..count],
                .denominator_slab = component.denominators,
                .claimed_sum = component.claim,
            };
        }
        return result;
    }
};

pub fn bind(
    provider: anytype,
    geometry: geometry_mod.Geometry,
    views: @import("views.zig").TreeViews,
) !Bound {
    const resident_bound = try resident.bind(provider, geometry, views);
    const interactions = try interaction_plan.Plan.init(geometry, views);
    const policy = try completion_plan.Plan.init(interactions);
    const output_pointer_table = try exactWords(
        provider,
        slots.interaction_output_pointer_table,
        geometry_mod.interaction_columns * pointer_words,
    );
    var coordinates: [geometry_mod.interaction_columns]Words = undefined;
    var output_first: [geometry_mod.component_count]usize = undefined;
    var coordinate_index: usize = 0;
    for (resident_bound.components, 0..) |component, index| {
        output_first[index] = coordinate_index;
        const matrix = component.interaction;
        const count = matrix.storage.len / matrix.column_stride_words;
        for (0..count) |column_index| {
            coordinates[coordinate_index] = try matrix.storage.sub(
                column_index * matrix.column_stride_words,
                matrix.column_stride_words,
            );
            coordinate_index += 1;
        }
    }
    if (coordinate_index != geometry_mod.interaction_columns)
        return error.InvalidInteractionBinding;
    const count = geometry_mod.component_count;
    const scratch = try policy.scratchWords();
    return .{
        .buffers = .{
            .output_tables = try exactWords(
                provider,
                slots.interaction_output_tables,
                count * pointer_words,
            ),
            .denominator_slabs = try exactWords(
                provider,
                slots.interaction_denominator_tables,
                count * pointer_words,
            ),
            .geometry = try exactAs(
                provider,
                completion.Geometry,
                slots.interaction_geometry,
                count,
            ),
            .claimed_sums = try exactWords(
                provider,
                slots.interaction_claim_tables,
                count * pointer_words,
            ),
            .reduction_partials = try exactWords(
                provider,
                slots.interaction_reduction_partials,
                scratch,
            ),
            .scan_block_sums = try exactWords(
                provider,
                slots.interaction_scan_block_sums,
                scratch,
            ),
        },
        .output_pointer_table = output_pointer_table,
        .output_coordinates = coordinates,
        .output_first = output_first,
        .resident = resident_bound,
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
        expected * (@sizeOf(F) / @sizeOf(u32)),
    );
    const result = try words.cast(F);
    if (result.len != expected) return error.InvalidInteractionBinding;
    return result;
}

test "completion bindings preserve every ragged interaction coordinate" {
    const std = @import("std");
    const arena_plan = @import("arena_plan.zig");
    const geometry = try geometry_mod.admit(.{
        .statement = .{ .log_n_rows = 4 },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
    });
    var prepared = try arena_plan.Prepared.init(std.testing.allocator, geometry);
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
    const instances = try bound.instances();
    var coordinates: usize = 0;
    for (instances) |instance| coordinates += instance.output_coordinates.len;
    try std.testing.expectEqual(
        @as(usize, geometry_mod.interaction_columns),
        coordinates,
    );
    try std.testing.expectEqual(
        bound.resident.components[1].claim.address,
        instances[1].claimed_sum.address,
    );
}
