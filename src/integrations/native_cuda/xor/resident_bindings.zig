//! Exact four-tree and LogUp relation views over one resident proof arena.

const std = @import("std");
const field = @import("../../../backends/cuda/abi/field.zig");
const column = @import("../../../backends/cuda/runtime/column.zig");
const common = @import(
    "../../../backends/cuda/runtime/stages/common.zig",
);
const relation_stage = @import(
    "../../../backends/cuda/runtime/stages/relation.zig",
);
const constraint = @import("constraint.zig");
const geometry_mod = @import("geometry.zig");
const plan_mod = @import("plan.zig");
const proof_bundle = @import("proof_bundle.zig");
const relation_mod = @import("relation.zig");
const shared = @import("../common/resident_bindings.zig");
const slots = @import("slots.zig");

const SharedBinding = shared.BindingFor(
    geometry_mod,
    plan_mod,
    slots,
    proof_bundle,
);
const Words = column.DeviceSlice(u32);

pub const Relation = struct {
    buffers: relation_stage.DeviceBuffers,
    source_columns: [relation_mod.source_pointer_count]Words,
    output_coordinates: [relation_mod.output_coordinate_count]Words,
    source_pointer_table: Words,
    descriptor_storage: Words,
    output_pointer_table: Words,
    denominator_slab: common.SecureFields,
    claimed_sum: common.SecureFields,

    pub fn instance(self: *const Relation) relation_stage.InstanceBinding {
        return .{
            .source_pointer_table = self.source_pointer_table,
            .source_columns = &self.source_columns,
            .descriptor_storage = self.descriptor_storage,
            .descriptors = &relation_mod.descriptors,
            .output_pointer_table = self.output_pointer_table,
            .output_coordinates = &self.output_coordinates,
            .denominator_slab = self.denominator_slab,
            .claimed_sum = self.claimed_sum,
        };
    }
};

pub const Bound = struct {
    base: shared.Bound,
    relation: Relation,
    constraint_buffers: constraint.Buffers,
};

pub fn bind(
    provider: anytype,
    prepared: *const plan_mod.PreparedPlan,
) !Bound {
    const base = try SharedBinding.bind(provider, prepared);
    const geometry = prepared.logical.geometry;
    const rows = try geometry.traceRowCount();
    const committed_rows = geometry.commitment_rows;
    const preprocessed = try base.trees.require(.preprocessed);
    const main = try base.trees.require(.main);
    const interaction = try base.trees.require(.interaction);

    const source_columns = [relation_mod.source_pointer_count]Words{
        try coefficientColumn(preprocessed, 4, rows),
        try coefficientColumn(preprocessed, 5, rows),
        try coefficientColumn(preprocessed, 6, rows),
        try coefficientColumn(main, 3, rows),
        try coefficientColumn(main, 0, rows),
        try coefficientColumn(main, 1, rows),
        try coefficientColumn(main, 2, rows),
    };
    var output_coordinates: [relation_mod.output_coordinate_count]Words =
        undefined;
    for (&output_coordinates, 0..) |*output, index| {
        output.* = try coefficientColumn(interaction, index, rows);
    }

    const lookup_elements = try exactAs(
        provider,
        field.SecureField,
        slots.lookup_elements,
        2,
    );
    const claimed_sum = try exactAs(
        provider,
        field.SecureField,
        slots.relation_claimed_sum,
        1,
    );
    const relation = Relation{
        .buffers = .{
            .drawn_z_alpha = lookup_elements,
            .alpha_powers = try exactAs(
                provider,
                field.SecureField,
                slots.relation_alpha_powers,
                relation_mod.max_alpha_powers,
            ),
            .z = try exactAs(
                provider,
                field.SecureField,
                slots.relation_z,
                1,
            ),
            .source_tables = try exactWords(
                provider,
                slots.relation_source_tables,
                2,
            ),
            .descriptors = try exactWords(
                provider,
                slots.relation_descriptor_tables,
                2,
            ),
            .output_tables = try exactWords(
                provider,
                slots.relation_output_tables,
                2,
            ),
            .denominator_slabs = try exactWords(
                provider,
                slots.relation_denominator_tables,
                2,
            ),
            .geometry = try exactAs(
                provider,
                relation_stage.Geometry,
                slots.relation_geometry,
                1,
            ),
            .claimed_sums = try exactWords(
                provider,
                slots.relation_claimed_sum_tables,
                2,
            ),
            .reduction_partials = try exactWords(
                provider,
                slots.relation_reduction_partials,
                try relationScratchWords(geometry.statement.log_size),
            ),
            .scan_block_sums = try exactWords(
                provider,
                slots.relation_scan_block_sums,
                try relationScratchWords(geometry.statement.log_size),
            ),
        },
        .source_columns = source_columns,
        .output_coordinates = output_coordinates,
        .source_pointer_table = try exactWords(
            provider,
            slots.relation_source_pointer_table,
            relation_mod.source_pointer_count * 2,
        ),
        .descriptor_storage = try exactWords(
            provider,
            slots.relation_descriptors,
            relation_mod.interaction_column_count *
                @import(
                    "../../../backends/cuda/abi/stages/relation.zig",
                ).descriptor_words,
        ),
        .output_pointer_table = try exactWords(
            provider,
            slots.relation_output_pointer_table,
            relation_mod.output_coordinate_count * 2,
        ),
        .denominator_slab = try exactAs(
            provider,
            field.SecureField,
            slots.relation_denominator_slab,
            relation_mod.interaction_column_count * rows,
        ),
        .claimed_sum = claimed_sum,
    };

    return .{
        .base = base,
        .relation = relation,
        .constraint_buffers = .{
            .source_evaluations = .{
                .storage = try base.source_evaluations.storage.sub(
                    0,
                    geometry.traceColumnCount() * committed_rows,
                ),
                .column_stride_words = committed_rows,
            },
            .random_coefficient_powers = try exactAs(
                provider,
                field.SecureField,
                slots.composition_powers,
                @import("../../../examples/xor/component.zig").N_CONSTRAINTS,
            ),
            .denominator_inverses = try exactWords(
                provider,
                slots.constraint_denominator_inverses,
                2,
            ),
            .lookup_elements = lookup_elements,
            .claimed_sum = claimed_sum,
            .composition_coordinates = base.constraint_buffers.composition_coordinates,
        },
    };
}

fn coefficientColumn(
    tree: @import("../common/resident_views.zig").TraceTree,
    index: usize,
    rows: usize,
) !Words {
    if (index >= tree.column_log_sizes.len or
        tree.coefficients.column_stride_words < rows)
    {
        return error.InvalidKernelDescriptor;
    }
    return tree.coefficients.storage.sub(
        index * tree.coefficients.column_stride_words,
        rows,
    );
}

fn relationScratchWords(log_rows: u32) !usize {
    const plan = try relation_mod.Plan.init(log_rows);
    return @intCast(try plan.topology().scratchWords());
}

fn exactWords(
    provider: anytype,
    id: slots.SlotId,
    expected: usize,
) !Words {
    const value = try provider.slot(id);
    if (value.len != expected) return error.InvalidKernelDescriptor;
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
    if (result.len != expected) return error.InvalidKernelDescriptor;
    return result;
}

test "exact XOR binds four trees and one complete relation instance" {
    const geometry = try geometry_mod.admit(
        .{ .log_size = 8, .log_step = 2, .offset = 3 },
        @import("stwo_core").pcs.PcsConfig.default(),
    );
    var prepared = try plan_mod.PreparedPlan.init(
        std.testing.allocator,
        geometry,
    );
    defer prepared.deinit(std.testing.allocator);
    const provider = TestProvider{ .prepared = &prepared };
    const bound = try bind(&provider, &prepared);
    try std.testing.expectEqual(
        @as(usize, 4),
        bound.base.trees.active().len,
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        (try bound.base.trees.require(.interaction)).column_log_sizes.len,
    );
    try std.testing.expectEqual(
        @as(usize, 15),
        bound.constraint_buffers.source_evaluations.storage.len /
            bound.constraint_buffers.source_evaluations.column_stride_words,
    );
    const instance = bound.relation.instance();
    const relation_plan = try relation_mod.Plan.init(
        geometry.statement.log_size,
    );
    const runtime_plan = try relation_stage.prepare(
        std.testing.allocator,
        .{
            .topology = relation_plan.topology(),
            .buffers = bound.relation.buffers,
            .instances = &.{instance},
        },
    );
    relation_stage.deinit(std.testing.allocator, runtime_plan);
}

const TestProvider = struct {
    prepared: *const plan_mod.PreparedPlan,

    pub fn slot(
        self: *const TestProvider,
        id: slots.SlotId,
    ) !Words {
        const placement = try self
            .prepared
            .cuda_plan
            .arena_plan
            .placement(id);
        return .{
            .address = 0x1_0000_0000 +
                placement.offset_words * @sizeOf(u32),
            .len = placement.requirement.words,
            .owner = 7,
            .generation = 11,
        };
    }
};
