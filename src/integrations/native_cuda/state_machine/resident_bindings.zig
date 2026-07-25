//! Exact mixed-height State v2 views over one resident proof arena.

const std = @import("std");
const field = @import("../../../backends/cuda/abi/field.zig");
const relation_abi = @import(
    "../../../backends/cuda/abi/stages/relation.zig",
);
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

pub const RelationInstance = struct {
    source_columns: [relation_mod.source_pointer_count]Words,
    output_coordinates: [relation_mod.output_coordinates_per_instance]Words,
    source_pointer_table: Words,
    descriptor_storage: Words,
    output_pointer_table: Words,
    denominator_slab: common.SecureFields,
    claimed_sum: common.SecureFields,

    fn binding(
        self: *const RelationInstance,
        descriptors: []const relation_abi.ColumnDescriptor,
    ) relation_stage.InstanceBinding {
        return .{
            .source_pointer_table = self.source_pointer_table,
            .source_columns = &self.source_columns,
            .descriptor_storage = self.descriptor_storage,
            .descriptors = descriptors,
            .output_pointer_table = self.output_pointer_table,
            .output_coordinates = &self.output_coordinates,
            .denominator_slab = self.denominator_slab,
            .claimed_sum = self.claimed_sum,
        };
    }
};

pub const Relation = struct {
    buffers: relation_stage.DeviceBuffers,
    instances: [relation_mod.instance_count]RelationInstance,
    source_values: common.WordMatrix,
    claimed_sums: common.SecureFields,

    pub fn bindings(
        self: *const Relation,
    ) [relation_mod.instance_count]relation_stage.InstanceBinding {
        return .{
            self.instances[0].binding(&relation_mod.x_descriptors),
            self.instances[1].binding(&relation_mod.y_descriptors),
        };
    }
};

pub const Bound = struct {
    base: shared.Bound,
    empty_preprocessed_root: Words,
    transcript_statement_words: Words,
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
    const interaction = try base.trees.require(.interaction);
    const source_values = common.WordMatrix{
        .storage = try exactWords(
            provider,
            slots.relation_source_values,
            geometry_mod.relation_source_columns * rows,
        ),
        .column_stride_words = rows,
    };
    const lookup_elements = try exactAs(
        provider,
        field.SecureField,
        slots.lookup_elements,
        2,
    );
    const claimed_sums = try exactAs(
        provider,
        field.SecureField,
        slots.relation_claimed_sums,
        relation_mod.instance_count,
    );
    const source_pointer_storage = try exactWords(
        provider,
        slots.relation_source_pointer_table,
        relation_mod.instance_count *
            relation_mod.source_pointer_count * 2,
    );
    const descriptor_storage = try exactWords(
        provider,
        slots.relation_descriptors,
        relation_mod.instance_count * relation_abi.descriptor_words,
    );
    const output_pointer_storage = try exactWords(
        provider,
        slots.relation_output_pointer_table,
        relation_mod.instance_count *
            relation_mod.output_coordinates_per_instance * 2,
    );
    const denominator_storage = try exactAs(
        provider,
        field.SecureField,
        slots.relation_denominator_slab,
        rows + rows / 2,
    );

    const x_instance = try relationInstance(
        source_values,
        interaction,
        0,
        0,
        rows,
        0,
        source_pointer_storage,
        descriptor_storage,
        output_pointer_storage,
        denominator_storage,
        try claimed_sums.sub(0, 1),
    );
    const y_instance = try relationInstance(
        source_values,
        interaction,
        2,
        4,
        rows / 2,
        rows,
        source_pointer_storage,
        descriptor_storage,
        output_pointer_storage,
        denominator_storage,
        try claimed_sums.sub(1, 1),
    );
    const committed_rows = geometry.commitment_rows;
    return .{
        .base = base,
        .empty_preprocessed_root = try exactWords(
            provider,
            slots.empty_preprocessed_root,
            8,
        ),
        .transcript_statement_words = try exactWords(
            provider,
            slots.transcript_statement_words,
            geometry_mod.transcript_statement_word_count,
        ),
        .relation = .{
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
                    relation_mod.instance_count * 2,
                ),
                .descriptors = try exactWords(
                    provider,
                    slots.relation_descriptor_tables,
                    relation_mod.instance_count * 2,
                ),
                .output_tables = try exactWords(
                    provider,
                    slots.relation_output_tables,
                    relation_mod.instance_count * 2,
                ),
                .denominator_slabs = try exactWords(
                    provider,
                    slots.relation_denominator_tables,
                    relation_mod.instance_count * 2,
                ),
                .geometry = try exactAs(
                    provider,
                    relation_stage.Geometry,
                    slots.relation_geometry,
                    relation_mod.instance_count,
                ),
                .claimed_sums = try exactWords(
                    provider,
                    slots.relation_claimed_sum_tables,
                    relation_mod.instance_count * 2,
                ),
                .reduction_partials = try exactWords(
                    provider,
                    slots.relation_reduction_partials,
                    try relationScratchWords(
                        geometry.statement.log_n_rows,
                    ),
                ),
                .scan_block_sums = try exactWords(
                    provider,
                    slots.relation_scan_block_sums,
                    try relationScratchWords(
                        geometry.statement.log_n_rows,
                    ),
                ),
            },
            .instances = .{ x_instance, y_instance },
            .source_values = source_values,
            .claimed_sums = claimed_sums,
        },
        .constraint_buffers = .{
            .source_evaluations = .{
                .storage = try base.source_evaluations.storage.sub(
                    0,
                    constraint.source_column_count * committed_rows,
                ),
                .column_stride_words = committed_rows,
            },
            .random_coefficient_powers = try exactAs(
                provider,
                field.SecureField,
                slots.composition_powers,
                constraint.constraint_count,
            ),
            .denominator_inverses = try exactWords(
                provider,
                slots.constraint_denominator_inverses,
                6,
            ),
            .lookup_elements = lookup_elements,
            .claimed_sums = claimed_sums,
            .composition_coordinates = base.constraint_buffers.composition_coordinates,
        },
    };
}

fn relationInstance(
    source_values: common.WordMatrix,
    interaction: @import("../common/resident_views.zig").TraceTree,
    main_first: usize,
    interaction_first: usize,
    rows: usize,
    denominator_first: usize,
    source_pointer_storage: Words,
    descriptor_storage: Words,
    output_pointer_storage: Words,
    denominator_storage: common.SecureFields,
    claimed_sum: common.SecureFields,
) !RelationInstance {
    const instance_index = main_first / 2;
    var outputs: [relation_mod.output_coordinates_per_instance]Words = undefined;
    for (&outputs, 0..) |*output, coordinate| {
        output.* = try coefficientColumn(
            interaction,
            interaction_first + coordinate,
            rows,
        );
    }
    return .{
        .source_columns = .{
            try matrixColumn(source_values, main_first, rows),
            try matrixColumn(source_values, main_first + 1, rows),
        },
        .output_coordinates = outputs,
        .source_pointer_table = try source_pointer_storage.sub(
            instance_index * relation_mod.source_pointer_count * 2,
            relation_mod.source_pointer_count * 2,
        ),
        .descriptor_storage = try descriptor_storage.sub(
            instance_index * relation_abi.descriptor_words,
            relation_abi.descriptor_words,
        ),
        .output_pointer_table = try output_pointer_storage.sub(
            instance_index *
                relation_mod.output_coordinates_per_instance * 2,
            relation_mod.output_coordinates_per_instance * 2,
        ),
        .denominator_slab = try denominator_storage.sub(
            denominator_first,
            rows,
        ),
        .claimed_sum = claimed_sum,
    };
}

fn matrixColumn(
    matrix: common.WordMatrix,
    index: usize,
    rows: usize,
) !Words {
    if (matrix.column_stride_words < rows or
        matrix.storage.len % matrix.column_stride_words != 0 or
        index >= matrix.storage.len / matrix.column_stride_words)
    {
        return error.InvalidKernelDescriptor;
    }
    return matrix.storage.sub(
        index * matrix.column_stride_words,
        rows,
    );
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

test "State v2 binds three resident trees and two relation instances" {
    const geometry = try geometry_mod.admit(
        .{
            .log_n_rows = 8,
            .initial_state = .{
                @import("stwo_core").fields.m31.M31.fromU64(9),
                @import("stwo_core").fields.m31.M31.fromU64(3),
            },
        },
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
        @as(usize, 3),
        bound.base.trees.active().len,
    );
    try std.testing.expectEqual(
        @as(usize, 8),
        (try bound.base.trees.require(.interaction))
            .column_log_sizes.len,
    );
    const bindings_value = bound.relation.bindings();
    const relation_plan = try relation_mod.Plan.init(
        geometry.statement.log_n_rows,
    );
    const runtime_plan = try relation_stage.prepare(
        std.testing.allocator,
        .{
            .topology = relation_plan.topology(),
            .buffers = bound.relation.buffers,
            .instances = &bindings_value,
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
