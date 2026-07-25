const std = @import("std");
const stwo = @import("stwo_under_test");
const exact = stwo.integrations.native_cuda.poseidon;

test {
    std.testing.refAllDecls(exact);
}

test "exact Poseidon arena binds three non-empty trees and one relation" {
    const allocator = std.testing.allocator;
    const geometry = try exact.geometry.admit(
        .{ .log_n_instances = 11 },
        stwo.core.pcs.PcsConfig.default(),
    );
    var prepared = try exact.plan.PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);
    const provider = Provider{ .prepared = &prepared };
    const views = try exact.resident_bindings.bind(&provider, &prepared);

    try std.testing.expectEqual(
        @as(usize, 3),
        views.trace.trees.active().len,
    );
    try std.testing.expectEqual(
        @as(usize, 32),
        (try views.trace.trees.require(.interaction)).column_log_sizes.len,
    );
    try std.testing.expectEqual(
        @as(usize, 1296),
        views.constraint.source_evaluations.storage.len /
            views.constraint.source_evaluations.column_stride_words,
    );
    try std.testing.expectEqual(
        @as(usize, 4) * try geometry.traceRowCount(),
        views.constraint.source_evaluations.column_stride_words,
    );
    try std.testing.expectEqual(
        @as(usize, 256) * try geometry.traceRowCount(),
        views.relation.source_values.storage.len,
    );
    try std.testing.expect(
        views.relation.source_values.storage.address !=
            views.trace.main_coefficients.storage.address,
    );

    const relation_plan = try exact.relation.Plan.init(geometry.log_n_rows);
    const instance = views.relation.instance();
    const runtime_relation =
        stwo.backends.cuda.runtime.stages.relation;
    const prepared_relation = try runtime_relation.prepare(
        allocator,
        .{
            .topology = relation_plan.topology(),
            .buffers = views.relation.buffers,
            .instances = &.{instance},
        },
    );
    runtime_relation.deinit(allocator, prepared_relation);
}

test "Poseidon exact AIR domain is independent from commitment blowup" {
    const geometry = try exact.geometry.admit(
        .{ .log_n_instances = 13 },
        stwo.core.pcs.PcsConfig.default(),
    );
    try std.testing.expectEqual(
        2 * try geometry.traceRowCount(),
        geometry.commitment_rows,
    );
    try std.testing.expectEqual(
        4 * try geometry.traceRowCount(),
        geometry.composition_rows,
    );
    const descriptor =
        try stwo.backends.cuda.runtime.constraints.poseidon.descriptor(
            geometry.log_n_rows,
        );
    try std.testing.expectEqual(
        stwo.backends.cuda.abi.schema.KernelSchema
            .native_poseidon_constraint_v1,
        descriptor.abi_schema,
    );
}

const Provider = struct {
    prepared: *const exact.plan.PreparedPlan,

    pub fn slot(
        self: *const Provider,
        id: exact.slots.SlotId,
    ) !stwo.backends.cuda.runtime.column.DeviceSlice(u32) {
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
