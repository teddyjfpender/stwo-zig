const stwo = @import("stwo");
const std = @import("std");

const subject =
    stwo.integrations.native_cuda.wide_fibonacci.resident_bindings;
const plan_mod = stwo.integrations.native_cuda.wide_fibonacci.plan;
const proof_bundle =
    stwo.integrations.native_cuda.wide_fibonacci.proof_bundle;
const request = stwo.integrations.native_cuda.wide_fibonacci.request;
const slots = stwo.integrations.native_cuda.wide_fibonacci.slots;
const arena = stwo.backends.cuda.runtime.arena;
const column = stwo.backends.cuda.runtime.column;
const runtime_error = stwo.backends.cuda.runtime.runtime_error;

const base_address: usize = 0x1000_0000;

const FakeProvider = struct {
    prepared: *const plan_mod.PreparedPlan,
    truncated_slot: ?arena.SlotId = null,
    misaligned_slot: ?arena.SlotId = null,

    pub fn slot(
        self: *const FakeProvider,
        id: arena.SlotId,
    ) runtime_error.Error!column.DeviceSlice(u32) {
        const placement = try self.prepared.arena_plan.placement(id);
        var words = placement.requirement.words;
        if (self.truncated_slot == id) words -= 1;
        var address = base_address + placement.offset_words * @sizeOf(u32);
        if (self.misaligned_slot == id) address += @sizeOf(u32);
        return .{
            .address = address,
            .len = words,
            .owner = 17,
            .generation = 23,
        };
    }
};

test "prepared arena binds every proof phase to exact runtime shapes" {
    const allocator = std.testing.allocator;
    const geometry = try request.admit(testRequest(5, 8));
    var prepared = try plan_mod.PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);
    const provider = FakeProvider{ .prepared = &prepared };
    const views = try subject.bind(&provider, &prepared);

    try std.testing.expectEqual(
        geometry.main_columns * geometry.commitment_rows,
        views.trace.main_coefficients.storage.len,
    );
    try std.testing.expectEqual(
        geometry.commitment_rows,
        views.trace.main_coefficients.column_stride_words,
    );
    try std.testing.expectEqual(
        geometry.trace_rows,
        views.trace.composition_coefficients.column_stride_words,
    );
    try std.testing.expectEqual(
        (geometry.main_columns + request.composition_column_count) *
            geometry.commitment_rows,
        views.trace.all_evaluations.storage.len,
    );
    try std.testing.expectEqual(
        geometry.sampled_value_count,
        views.oods.sampled_values.len,
    );
    try std.testing.expectEqual(
        geometry.sampled_value_count,
        views.quotient.prepared_terms.len,
    );
    try std.testing.expectEqual(
        views.fri.layers[0].coordinates.storage.address,
        views.quotient.result_coordinates.c0.address,
    );
    try std.testing.expectEqual(
        @as(usize, 4) * geometry.commitment_rows,
        views.fri.layers[0].coordinates.storage.len,
    );
    try std.testing.expectEqual(
        geometry.fri_tree_count,
        views.fri.activeLayers().len,
    );
    try std.testing.expect(
        views.fri.last_evaluation.address !=
            views.fri.last_coefficients.address,
    );

    const fri_assembly = views.decommit.friAssembly(
        views.fri.layers[0],
        views.proof.decommitment,
    );
    try std.testing.expectEqual(
        views.fri.layers[0].coordinates.storage.address,
        fri_assembly.coordinates.storage.address,
    );
    try std.testing.expectEqual(
        prepared.proof.section(.decommitment).words,
        fri_assembly.assembly.len,
    );
    try std.testing.expectEqual(
        prepared.proof.total_words,
        views.proof.bundle.len,
    );
    try std.testing.expectEqual(
        proof_bundle.fixed_header_words - 1,
        (views.proof.degree_verdict.address -
            views.proof.bundle.address) / @sizeOf(u32),
    );
}

test "binding rejects capacity drift and typed alignment drift" {
    const allocator = std.testing.allocator;
    const geometry = try request.admit(testRequest(5, 8));
    var prepared = try plan_mod.PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);

    const truncated = FakeProvider{
        .prepared = &prepared,
        .truncated_slot = slots.committed_evaluation_slab,
    };
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        subject.bind(&truncated, &prepared),
    );

    const misaligned = FakeProvider{
        .prepared = &prepared,
        .misaligned_slot = slots.main_merkle_hashes,
    };
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        subject.bind(&misaligned, &prepared),
    );

    prepared.fri.layers[0].coordinate_words += 1;
    const valid_provider = FakeProvider{ .prepared = &prepared };
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        subject.bind(&valid_provider, &prepared),
    );
}

test "binding arithmetic covers minimum standard and extreme geometry" {
    const allocator = std.testing.allocator;
    for ([_]u32{ 3, 14, 22 }) |log_n_rows| {
        const geometry = try request.admit(testRequest(log_n_rows, 100));
        var prepared = try plan_mod.PreparedPlan.init(allocator, geometry);
        defer prepared.deinit(allocator);
        const provider = FakeProvider{ .prepared = &prepared };
        const views = try subject.bind(&provider, &prepared);
        try std.testing.expectEqual(
            geometry.commitment_rows,
            views.fri.layers[0].coordinates.column_stride_words,
        );
        try std.testing.expectEqual(
            geometry.fri_tree_count,
            views.fri.layer_count,
        );
    }
}

fn testRequest(log_n_rows: u32, sequence_len: u32) request.Request {
    return .{
        .statement = .{
            .log_n_rows = log_n_rows,
            .sequence_len = sequence_len,
        },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    };
}
