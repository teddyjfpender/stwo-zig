const std = @import("std");
const exact = @import("stwo_under_test")
    .integrations
    .native_cuda
    .state_machine;

test {
    std.testing.refAllDecls(exact);
}

test "State v2 prepared plan binds exact mixed relation topology" {
    const allocator = std.testing.allocator;
    const geometry = try exact.geometry.admit(
        .{
            .log_n_rows = 8,
            .initial_state = .{
                @import("stwo_under_test").core.fields.m31.M31.fromU64(9),
                @import("stwo_under_test").core.fields.m31.M31.fromU64(3),
            },
        },
        @import("stwo_under_test").core.pcs.PcsConfig.default(),
    );
    var prepared = try exact.plan.PreparedPlan.init(
        allocator,
        geometry,
    );
    defer prepared.deinit(allocator);
    const provider = Provider{ .prepared = &prepared };
    const bound = try exact.resident_bindings.bind(
        &provider,
        &prepared,
    );
    try std.testing.expectEqual(
        @as(usize, 3),
        bound.base.trees.active().len,
    );
    try std.testing.expectEqual(
        exact.geometry.terminal_statement_words,
        bound.base.proof.statement.len,
    );
}

const Provider = struct {
    prepared: *const exact.plan.PreparedPlan,

    pub fn slot(
        self: *const Provider,
        id: exact.slots.SlotId,
    ) !@import("stwo_under_test").backends.cuda.runtime.column
        .DeviceSlice(u32) {
        const placement = try self
            .prepared
            .cuda_plan
            .arena_plan
            .placement(id);
        return .{
            .address = 0x1_0000_0000 +
                placement.offset_words * @sizeOf(u32),
            .len = placement.requirement.words,
            .owner = 17,
            .generation = 19,
        };
    }
};
