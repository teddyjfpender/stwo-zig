//! Native XOR instantiation of the shared resident arena bindings.

const std = @import("std");
const shared = @import("../common/resident_bindings.zig");
const geometry_mod = @import("geometry.zig");
const plan_mod = @import("plan.zig");
const proof_bundle = @import("proof_bundle.zig");
const slots = @import("slots.zig");

const Binding = shared.BindingFor(
    geometry_mod,
    plan_mod,
    slots,
    proof_bundle,
);

pub const Bound = shared.Bound;
pub const bind = Binding.bind;

test "XOR arena binding is structurally sealed" {
    var prepared = try plan_mod.prepare(
        std.testing.allocator,
        .{ .log_size = 8, .log_step = 3 },
    );
    defer prepared.deinit(std.testing.allocator);
    const provider = TestProvider{ .prepared = &prepared };
    const bound = try bind(&provider, &prepared);
    try std.testing.expectEqual(@as(usize, 3), bound.trees.active().len);
    try std.testing.expectEqual(
        @as(usize, 2),
        (try bound.trees.require(.preprocessed)).column_log_sizes.len,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        (try bound.trees.require(.main)).column_log_sizes.len,
    );
    try std.testing.expectEqual(
        @as(usize, 8),
        (try bound.trees.require(.composition)).column_log_sizes.len,
    );
}

const TestProvider = struct {
    prepared: *const plan_mod.PreparedPlan,

    pub fn slot(
        self: *const TestProvider,
        id: slots.SlotId,
    ) !@import(
        "../../../backends/cuda/runtime/column.zig",
    ).DeviceSlice(u32) {
        const placement = try self
            .prepared
            .cuda_plan
            .placement(@intFromEnum(id));
        return .{
            .address = 0x1000 + placement.offset,
            .len = placement.words,
            .owner = 1,
        };
    }
};
