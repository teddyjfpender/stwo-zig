//! Native Plonk instantiation of the shared resident arena bindings.

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

pub const bind = Binding.bind;

test "Plonk binds four, four, and eight resident columns" {
    const std = @import("std");
    const geometry = try geometry_mod.admit(
        .{ .log_n_rows = 8 },
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
        (try bound.trees.require(.preprocessed)).column_log_sizes.len,
    );
    try std.testing.expectEqual(
        @as(usize, 4),
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
    ) !@import("stwo_cuda_backend").runtime.column.DeviceSlice(u32) {
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
