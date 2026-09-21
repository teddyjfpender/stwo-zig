const std = @import("std");
const profile = @import("secp256k1_adaptive_profile_v1.zig");
const statement = @import("ethereum_statement.zig");

test "adaptive secp profile omits only an exactly empty retirement family" {
    const plan = try profile.compile(.{
        .base_steps = 4_194_304,
        .keccak_calls = 0,
        .signer_calls = 0,
        .total_steps = 4_194_304,
    }, emptyShapes());
    try std.testing.expectEqual(profile.Mode.inactive_zero_count, plan.mode);
    try std.testing.expectEqual(@as(u32, 0), plan.selected_component_count);
    try std.testing.expectEqual(@as(u64, 828), plan.legacy_costs.preprocessed_cells);
    try std.testing.expectEqual(@as(u64, 10_818), plan.legacy_costs.main_cells);
    try std.testing.expectEqual(@as(u64, 6_048), plan.legacy_costs.interaction_cells);
    try std.testing.expectEqual(@as(u64, 17_694), plan.legacy_costs.total_cells);
    try std.testing.expectEqual(@as(u64, 0), plan.selected_costs.total_cells);
    try std.testing.expectEqual(@as(u64, 3_698_046), try profile.projectedOmittedCells(
        plan,
        209,
    ));
    try plan.validate();
    try std.testing.expect(!profile.production_active);

    var forged = plan;
    forged.verifier_program_identity[0] ^= 1;
    try std.testing.expectError(error.PlanMismatch, forged.validate());
}

test "adaptive secp profile keeps active compact geometry and rejects count drift" {
    const active = try profile.compile(.{
        .base_steps = 100,
        .keccak_calls = 3,
        .signer_calls = 1,
        .total_steps = 104,
    }, activeShapes());
    try std.testing.expectEqual(profile.Mode.compact_v1, active.mode);
    try std.testing.expectEqual(profile.component_count, active.selected_component_count);
    try std.testing.expectEqual(
        active.legacy_costs.total_cells,
        active.selected_costs.total_cells,
    );
    try active.validate();

    var bad_retirement = active.retirement;
    bad_retirement.total_steps += 1;
    try std.testing.expectError(
        error.RetirementCountMismatch,
        profile.compile(bad_retirement, active.shapes),
    );
    var bad_shapes = active.shapes;
    bad_shapes.recovery_caller.n_rows = 0;
    try std.testing.expectError(
        error.CallCountMismatch,
        profile.compile(active.retirement, bad_shapes),
    );
    bad_shapes = emptyShapes();
    bad_shapes.scalar.n_rows = 1;
    try std.testing.expectError(
        error.InvalidComponentGeometry,
        profile.compile(.{
            .base_steps = 100,
            .keccak_calls = 0,
            .signer_calls = 0,
            .total_steps = 100,
        }, bad_shapes),
    );
}

fn emptyShapes() statement.SecpShapes {
    const empty = statement.Shape{ .log_size = 1, .n_rows = 0 };
    return .{
        .product_base = empty,
        .product_scalar = empty,
        .linear_base = empty,
        .linear_scalar = empty,
        .point = empty,
        .split = empty,
        .scalar = empty,
        .table = empty,
        .recovery = empty,
        .byte = .{ .log_size = 8, .n_rows = 256 },
        .recovery_caller = empty,
    };
}

fn activeShapes() statement.SecpShapes {
    const singleton = statement.Shape{ .log_size = 1, .n_rows = 1 };
    return .{
        .product_base = singleton,
        .product_scalar = singleton,
        .linear_base = singleton,
        .linear_scalar = singleton,
        .point = singleton,
        .split = singleton,
        .scalar = singleton,
        .table = singleton,
        .recovery = singleton,
        .byte = .{ .log_size = 8, .n_rows = 256 },
        .recovery_caller = singleton,
    };
}
