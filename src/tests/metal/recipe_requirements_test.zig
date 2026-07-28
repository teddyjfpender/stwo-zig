const std = @import("std");
const arena_binding = @import("../../integrations/cairo_metal/arena_binding.zig");
const recipe_requirements = @import("../../integrations/cairo_metal/recipe_requirements.zig");

test {
    std.testing.refAllDecls(recipe_requirements);
}

test "Cairo Metal witness recipes match requirements exactly" {
    try (arena_binding.WitnessRecipes{}).validate(.{});
    try std.testing.expectError(
        arena_binding.Error.MissingBinding,
        (arena_binding.WitnessRecipes{}).validate(.{ .verify_instruction = true }),
    );

    var compact: @import("stwo_metal_backend").protocol_recipes.CompactRecipe = undefined;
    try std.testing.expectError(
        arena_binding.Error.InvalidSchedule,
        (arena_binding.WitnessRecipes{ .compact_verify = &compact }).validate(.{}),
    );
    try (arena_binding.WitnessRecipes{ .compact_verify = &compact }).validate(.{
        .verify_instruction = true,
    });
}
