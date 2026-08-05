const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const hint_recipe = @import("hint_recipe.zig");
const types = @import("types.zig");

test "hint recipe registry has stable typed identities and signatures" {
    try std.testing.expectEqual(@as(usize, 2), hint_recipe.recipes.len);
    for (hint_recipe.recipes, 0..) |recipe, index| {
        try std.testing.expectEqual(index, types.idIndex(recipe.id));
        try std.testing.expectEqual(index, @intFromEnum(recipe.kind));
        try std.testing.expect(recipe.version != 0);
        try std.testing.expect(recipe.name.len != 0);
    }

    const inverse = hint_recipe.get(.field_inverse_or_zero);
    try std.testing.expectEqual(
        hint_recipe.ExceptionalCasePolicy.zero_returns_zero_inverse_and_false,
        inverse.exceptional_cases,
    );
    try std.testing.expectEqualSlices(
        types.Type,
        &.{.felt},
        inverse.input_types,
    );
    try std.testing.expectEqualSlices(
        types.Type,
        &.{ .felt, .bit },
        inverse.output_types,
    );
}

test "hint recipe invocation rejects unknown IDs, arity, and type drift" {
    const identity = hint_recipe.id(.identity_felt);
    try hint_recipe.validateInvocation(identity, &.{.felt}, &.{.felt});
    try std.testing.expectError(
        error.InvalidHintInputArity,
        hint_recipe.validateInvocation(identity, &.{}, &.{.felt}),
    );
    try std.testing.expectError(
        error.InvalidHintInputType,
        hint_recipe.validateInvocation(identity, &.{.bit}, &.{.felt}),
    );
    try std.testing.expectError(
        error.InvalidHintOutputType,
        hint_recipe.validateInvocation(identity, &.{.felt}, &.{.bit}),
    );
    const unknown = try types.idFromIndex(types.HintRecipeId, 999);
    try std.testing.expectError(
        error.UnknownHintRecipe,
        hint_recipe.validateInvocation(unknown, &.{.felt}, &.{.felt}),
    );
}

test "hint recipe honest evaluator pins inverse exceptional behavior" {
    var identity_output = [_]u32{0};
    try hint_recipe.evaluateField(
        hint_recipe.id(.identity_felt),
        &.{17},
        &identity_output,
    );
    try std.testing.expectEqual(@as(u32, 17), identity_output[0]);

    var inverse_outputs = [_]u32{ 99, 99 };
    try hint_recipe.evaluateField(
        hint_recipe.id(.field_inverse_or_zero),
        &.{0},
        &inverse_outputs,
    );
    try std.testing.expectEqualSlices(u32, &.{ 0, 0 }, &inverse_outputs);

    try hint_recipe.evaluateField(
        hint_recipe.id(.field_inverse_or_zero),
        &.{7},
        &inverse_outputs,
    );
    try std.testing.expectEqual(@as(u32, 1), inverse_outputs[1]);
    const product = m31.M31.fromCanonical(7).mul(
        m31.M31.fromCanonical(inverse_outputs[0]),
    );
    try std.testing.expect(product.isOne());
    try std.testing.expectError(
        error.NonCanonicalHintInput,
        hint_recipe.evaluateField(
            hint_recipe.id(.identity_felt),
            &.{m31.Modulus},
            &identity_output,
        ),
    );
}
