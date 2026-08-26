const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const hint_recipe = @import("hint_recipe.zig");
const types = @import("types.zig");

test "hint recipe registry has stable typed identities and signatures" {
    try std.testing.expectEqual(@as(usize, 3), hint_recipe.recipes.len);
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

    const divrem = hint_recipe.get(.rv32_divrem);
    try std.testing.expectEqual(
        hint_recipe.ExceptionalCasePolicy.rv32_divrem_zero_and_signed_overflow,
        divrem.exceptional_cases,
    );
    try std.testing.expectEqualSlices(
        types.Type,
        &.{ .word32, .word32, .bit },
        divrem.input_types,
    );
    try std.testing.expectEqualSlices(
        types.Type,
        &.{ .word32, .word32, .bit, .bit },
        divrem.output_types,
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
    try hint_recipe.validateInvocation(
        hint_recipe.id(.rv32_divrem),
        &.{ .word32, .word32, .bit },
        &.{ .word32, .word32, .bit, .bit },
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
    var div_outputs = [_]u32{0} ** 4;
    try std.testing.expectError(
        error.UnsupportedFieldRecipe,
        hint_recipe.evaluateField(
            hint_recipe.id(.rv32_divrem),
            &.{ 1, 1, 0 },
            &div_outputs,
        ),
    );
}

test "RV32 DIVREM hint pins every architectural exceptional class" {
    const Case = struct {
        lhs: u32,
        rhs: u32,
        signed: bool,
        quotient: u32,
        remainder: u32,
        class: hint_recipe.DivRemClass,
    };
    const cases = [_]Case{
        .{ .lhs = 17, .rhs = 5, .signed = false, .quotient = 3, .remainder = 2, .class = .regular },
        .{ .lhs = 17, .rhs = 0, .signed = false, .quotient = 0xffff_ffff, .remainder = 17, .class = .zero_divisor },
        .{ .lhs = 0xffff_fff1, .rhs = 4, .signed = true, .quotient = 0xffff_fffd, .remainder = 0xffff_fffd, .class = .regular },
        .{ .lhs = 15, .rhs = 0xffff_fffc, .signed = true, .quotient = 0xffff_fffd, .remainder = 3, .class = .regular },
        .{ .lhs = 0xffff_fff1, .rhs = 0xffff_fffc, .signed = true, .quotient = 3, .remainder = 0xffff_fffd, .class = .regular },
        .{ .lhs = 0x8000_0000, .rhs = 0xffff_ffff, .signed = true, .quotient = 0x8000_0000, .remainder = 0, .class = .signed_overflow },
        .{ .lhs = 0x8000_0000, .rhs = 0, .signed = true, .quotient = 0xffff_ffff, .remainder = 0x8000_0000, .class = .zero_divisor },
        .{ .lhs = 0x8000_0000, .rhs = 0xffff_ffff, .signed = false, .quotient = 0, .remainder = 0x8000_0000, .class = .regular },
    };
    for (cases) |case| {
        const actual = try hint_recipe.evaluateDivRem(
            hint_recipe.id(.rv32_divrem),
            case.lhs,
            case.rhs,
            case.signed,
        );
        try std.testing.expectEqual(case.quotient, actual.quotient);
        try std.testing.expectEqual(case.remainder, actual.remainder);
        try std.testing.expectEqual(case.class, actual.class);
        try std.testing.expectEqual(
            case.class == .zero_divisor,
            actual.zeroDivisor(),
        );
        try std.testing.expectEqual(
            case.class == .signed_overflow,
            actual.signedOverflow(),
        );
    }
    try std.testing.expectError(
        error.UnsupportedFieldRecipe,
        hint_recipe.evaluateDivRem(
            hint_recipe.id(.identity_felt),
            1,
            1,
            false,
        ),
    );
}
