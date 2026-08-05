const std = @import("std");
const hints = @import("hints.zig");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

test "hint builder seals declarations and bindings in canonical order" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const felt = try arena.input("felt", .felt, generated);
    const live = try arena.input("live", .bit, generated);
    const first = try hints.add(
        &arena,
        .identity_felt,
        &.{felt},
        live,
        generated,
    );
    const second = try hints.add(
        &arena,
        .identity_felt,
        &.{felt},
        live,
        generated,
    );
    const first_output = hints.outputs(&arena, first).?[0];
    const second_output = hints.outputs(&arena, second).?[0];
    const first_root = try arena.sub(first_output, felt, generated);
    const second_root = try arena.sub(second_output, felt, generated);
    const first_constraint = try arena.assertZero(
        "hint.first",
        first_root,
        live,
        .hint_binding,
        generated,
    );
    const second_constraint = try arena.assertZero(
        "hint.second",
        second_root,
        live,
        .hint_binding,
        generated,
    );

    try std.testing.expectError(
        error.NonCanonicalHintBindingOrder,
        hints.bind(&arena, second, &.{.{
            .output_index = 0,
            .target = .{ .constraint = second_constraint },
            .path = &.{ second_output, second_root },
        }}),
    );
    const unknown = try types.idFromIndex(types.HintId, 999);
    try std.testing.expectError(error.UnknownHint, hints.bind(&arena, unknown, &.{}));
    try hints.bind(&arena, first, &.{.{
        .output_index = 0,
        .target = .{ .constraint = first_constraint },
        .path = &.{ first_output, first_root },
    }});
    try std.testing.expectError(
        error.HintAlreadyBound,
        hints.bind(&arena, first, &.{}),
    );
    try hints.bind(&arena, second, &.{.{
        .output_index = 0,
        .target = .{ .constraint = second_constraint },
        .path = &.{ second_output, second_root },
    }});
    try validate.validate(&arena);
}

test "hint builder rejects incomplete, mismatched, and malformed proof paths" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const felt = try arena.input("felt", .felt, generated);
    const live = try arena.input("live", .bit, generated);
    const hint_id = try hints.add(
        &arena,
        .field_inverse_or_zero,
        &.{felt},
        live,
        generated,
    );
    const outputs = hints.outputs(&arena, hint_id).?;
    const product = try arena.mul(felt, outputs[0], generated);
    const root = try arena.sub(product, outputs[1], generated);
    const binding = try arena.assertZero(
        "hint.inverse",
        root,
        live,
        .hint_binding,
        generated,
    );
    const wrong_activation = try arena.assertZero(
        "hint.inverse.ungated",
        root,
        null,
        .hint_binding,
        generated,
    );

    try std.testing.expectError(
        error.InvalidHintBindingTarget,
        hints.bind(&arena, hint_id, &.{.{
            .output_index = 0,
            .target = .{ .constraint = wrong_activation },
            .path = &.{ outputs[0], product, root },
        }}),
    );
    try std.testing.expectError(
        error.InvalidHintBindingPath,
        hints.bind(&arena, hint_id, &.{.{
            .output_index = 0,
            .target = .{ .constraint = binding },
            .path = &.{ outputs[0], root },
        }}),
    );
    try std.testing.expectError(
        error.InvalidHintBindingOutput,
        hints.bind(&arena, hint_id, &.{.{
            .output_index = 0,
            .target = .{ .constraint = binding },
            .path = &.{ outputs[0], product, root },
        }}),
    );
    try std.testing.expectError(
        error.NonCanonicalHintBindingOrder,
        hints.bind(&arena, hint_id, &.{
            .{
                .output_index = 1,
                .target = .{ .constraint = binding },
                .path = &.{ outputs[1], root },
            },
            .{
                .output_index = 0,
                .target = .{ .constraint = binding },
                .path = &.{ outputs[0], product, root },
            },
        }),
    );
    try hints.bind(&arena, hint_id, &.{
        .{
            .output_index = 0,
            .target = .{ .constraint = binding },
            .path = &.{ outputs[0], product, root },
        },
        .{
            .output_index = 1,
            .target = .{ .constraint = binding },
            .path = &.{ outputs[1], root },
        },
    });
    try validate.validate(&arena);
}
