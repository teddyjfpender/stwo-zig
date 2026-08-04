const std = @import("std");
const ir = @import("ir.zig");
const source = @import("source.zig");
const test_support = @import("test_support.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

test "whole logical program owns ordered records and passes validation" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    try validate.validate(&fixture.arena);
    try std.testing.expectEqual(@as(usize, 2), fixture.arena.constraintsView().len);
    try std.testing.expectEqual(@as(usize, 1), fixture.arena.hintsView().len);
    try std.testing.expectEqual(@as(usize, 2), fixture.arena.effectsView().len);
    try std.testing.expectEqual(@as(usize, 2), fixture.arena.functionsView().len);

    const hint_id = try types.idFromIndex(types.HintId, 0);
    try std.testing.expectEqualSlices(
        types.ValueId,
        &.{fixture.lhs},
        fixture.arena.hintInputs(hint_id).?,
    );
    try std.testing.expectEqualSlices(
        types.ValueId,
        &.{fixture.hint_output},
        fixture.arena.hintOutputs(hint_id).?,
    );
    const second_effect = try types.idFromIndex(types.EffectId, 1);
    try std.testing.expectEqualSlices(
        types.ValueId,
        &.{fixture.hint_output},
        fixture.arena.effectValues(second_effect).?,
    );
}

test "program constructors reject invalid constraint declarations" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const felt = try arena.input("felt", .felt, generated);
    const word = try arena.input("word", .word32, generated);

    try std.testing.expectError(
        error.InvalidConstraintRoot,
        arena.assertZero("word", word, null, .semantic, generated),
    );
    try std.testing.expectError(
        error.InvalidConstraintGate,
        arena.assertZero("gate", felt, felt, .semantic, generated),
    );
    _ = try arena.assertZero("unique", felt, null, .semantic, generated);
    try std.testing.expectError(
        error.DuplicateConstraintName,
        arena.assertZero("unique", felt, null, .semantic, generated),
    );
}

test "program constructors reject malformed hints and effects" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const felt = try arena.input("felt", .felt, generated);
    const live = try arena.input("live", .bit, generated);

    try std.testing.expectError(
        error.EmptyHintOutputs,
        arena.addHint("empty", &.{felt}, &.{}, generated),
    );
    try std.testing.expectError(
        error.EmptyEffectValues,
        arena.addEffect(.program_fetch, &.{}, live, null, generated),
    );
    try std.testing.expectError(
        error.InvalidEffectLiveness,
        arena.addEffect(.program_fetch, &.{felt}, felt, null, generated),
    );
    try std.testing.expectError(
        error.InvalidAccessOrdinal,
        arena.addEffect(.register_read, &.{felt}, live, null, generated),
    );
    try std.testing.expectError(
        error.InvalidAccessOrdinal,
        arena.addEffect(.program_fetch, &.{felt}, live, 0, generated),
    );
    _ = try arena.addEffect(.register_read, &.{felt}, live, 0, generated);
    try std.testing.expectError(
        error.DuplicateAccessOrdinal,
        arena.addEffect(.memory_read, &.{felt}, live, 0, generated),
    );
}

test "program constructors reject malformed function signatures" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const lhs = try arena.input("lhs", .felt, generated);
    const rhs = try arena.input("rhs", .felt, generated);
    const sum = try arena.add(lhs, rhs, generated);

    try std.testing.expectError(
        error.EmptyFunction,
        arena.addFunction("empty", &.{}, &.{}, generated),
    );
    try std.testing.expectError(
        error.InvalidFunctionInput,
        arena.addFunction("bad_input", &.{sum}, &.{sum}, generated),
    );
    _ = try arena.addFunction("sum", &.{ lhs, rhs }, &.{sum}, generated);
    try std.testing.expectError(
        error.DuplicateFunctionName,
        arena.addFunction("sum", &.{ lhs, rhs }, &.{sum}, generated),
    );
}
