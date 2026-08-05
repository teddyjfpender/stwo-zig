const std = @import("std");
const functions = @import("functions.zig");
const hints = @import("hints.zig");
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
    try std.testing.expectEqual(@as(usize, 1), hints.view(&fixture.arena).len);
    try std.testing.expectEqual(@as(usize, 2), fixture.arena.effectsView().len);
    try std.testing.expectEqual(@as(usize, 2), functions.view(&fixture.arena).len);
    try std.testing.expectEqual(@as(usize, 1), functions.calls(&fixture.arena).len);

    const hint_id = try types.idFromIndex(types.HintId, 0);
    try std.testing.expectEqualSlices(
        types.ValueId,
        &.{fixture.lhs},
        hints.inputs(&fixture.arena, hint_id).?,
    );
    try std.testing.expectEqualSlices(
        types.ValueId,
        &.{fixture.hint_output},
        hints.outputs(&fixture.arena, hint_id).?,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        hints.bindings(&fixture.arena, hint_id).?.len,
    );
    const second_effect = try types.idFromIndex(types.EffectId, 1);
    try std.testing.expectEqualSlices(
        types.ValueId,
        &.{fixture.hint_output},
        fixture.arena.effectValues(second_effect).?,
    );
    const call_id = try types.idFromIndex(types.CallId, 0);
    try std.testing.expectEqualSlices(
        types.ValueId,
        &.{ fixture.lhs, fixture.rhs, fixture.live },
        functions.callArguments(&fixture.arena, call_id).?,
    );
    try std.testing.expectEqualSlices(
        types.ValueId,
        &.{fixture.call_output},
        functions.callOutputs(&fixture.arena, call_id).?,
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
        error.InvalidHintInputType,
        hints.add(&arena, .identity_felt, &.{live}, live, generated),
    );
    try std.testing.expectError(
        error.InvalidHintActivation,
        hints.add(&arena, .identity_felt, &.{felt}, felt, generated),
    );
    const hint_id = try hints.add(
        &arena,
        .identity_felt,
        &.{felt},
        live,
        generated,
    );
    try std.testing.expectError(error.UnboundHintOutput, validate.validate(&arena));
    const hint_output = hints.outputs(&arena, hint_id).?[0];
    const hint_root = try arena.sub(hint_output, felt, generated);
    const hint_binding = try arena.assertZero(
        "hint.identity",
        hint_root,
        live,
        .hint_binding,
        generated,
    );
    try std.testing.expectError(
        error.InvalidHintBindingPath,
        hints.bind(&arena, hint_id, &.{.{
            .output_index = 0,
            .target = .{ .constraint = hint_binding },
            .path = &.{hint_output},
        }}),
    );
    try hints.bind(&arena, hint_id, &.{.{
        .output_index = 0,
        .target = .{ .constraint = hint_binding },
        .path = &.{ hint_output, hint_root },
    }});
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

    _ = try functions.add(&arena, "unit", &.{}, &.{}, generated);
    try std.testing.expectError(
        error.InvalidFunctionInput,
        functions.add(&arena, "bad_input", &.{sum}, &.{sum}, generated),
    );
    _ = try functions.add(&arena, "sum", &.{ lhs, rhs }, &.{sum}, generated);
    try std.testing.expectError(
        error.DuplicateFunctionName,
        functions.add(&arena, "sum", &.{ lhs, rhs }, &.{sum}, generated),
    );
}

test "static calls are typed and dependency-topological" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const lhs = try arena.input("lhs", .felt, generated);
    const rhs = try arena.input("rhs", .felt, generated);
    const bit = try arena.input("bit", .bit, generated);
    const sum = try arena.add(lhs, rhs, generated);
    const callee = try functions.add(
        &arena,
        "callee",
        &.{ lhs, rhs },
        &.{sum},
        generated,
    );
    const caller = try functions.begin(
        &arena,
        "caller",
        &.{ lhs, rhs },
        generated,
    );
    try std.testing.expectError(
        error.FunctionAlreadyOpen,
        functions.begin(&arena, "nested", &.{lhs}, generated),
    );
    try std.testing.expectError(
        error.NonTopologicalCall,
        functions.call(
            &arena,
            caller,
            &.{ lhs, rhs },
            .inline_expansion,
            generated,
        ),
    );
    try std.testing.expectError(
        error.CallArityMismatch,
        functions.call(
            &arena,
            callee,
            &.{lhs},
            .inline_expansion,
            generated,
        ),
    );
    try std.testing.expectError(
        error.ArgumentTypeMismatch,
        functions.call(
            &arena,
            callee,
            &.{ bit, rhs },
            .inline_expansion,
            generated,
        ),
    );
    const call_id = try functions.call(
        &arena,
        callee,
        &.{ lhs, rhs },
        .relation_backed,
        generated,
    );
    const call_outputs = functions.callOutputs(&arena, call_id).?;
    try std.testing.expectEqual(@as(usize, 1), call_outputs.len);
    try std.testing.expect(std.meta.eql(
        arena.node(call_outputs[0]).?.key.ty,
        arena.node(sum).?.key.ty,
    ));
    try functions.finish(&arena, caller, call_outputs);
    try validate.validate(&arena);
}
