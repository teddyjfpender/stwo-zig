//! Executable examples for the public typed AIR authoring surface.

const std = @import("std");
const air = @import("mod.zig");

test "public authoring example compiles a minimal pure component" {
    var arena = try buildPure(std.testing.allocator);
    defer arena.deinit();
    try air.validate.validate(&arena);

    var degrees = try air.degree.analyze(std.testing.allocator, &arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(air.degree.Degree, 2), degrees.maximumConstraintDegree());
    const identity = try air.digest.compute(&arena);
    try std.testing.expect(!std.mem.allEqual(u8, &identity, 0));
    const manifest = try air.manifest.serializeAlloc(std.testing.allocator, &arena);
    defer std.testing.allocator.free(manifest);
    try std.testing.expect(std.mem.startsWith(u8, manifest, air.manifest.magic));
}

test "public authoring example compiles a bound hint and ordered effect" {
    var arena = try buildEffectful(std.testing.allocator);
    defer arena.deinit();
    try air.validate.validate(&arena);

    try std.testing.expectEqual(@as(usize, 1), air.hints.view(&arena).len);
    try std.testing.expectEqual(@as(usize, 1), arena.effectsView().len);
    const hint_id = try air.types.idFromIndex(air.types.HintId, 0);
    try std.testing.expectEqual(@as(usize, 2), air.hints.bindings(&arena, hint_id).?.len);
    const identity = try air.digest.compute(&arena);
    try std.testing.expect(!std.mem.allEqual(u8, &identity, 0));
}

fn buildPure(allocator: std.mem.Allocator) !air.ir.Arena {
    var arena = air.ir.Arena.init(allocator);
    errdefer arena.deinit();
    const generated = air.source.SourceSpan.generated();
    const lhs = try arena.input("example.lhs", .felt, generated);
    const rhs = try arena.input("example.rhs", .felt, generated);
    const expected = try arena.input("example.expected", .felt, generated);
    const active = try arena.input("example.active", .bit, generated);
    const sum = try arena.add(lhs, rhs, generated);
    const difference = try arena.sub(sum, expected, generated);
    _ = try arena.assertZero(
        "example.addition",
        difference,
        active,
        .semantic,
        generated,
    );
    _ = try air.functions.add(
        &arena,
        "example.add",
        &.{ lhs, rhs },
        &.{sum},
        generated,
    );
    return arena;
}

fn buildEffectful(allocator: std.mem.Allocator) !air.ir.Arena {
    var arena = air.ir.Arena.init(allocator);
    errdefer arena.deinit();
    const generated = air.source.SourceSpan.generated();
    const input = try arena.input("example.input", .felt, generated);
    const active = try arena.input("example.active", .bit, generated);
    const hint_id = try air.hints.add(
        &arena,
        .identity_felt,
        &.{input},
        active,
        generated,
    );
    const output = air.hints.outputs(&arena, hint_id).?[0];
    const binding_root = try arena.sub(output, input, generated);
    const constraint = try arena.assertZero(
        "example.identity",
        binding_root,
        active,
        .hint_binding,
        generated,
    );
    const effect = try arena.addEffect(
        .public_produce,
        &.{output},
        active,
        null,
        generated,
    );
    try air.hints.bind(&arena, hint_id, &.{
        .{
            .output_index = 0,
            .target = .{ .constraint = constraint },
            .path = &.{ output, binding_root },
        },
        .{
            .output_index = 0,
            .target = .{ .effect = effect },
            .path = &.{output},
        },
    });
    return arena;
}
