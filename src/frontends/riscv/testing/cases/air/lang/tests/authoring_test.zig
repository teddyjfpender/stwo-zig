//! Executable examples for the public typed AIR authoring surface.

const std = @import("std");
const canonical_air_eab98d = @import("stwo_riscv_air_lang").modules.degree;
const canonical_air_2ce8fd = @import("stwo_riscv_air_lang").modules.digest;
const canonical_air_63de32 = @import("stwo_riscv_air_lang").modules.functions;
const canonical_air_6539f5 = @import("stwo_riscv_air_lang").modules.hints;
const canonical_air_1bd16a = @import("stwo_riscv_air_lang").modules.ir;
const canonical_air_19f017 = @import("stwo_riscv_air_lang").modules.manifest;
const canonical_air_e299bd = @import("stwo_riscv_air_lang").modules.source;
const canonical_air_3c1a7c = @import("stwo_riscv_air_lang").modules.types;
const canonical_air_e777c6 = @import("stwo_riscv_air_lang").modules.validate;

test "public authoring example compiles a minimal pure component" {
    var arena = try buildPure(std.testing.allocator);
    defer arena.deinit();
    try canonical_air_e777c6.validate(&arena);

    var degrees = try canonical_air_eab98d.analyze(std.testing.allocator, &arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(canonical_air_eab98d.Degree, 2), degrees.maximumConstraintDegree());
    const identity = try canonical_air_2ce8fd.compute(&arena);
    try std.testing.expect(!std.mem.allEqual(u8, &identity, 0));
    const manifest = try canonical_air_19f017.serializeAlloc(std.testing.allocator, &arena);
    defer std.testing.allocator.free(manifest);
    try std.testing.expect(std.mem.startsWith(u8, manifest, canonical_air_19f017.magic));
}

test "public authoring example compiles a bound hint and ordered effect" {
    var arena = try buildEffectful(std.testing.allocator);
    defer arena.deinit();
    try canonical_air_e777c6.validate(&arena);

    try std.testing.expectEqual(@as(usize, 1), canonical_air_6539f5.view(&arena).len);
    try std.testing.expectEqual(@as(usize, 1), arena.effectsView().len);
    const hint_id = try canonical_air_3c1a7c.idFromIndex(canonical_air_3c1a7c.HintId, 0);
    try std.testing.expectEqual(@as(usize, 2), canonical_air_6539f5.bindings(&arena, hint_id).?.len);
    const identity = try canonical_air_2ce8fd.compute(&arena);
    try std.testing.expect(!std.mem.allEqual(u8, &identity, 0));
}

fn buildPure(allocator: std.mem.Allocator) !canonical_air_1bd16a.Arena {
    var arena = canonical_air_1bd16a.Arena.init(allocator);
    errdefer arena.deinit();
    const generated = canonical_air_e299bd.SourceSpan.generated();
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
    _ = try canonical_air_63de32.add(
        &arena,
        "example.add",
        &.{ lhs, rhs },
        &.{sum},
        generated,
    );
    return arena;
}

fn buildEffectful(allocator: std.mem.Allocator) !canonical_air_1bd16a.Arena {
    var arena = canonical_air_1bd16a.Arena.init(allocator);
    errdefer arena.deinit();
    const generated = canonical_air_e299bd.SourceSpan.generated();
    const input = try arena.input("example.input", .felt, generated);
    const active = try arena.input("example.active", .bit, generated);
    const hint_id = try canonical_air_6539f5.add(
        &arena,
        .identity_felt,
        &.{input},
        active,
        generated,
    );
    const output = canonical_air_6539f5.outputs(&arena, hint_id).?[0];
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
    try canonical_air_6539f5.bind(&arena, hint_id, &.{
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
