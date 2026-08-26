const std = @import("std");
const digest = @import("digest.zig");
const ir = @import("ir.zig");
const source = @import("source.zig");
const test_support = @import("test_support.zig");
const types = @import("types.zig");

test "semantic digest has a pinned empty-program identity" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const actual = try digest.compute(&arena);
    const rendered = std.fmt.bytesToHex(actual, .lower);
    const expected = "0a8ed93f815b86478c087ca82bdbc63f9fcd6d6d9a170c896ebf610f8c26459f";
    try std.testing.expectEqualStrings(expected, &rendered);
}

test "legacy relation effects retain their pinned v1 semantic identity" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const actual = try digest.compute(&fixture.arena);
    const rendered = std.fmt.bytesToHex(actual, .lower);
    const expected = "adb43b290f45dc96d7d3c4d5ca91ada30acecfabbb3a29a4301da9b240cea389";
    try std.testing.expectEqualStrings(expected, &rendered);
}

test "semantic digest ignores allocation, interning, and diagnostic sources" {
    var canonical = try test_support.Fixture.init(std.testing.allocator);
    defer canonical.deinit();
    var perturbed = try test_support.Fixture.initPerturbed(std.testing.allocator);
    defer perturbed.deinit();

    const canonical_digest = try digest.compute(&canonical.arena);
    const perturbed_digest = try digest.compute(&perturbed.arena);
    try std.testing.expectEqual(canonical_digest, perturbed_digest);

    scrubDiagnosticSpans(&perturbed.arena);
    const source_free_digest = try digest.compute(&perturbed.arena);
    try std.testing.expectEqual(canonical_digest, source_free_digest);
}

test "semantic digest binds type, name, record order, and call strategy" {
    var felt_program = try inputProgram(std.testing.allocator, "value", .felt);
    defer felt_program.deinit();
    var byte_program = try inputProgram(std.testing.allocator, "value", .byte);
    defer byte_program.deinit();
    var renamed_program = try inputProgram(std.testing.allocator, "renamed", .felt);
    defer renamed_program.deinit();
    const felt_digest = try digest.compute(&felt_program);
    const byte_digest = try digest.compute(&byte_program);
    const renamed_digest = try digest.compute(&renamed_program);
    try std.testing.expect(!std.mem.eql(u8, &felt_digest, &byte_digest));
    try std.testing.expect(!std.mem.eql(u8, &felt_digest, &renamed_digest));

    var forward = try effectOrderProgram(std.testing.allocator, false);
    defer forward.deinit();
    var reverse = try effectOrderProgram(std.testing.allocator, true);
    defer reverse.deinit();
    const forward_digest = try digest.compute(&forward);
    const reverse_digest = try digest.compute(&reverse);
    try std.testing.expect(!std.mem.eql(u8, &forward_digest, &reverse_digest));

    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const inline_digest = try digest.compute(&fixture.arena);
    fixture.arena.calls.items[0].strategy = .relation_backed;
    const relation_digest = try digest.compute(&fixture.arena);
    try std.testing.expect(!std.mem.eql(u8, &inline_digest, &relation_digest));
}

test "semantic digest validates before hashing" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    fixture.arena.hints.items[0].inputs.start = 1;
    try std.testing.expectError(error.InvalidRange, digest.compute(&fixture.arena));
}

fn scrubDiagnosticSpans(arena: *ir.Arena) void {
    const generated = source.SourceSpan.generated();
    for (arena.nodes.items) |*node| node.primary_source = generated;
    for (arena.constraints.items) |*constraint| constraint.source_span = generated;
    for (arena.hints.items) |*hint| hint.source_span = generated;
    for (arena.effects.items) |*effect| effect.source_span = generated;
    for (arena.functions.items) |*function| function.source_span = generated;
    for (arena.calls.items) |*call| call.source_span = generated;
}

fn inputProgram(
    allocator: std.mem.Allocator,
    name: []const u8,
    ty: types.Type,
) !ir.Arena {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    _ = try arena.input(name, ty, source.SourceSpan.generated());
    return arena;
}

fn effectOrderProgram(
    allocator: std.mem.Allocator,
    reverse: bool,
) !ir.Arena {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const generated = source.SourceSpan.generated();
    const lhs = try arena.input("lhs", .felt, generated);
    const rhs = try arena.input("rhs", .felt, generated);
    if (reverse) {
        _ = try arena.addEffect(.public_produce, &.{rhs}, null, null, generated);
        _ = try arena.addEffect(.public_consume, &.{lhs}, null, null, generated);
    } else {
        _ = try arena.addEffect(.public_consume, &.{lhs}, null, null, generated);
        _ = try arena.addEffect(.public_produce, &.{rhs}, null, null, generated);
    }
    return arena;
}
