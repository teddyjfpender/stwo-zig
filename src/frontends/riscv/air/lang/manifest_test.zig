const std = @import("std");
const ir = @import("ir.zig");
const manifest = @import("manifest.zig");
const source = @import("source.zig");
const test_support = @import("test_support.zig");

test "logical manifest has a pinned empty-program encoding" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const actual = try manifest.serializeAlloc(std.testing.allocator, &arena);
    defer std.testing.allocator.free(actual);

    const expected = "STWAIRL\x00" ++
        "\x03\x00" ++
        "\x02\x00" ++
        "\x00\x00\x00\x00" ** 6;
    try std.testing.expectEqualStrings(expected, actual);
}

test "logical manifest is independent of interning insertion order and address" {
    var canonical = try test_support.Fixture.init(std.testing.allocator);
    defer canonical.deinit();
    var perturbed = try test_support.Fixture.initPerturbed(std.testing.allocator);
    defer perturbed.deinit();

    const canonical_bytes = try manifest.serializeAlloc(
        std.testing.allocator,
        &canonical.arena,
    );
    defer std.testing.allocator.free(canonical_bytes);
    const perturbed_bytes = try manifest.serializeAlloc(
        std.testing.allocator,
        &perturbed.arena,
    );
    defer std.testing.allocator.free(perturbed_bytes);

    try std.testing.expectEqualSlices(u8, canonical_bytes, perturbed_bytes);
}

test "logical manifest preserves semantic effect order" {
    var forward = try effectOrderProgram(std.testing.allocator, false);
    defer forward.deinit();
    var reverse = try effectOrderProgram(std.testing.allocator, true);
    defer reverse.deinit();
    const forward_bytes = try manifest.serializeAlloc(std.testing.allocator, &forward);
    defer std.testing.allocator.free(forward_bytes);
    const reverse_bytes = try manifest.serializeAlloc(std.testing.allocator, &reverse);
    defer std.testing.allocator.free(reverse_bytes);
    try std.testing.expect(!std.mem.eql(u8, forward_bytes, reverse_bytes));
}

test "logical manifest binds call lowering strategy" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const inline_bytes = try manifest.serializeAlloc(
        std.testing.allocator,
        &fixture.arena,
    );
    defer std.testing.allocator.free(inline_bytes);
    fixture.arena.calls.items[0].strategy = .relation_backed;
    const relation_bytes = try manifest.serializeAlloc(
        std.testing.allocator,
        &fixture.arena,
    );
    defer std.testing.allocator.free(relation_bytes);
    try std.testing.expect(!std.mem.eql(u8, inline_bytes, relation_bytes));
}

test "logical manifest binds explicit hint proof paths" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const all_bindings = try manifest.serializeAlloc(
        std.testing.allocator,
        &fixture.arena,
    );
    defer std.testing.allocator.free(all_bindings);

    var range = fixture.arena.hints.items[0].bindings.?;
    range.len = 1;
    fixture.arena.hints.items[0].bindings = range;
    fixture.arena.hint_bindings.shrinkRetainingCapacity(1);
    const first_path = fixture.arena.hint_bindings.items[0].path;
    fixture.arena.hint_binding_values.shrinkRetainingCapacity(
        @as(usize, first_path.start) + @as(usize, first_path.len),
    );
    const constraint_only = try manifest.serializeAlloc(
        std.testing.allocator,
        &fixture.arena,
    );
    defer std.testing.allocator.free(constraint_only);
    try std.testing.expect(!std.mem.eql(u8, all_bindings, constraint_only));
}

test "logical manifest validates before writing any bytes" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    fixture.arena.hints.items[0].inputs.start = 1;

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.InvalidRange,
        manifest.writeCanonical(bytes.writer(std.testing.allocator), &fixture.arena),
    );
    try std.testing.expectEqual(@as(usize, 0), bytes.items.len);
}

fn manifestAllocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try test_support.Fixture.init(allocator);
    defer fixture.deinit();
    const bytes = try manifest.serializeAlloc(allocator, &fixture.arena);
    defer allocator.free(bytes);
}

test "logical manifest releases every partial serialization allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        manifestAllocationFailureCase,
        .{},
    );
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
