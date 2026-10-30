const std = @import("std");
const C = @import("../block_v8_window_chain_v1.zig");
fn d(value: u8) C.Digest {
    return @splat(value);
}
fn leaf(index: u32) C.Leaf {
    return .{ .key = d(@intCast(index + 10)), .public_input = d(@intCast(index + 20)), .profile = d(3), .epoch = d(4), .policy = d(5), .span = .{ .elf = d(1), .program = d(2), .incoming = d(@intCast(index + 30)), .outgoing = d(@intCast(index + 31)), .begin = @as(u64, index) * 100, .end = @as(u64, index + 1) * 100, .leaves = 1 } };
}
test "three genuine leaves retain exact count and independently indexed registry paths" {
    const a = std.testing.allocator;
    const leaves = [_]C.Leaf{ leaf(0), leaf(1), leaf(2) };
    var registry = try C.Registry.derive(a, &leaves, 3);
    defer registry.deinit();
    try std.testing.expectEqual(@as(u32, 3), registry.count);
    try std.testing.expectEqual(@as(usize, 4), registry.padded);
    try std.testing.expectEqual(@as(u64, 0), registry.span.begin);
    try std.testing.expectEqual(@as(u64, 300), registry.span.end);
    for (leaves, 0..) |item, index| {
        const path = try registry.path(a, @intCast(index));
        defer a.free(path);
        try C.requireMembership(registry.root, registry.count, registry.span, @intCast(index), item, path);
        var forged = item;
        forged.key[0] ^= 1;
        try std.testing.expectError(error.UntrustedWindowChainRegistry, C.requireMembership(registry.root, registry.count, registry.span, @intCast(index), forged, path));
        forged = item;
        forged.public_input[0] ^= 1;
        try std.testing.expectError(error.UntrustedWindowChainRegistry, C.requireMembership(registry.root, registry.count, registry.span, @intCast(index), forged, path));
        try std.testing.expectError(error.InvalidWindowChainIndex, C.requireMembership(registry.root, registry.count, registry.span, 3, item, path));
    }
    // This is a descriptor/commitment test, never proof or block authority.
    try std.testing.expect(!C.publication_qualified);
}
test "chain closure rejects gaps overlaps reorderings omitted state and mixed programs" {
    var left = leaf(0).span;
    var right = leaf(1).span;
    _ = try C.Span.join(left, right);
    right.begin += 1;
    try std.testing.expectError(error.NoncontiguousWindowChain, C.Span.join(left, right));
    right = leaf(1).span;
    right.begin -= 1;
    try std.testing.expectError(error.NoncontiguousWindowChain, C.Span.join(left, right));
    right = leaf(1).span;
    right.incoming[0] ^= 1;
    try std.testing.expectError(error.WindowChainStateMismatch, C.Span.join(left, right));
    right = leaf(1).span;
    right.elf[0] ^= 1;
    try std.testing.expectError(error.WindowChainProgramMismatch, C.Span.join(left, right));
    try std.testing.expectError(error.NoncontiguousWindowChain, C.Span.join(leaf(1).span, leaf(0).span));
    left.leaves = std.math.maxInt(u32);
    try std.testing.expectError(error.Overflow, C.Span.join(left, leaf(1).span));
}
test "registry rejects reordered duplicate and zero-key rosters before committing" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.WindowChainResourceLimit, C.Registry.derive(a, &.{}, 3));
    try std.testing.expectError(error.NoncontiguousWindowChain, C.Registry.derive(a, &.{ leaf(0), leaf(0) }, 3));
    try std.testing.expectError(error.NoncontiguousWindowChain, C.Registry.derive(a, &.{ leaf(1), leaf(0) }, 3));
    var item = leaf(0);
    item.key = @splat(0);
    try std.testing.expectError(error.InvalidWindowChainLeaf, C.Registry.derive(a, &.{item}, 3));
}
