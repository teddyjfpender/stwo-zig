//! Binding/admission tests only; physical root proof tests remain separate.
const std = @import("std");
const wire = @import("stwo_circuit_recursion_wire");
const F = @import("fold_root.zig");
const A = @import("root_admission.zig");
const walk = @import("transcript_walk.zig");
const Node = wire.packed_node.PackedNode;
const a = std.testing.allocator;
const fold_hash: [8]u32 = @splat(9);
fn encode(node: Node) ![]u8 {
    var writer = std.Io.Writer.Allocating.init(a);
    errdefer writer.deinit();
    try wire.packed_node.writePackedNode(&writer.writer, node);
    return writer.toOwnedSlice();
}
fn probe(allocator: std.mem.Allocator, json: []const u8, expected: []const A.Leaf, digest: [8]u32) !void {
    return F.verifyPackedStatements(allocator, json, expected, fold_hash, digest);
}
test "root admission requires separately trusted topology and bounds leaf count" {
    const trusted = A.TrustedTopologies{ .schema = A.SCHEMA, .leaves = &.{.{ .circuit_hash = @splat(11), .layout_digest = @splat(3) }} };
    try trusted.validate(1);
    try trusted.leaves[0].checkLayout(@splat(3));
    try std.testing.expectError(error.LeafLayoutMismatch, trusted.leaves[0].checkLayout(@splat(4)));
    try std.testing.expectError(error.InvalidRecursionLeafCount, trusted.validate(0));
    try std.testing.expectError(error.InvalidRecursionLeafCount, trusted.validate(A.MAX_LEAVES + 1));
    try std.testing.expectError(error.InvalidTrustedLeafTopologies, trusted.validate(2));
    try std.testing.expectError(error.LeafCircuitHashMismatch, A.checkLeaf(.{ .circuit_hash = trusted.leaves[0].circuit_hash, .statement_digest = @splat(7) }, @splat(12), @splat(7)));
    const wrong_schema = A.TrustedTopologies{ .schema = "producer-self-admission", .leaves = trusted.leaves };
    try std.testing.expectError(error.InvalidTrustedLeafTopologies, wrong_schema.validate(1));
}
test "packed root binds ordered leaf statements and rejects detached self-consistent JSON" {
    const words0 = [_]u32{ 1, 2, 3 };
    const words1 = [_]u32{ 4, 5, 6 };
    const text0 = try F.encodeWords(a, &words0);
    defer a.free(text0);
    const text1 = try F.encodeWords(a, &words1);
    defer a.free(text1);
    const leaf0: Node = .{ .composite = .{ .circuit_hash = @splat(11), .subtasks = &.{.{ .plain = &.{text0} }} } };
    const leaf1: Node = .{ .composite = .{ .circuit_hash = @splat(12), .subtasks = &.{.{ .plain = &.{text1} }} } };
    const root: Node = .{ .composite = .{ .circuit_hash = fold_hash, .subtasks = &.{ leaf0, leaf1 } } };
    const json = try encode(root);
    defer a.free(json);
    const expected = [_]A.Leaf{
        .{ .circuit_hash = @splat(11), .statement_digest = walk.statementDigest(&words0) },
        .{ .circuit_hash = @splat(12), .statement_digest = walk.statementDigest(&words1) },
    };
    const digest = F.parentDigest(&.{ .{ .circuit_hash = expected[0].circuit_hash, .digest = expected[0].statement_digest }, .{ .circuit_hash = expected[1].circuit_hash, .digest = expected[1].statement_digest } });
    try probe(a, json, &expected, digest);
    try std.testing.checkAllAllocationFailures(a, probe, .{ json, &expected, digest });
    // Attacker leaves root proof/packed bytes unchanged but replaces the JSON
    // public/words/output digest by a different internally consistent statement.
    var detached = expected;
    detached[0].statement_digest = walk.statementDigest(&.{ 7, 8, 9 });
    try std.testing.expectError(error.LeafStatementDigestMismatch, probe(a, json, &detached, digest));
    var self_admitted = expected;
    self_admitted[0].circuit_hash = @splat(99);
    try std.testing.expectError(error.LeafCircuitHashMismatch, probe(a, json, &self_admitted, digest));
    const reversed = [_]A.Leaf{ expected[1], expected[0] };
    try std.testing.expectError(error.LeafCircuitHashMismatch, probe(a, json, &reversed, digest));
}
test "every internal packed circuit must have canonical multiverifier topology" {
    const text = try F.encodeWords(a, &.{7});
    defer a.free(text);
    const leaf: Node = .{ .composite = .{ .circuit_hash = @splat(11), .subtasks = &.{.{ .plain = &.{text} }} } };
    const expected = [_]A.Leaf{.{ .circuit_hash = @splat(11), .statement_digest = walk.statementDigest(&.{7}) }};
    const child = F.Child{ .circuit_hash = expected[0].circuit_hash, .digest = expected[0].statement_digest };
    const digest = F.parentDigest(&.{ child, child });
    const valid: Node = .{ .composite = .{ .circuit_hash = fold_hash, .subtasks = &.{leaf} } };
    const valid_json = try encode(valid);
    defer a.free(valid_json);
    try probe(a, valid_json, &expected, digest);
    const fake: Node = .{ .composite = .{ .circuit_hash = @splat(99), .subtasks = &.{leaf} } };
    const fake_json = try encode(fake);
    defer a.free(fake_json);
    try std.testing.expectError(error.FoldCircuitHashMismatch, probe(a, fake_json, &expected, digest));
    const nested: Node = .{ .composite = .{ .circuit_hash = fold_hash, .subtasks = &.{fake} } };
    const nested_json = try encode(nested);
    defer a.free(nested_json);
    try std.testing.expectError(error.FoldCircuitHashMismatch, probe(a, nested_json, &expected, digest));
}

test "root leaf count rejects before allocation and composite traversal has a hard node budget" {
    const too_many: [A.MAX_LEAVES + 1]A.Leaf = @splat(.{ .circuit_hash = @splat(11), .statement_digest = @splat(7) });
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidRecursionLeafCount, probe(failing.allocator(), "", &too_many, @splat(0)));
    const text = try F.encodeWords(a, &.{7});
    defer a.free(text);
    const leaf: Node = .{ .composite = .{ .circuit_hash = @splat(11), .subtasks = &.{.{ .plain = &.{text} }} } };
    var nodes: [127]Node = undefined;
    var digests: [127][8]u32 = undefined;
    for (nodes[0..64], digests[0..64]) |*node, *digest| {
        node.* = leaf;
        digest.* = walk.statementDigest(&.{7});
    }
    var children: [63][2]Node = undefined;
    var next: usize = 64;
    var start: usize = 0;
    var count: usize = 64;
    while (count > 1) {
        for (0..count / 2) |pair| {
            const slot = next - 64;
            children[slot] = .{ nodes[start + 2 * pair], nodes[start + 2 * pair + 1] };
            digests[next] = F.parentDigest(&.{
                .{ .circuit_hash = if (start == 0) @splat(11) else fold_hash, .digest = digests[start + 2 * pair] },
                .{ .circuit_hash = if (start == 0) @splat(11) else fold_hash, .digest = digests[start + 2 * pair + 1] },
            });
            nodes[next] = .{ .composite = .{ .circuit_hash = fold_hash, .subtasks = &children[slot] } };
            next += 1;
        }
        start += count;
        count /= 2;
    }
    const expected: [64]A.Leaf = @splat(.{ .circuit_hash = @splat(11), .statement_digest = walk.statementDigest(&.{7}) });
    const valid_json = try encode(nodes[126]);
    defer a.free(valid_json);
    try probe(a, valid_json, &expected, digests[126]);
    const extra: Node = .{ .composite = .{ .circuit_hash = fold_hash, .subtasks = nodes[126..127] } };
    const json = try encode(extra);
    defer a.free(json);
    try std.testing.expectError(error.PackedTreeResourceLimit, probe(a, json, &expected, @splat(0)));
}
