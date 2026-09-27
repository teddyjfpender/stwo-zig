//! Pure byte-equation/layout/OOM fixtures. No proof is built/accepted and no
//! literal metadata fixture enters a positive fresh capture/receiver path.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Graph = @import("../recursion/air/block_v5_input_tail_ancestor_graph_v1.zig");
const Bus = @import("../recursion/block_v5_input_tail_ancestor_bus_v1.zig");
const Binding = @import("../recursion/air/block_v5_tail_linked_public_binding_v2.zig");
const Input = @import("../recursion/block_v5_tail_linked_input_policy_v2.zig");
const OldInput = @import("../recursion/block_v5_wide_input_policy_v1.zig");
const Values = struct {
    words: []const u32,
    mismatch_child: ?u32 = null,
    mismatch_coordinate: u32 = 0,
    pub fn at(self: Values, wire: Bus.Wire) ![4]M {
        if (wire.kind != .child_cell or wire.child > 3 or wire.coordinate >= self.words.len) return error.InvalidFixtureCell;
        var value = self.words[wire.coordinate];
        if (self.mismatch_child == wire.child and self.mismatch_coordinate == wire.coordinate) value ^= 1;
        var bytes: [4]M = undefined;
        for (&bytes, 0..) |*byte, part| byte.* = M.fromCanonical((value >> @as(u5, @intCast(8 * part))) & 255);
        return if (wire.part) |part| .{ bytes[part], M.zero(), M.zero(), M.zero() } else bytes;
    }
};
fn graphFixture(a: std.mem.Allocator) !void {
    const words = [_]u32{ 0xffffffff, 0x80000000, 0, 1, 0xaabbccdd, 0x11223344, 0xcafef00d, 0x12345678 };
    const pairs = [_]Graph.Pair{
        .{ .provider = .{ .child = 0, .first = 0, .words = 8 }, .consumer = .{ .child = 1, .first = 0, .words = 8 } },
        .{ .provider = .{ .child = 0, .first = 0, .words = 8 }, .consumer = .{ .child = 2, .first = 0, .words = 8 } },
        .{ .provider = .{ .child = 0, .first = 0, .words = 8 }, .consumer = .{ .child = 3, .first = 0, .words = 8 } },
    };
    var graph = try Graph.preparePairs(a, Values{ .words = &words }, &pairs);
    defer graph.deinit();
    try std.testing.expectEqual(@as(usize, 3 * 8 * 4 * 2), graph.inputs.len);
    for (graph.sources, 0..) |source, index| {
        try std.testing.expectEqual(@as(u32, if (index % 2 == 0) 0 else @intCast(index / 64 + 1)), source.child);
        try std.testing.expectEqual(@as(u32, @intCast(index % 64 / 8)), source.coordinate);
        try std.testing.expectEqual(@as(u2, @intCast(index % 8 / 2)), source.part.?);
    }
    const mutated = try a.dupe(Q, graph.inputs);
    defer a.free(mutated);
    mutated[1] = mutated[1].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(mutated, graph.values));
}
test "tail linked public: one provider exact byte source mapping feeds three consumers" {
    try graphFixture(std.testing.allocator);
}
test "tail linked public: graph construction propagates every original allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, graphFixture, .{});
}
test "tail linked public: mismatched provider length prefix or CV byte fails equations" {
    const words = [_]u32{ 7, 8, 9, 10, 11, 12, 13, 14 };
    const pair = [_]Graph.Pair{.{ .provider = .{ .child = 0, .first = 0, .words = 8 }, .consumer = .{ .child = 1, .first = 0, .words = 8 } }};
    for (0..8) |coordinate| {
        try std.testing.expectError(error.UnsatisfiedCircuit, Graph.preparePairs(std.testing.allocator, Values{ .words = &words, .mismatch_child = 1, .mismatch_coordinate = @intCast(coordinate) }, &pair));
    }
    var invalid = pair;
    invalid[0].consumer.words = 7;
    try std.testing.expectError(error.UntrustedInputTailAncestorCell, Graph.preparePairs(std.testing.allocator, Values{ .words = &words }, &invalid));
}
test "tail linked public: exact virtual word mapping preserves original raw ordinals" {
    const Request = @import("../recursion/air/block_v5_input_tail_public_digest_v1.zig").Request;
    try std.testing.expectEqual(@as(u32, 77), try Binding.sourceWord(1000, 239, Request{ .circuit = 0, .wire = 0, .uses = 1, .source = .{ .public_field = 77 } }));
    try std.testing.expectEqual(@as(u32, 1247), try Binding.sourceWord(1000, 239, Request{ .circuit = 0, .wire = 0, .uses = 1, .source = .{ .input_prefix = 238 } }));
    try std.testing.expectEqual(@as(u32, 1263), try Binding.sourceWord(1000, 239, Request{ .circuit = 0, .wire = 0, .uses = 1, .source = .{ .frontier = .{ .ordinal = 1, .word = 7 } } }));
    try std.testing.expectError(error.Overflow, Binding.sourceWord(std.math.maxInt(u32), 239, Request{ .circuit = 0, .wire = 0, .uses = 1, .source = .{ .input_prefix = 0 } }));
}
test "tail linked public: large original input has bounded new grammar and distinct protocol" {
    const Root = @import("../recursion/block_v5_tail_linked_public_windows_v2.zig");
    const Old = @import("../recursion/block_v5_wide_public_windows_v1.zig");
    try std.testing.expectEqual(@as(u32, 1), Old.VERSION);
    try std.testing.expectEqual(@as(u32, 2), Root.VERSION);
    try std.testing.expectEqual(@as(u32, 1), @import("../recursion/block_v5_reusable_wide_public_windows_protocol_v1.zig").VERSION);
    try std.testing.expectEqual(@as(u32, 2), @import("../recursion/block_v5_reusable_tail_linked_public_windows_protocol_v2.zig").VERSION);
    try std.testing.expectEqual(@as(u32, 3), @import("../recursion/block_v5_input_tail_ancestor_protocol_v1.zig").VERSION);
    try std.testing.expectEqual(@as(u32, 4_300_220), @import("../recursion/block_v5_wide_public_windows_source_v1.zig").PUBLIC_CIRCUIT);
    try std.testing.expectEqual(@as(u32, 4_300_260), @import("../recursion/block_v5_tail_linked_public_windows_source_v2.zig").PUBLIC_CIRCUIT);
    try std.testing.expect(Root.Policy != Old.Policy);
    try std.testing.expect(Input.Owned != OldInput.Owned);
    try std.testing.expect(try Input.cellsForWordCount((1 << 20) + 1) < 512);
    try std.testing.expect(try Input.cellsForWordCount(16 << 20) < 512);
    try std.testing.expectEqual(@as(usize, 239), try Input.cellsForWordCount(239));
    try std.testing.expectEqual(@as(usize, 249), try Input.cellsForWordCount(240));
    try std.testing.expectError(error.UntrustedWidePublicWindowRoster, (Root.Range{ .first = 0, .count = 5 }).require(5));
    try std.testing.expect(!Root.Owner.complete_block_authority);
    try std.testing.expect(!Bus.Owner.complete_source_authority);
}
