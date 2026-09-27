const std = @import("std");
const exact = @import("blake3_exact_root_aggregate.zig");
const tree = @import("blake3_execution_tree.zig");
const parent = @import("blake3_execution_parent_preparation.zig");
const protocol = @import("blake3_execution_parent_protocol.zig");

test "exact-count V2 outer root compiles and rejects empty children" {
    const fixture = @import("span_statement_blake3_test_fixture.zig");
    const job = try fixture.job(3);
    const empty: []const *const tree.Node = &.{};
    try std.testing.expectError(error.InvalidExactRootCount, exact.prepare(
        std.testing.allocator, job, empty, @splat(0), 1024,
    ));
    const root = try exact.expectedRoot(job);
    try std.testing.expectEqual(@as(u32, 3), root.statement.body.executed.segment_count);
    try std.testing.expectEqual(@as(u8, 2), root.statement.slots.height);
}

test "exact-count V2 outer key binding is domain separated and leaves v3 unchanged" {
    const base = parent.Context{
        .child_key_id = @splat(1),
        .child_config = protocol.CSP_CONFIG,
        .graph_ids = @splat(@splat(2)),
        .transcript_plan_id = @splat(3),
        .statement_identity = @splat(4),
        .span_binding_id = @splat(5),
    };
    const original = try protocol.contextIdentity(base);
    var extension = base;
    extension.exact_aggregation = .{
        .roster_digest = @splat(6),
        .binding_digest = @splat(7),
        .child_count = 5,
    };
    const bound = try protocol.contextIdentity(extension);
    try std.testing.expect(!std.mem.eql(u8, &original, &bound));
    extension.exact_aggregation.?.roster_digest[0] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &bound, &try protocol.contextIdentity(extension)));
    extension.exact_aggregation.?.child_count = 1;
    try std.testing.expectError(error.InvalidBlake3ExactAggregation, protocol.contextIdentity(extension));
}
