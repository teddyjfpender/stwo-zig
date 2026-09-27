//! Join two independently prepared child verifiers and their adjacent Spans.
//! Distinct inputs are consumed on every path; alias rejection leaves the single
//! owner untouched. The returned columns own the fold.
const std = @import("std");
const core = @import("stwo_core");
const parent = @import("blake3_execution_parent_preparation.zig");
const protocol = @import("blake3_execution_parent_protocol.zig");
const span = @import("span_statement_blake3.zig");
const rebase = @import("air/blake3_parent_rebase.zig");
const join = @import("air/blake3_parent_join.zig");
pub const Fold = struct {
    prepared: parent.Prepared,
    statement: span.SpanStatement,
    pub fn deinit(self: *Fold) void {
        self.prepared.deinit();
        self.* = undefined;
    }
};
pub fn admit(left: *const parent.Context, right: *const parent.Context, statements: [2]span.SpanStatement) !span.SpanStatement {
    for ([_]*const parent.Context{ left, right }, statements) |context, statement| {
        if (context.aggregation != null or context.statement_identity == null or context.span_binding_id == null) return error.InvalidAggregateChild;
        const id = (try span.identity.hash(&try statement.canonicalWords(), .statement)).bytes;
        if (!std.mem.eql(u8, &id, &context.statement_identity.?)) return error.UntrustedAggregateSpan;
        _ = try protocol.contextIdentity(context.*);
    }
    return span.SpanStatement.fold(statements[0], statements[1]);
}
pub fn prepareOwned(a: std.mem.Allocator, left: *parent.Prepared, right: *parent.Prepared, statements: [2]span.SpanStatement) !Fold {
    return prepareImpl(a, left, right, statements, null);
}
pub fn prepareShared(a: std.mem.Allocator, left: *parent.PartitionPrepared, right: *parent.PartitionPrepared, statements: [2]span.SpanStatement, columns: *@import("blake3_native_hash_columns.zig").Owner) !Fold {
    return prepareImpl(a, left, right, statements, columns);
}
fn prepareImpl(a: std.mem.Allocator, left: anytype, right: @TypeOf(left), statements: [2]span.SpanStatement, columns: ?*@import("blake3_native_hash_columns.zig").Owner) !Fold {
    // One owner cannot be both children.
    if (left == right) return error.AliasedAggregateChildren;
    defer left.deinit();
    defer right.deinit();
    const statement = try admit(&left.context, &right.context, statements);
    var left_namespace = try rebase.prepare(a, &left.rows, 1);
    defer left_namespace.deinit();
    var right_namespace = try rebase.prepare(a, &right.rows, try left_namespace.end());
    defer right_namespace.deinit();
    const namespace_ids = [2][32]u8{ try left_namespace.identity(), try right_namespace.identity() };
    var context = left.context;
    context.quad_aggregation = null;
    context.aggregation = .{
        .right_child_key_id = right.context.child_key_id,
        .right_config = right.context.child_config,
        .right_graph_ids = right.context.graph_ids,
        .right_transcript_plan_id = right.context.transcript_plan_id,
        .child_statement_ids = .{ left.context.statement_identity.?, right.context.statement_identity.? },
        .child_span_binding_ids = .{ left.context.span_binding_id.?, right.context.span_binding_id.? },
        .namespace_ids = namespace_ids,
    };
    context.statement_identity = (try span.identity.hash(&try statement.canonicalWords(), .statement)).bytes;
    var binding = core.channel.blake3.Channel{};
    binding.mixU32s(&.{ 0x42334147, 1 });
    const mix = @import("../prover/blake3_execution_protocol.zig").mixDigest;
    mix(&binding, try protocol.contextIdentity(left.context));
    mix(&binding, try protocol.contextIdentity(right.context));
    mix(&binding, context.statement_identity.?);
    for (namespace_ids) |id| mix(&binding, id);
    context.span_binding_id = binding.digestBytes();
    try rebase.apply(&left.rows, &left_namespace, namespace_ids[0]);
    try rebase.apply(&right.rows, &right_namespace, namespace_ids[1]);
    const ranges = [2]join.Range{ .{ .first = left_namespace.first, .end = try left_namespace.end() }, .{ .first = right_namespace.first, .end = try right_namespace.end() } };
    const rows = if (@TypeOf(left.*) == parent.PartitionPrepared)
        try join.joinShared(&left.rows, &right.rows, ranges, columns orelse return error.InvalidAggregateChild)
    else
        try join.joinDraining(a, &left.rows, &right.rows, ranges);
    return .{ .prepared = .{ .rows = rows, .context = context }, .statement = statement };
}
