//! Owning verified tree nodes. Received artifacts require an independently
//! admitted key; neither the artifact nor its Span may select verification keys.
const std = @import("std");
const protocol = @import("blake3_execution_parent_protocol.zig");
const verifier = @import("blake3_native_parent_verifier.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const parent = @import("blake3_execution_parent_preparation.zig");
const aggregate = @import("blake3_execution_aggregate.zig");
const spans = @import("span_statement_blake3.zig");
pub const Node = struct {
    admission: protocol.Admission,
    statement: spans.SpanStatement,
    verified: verifier.Verified,
    /// Consumes the artifact on every path. Output owns the capture and borrows
    /// neither the artifact nor the caller's admission/statement storage.
    pub fn verifyOwned(received: *artifact.Owned, admission: protocol.Admission, expected: [32]u8, statement: spans.SpanStatement) !Node {
        defer received.deinit();
        try admitStatement(&admission, expected, statement);
        return .{ .admission = admission, .statement = statement, .verified = try verifier.verify(received, &admission) };
    }
    pub fn validate(self: *const Node) !void {
        try admitStatement(&self.admission, self.admission.expected_id, self.statement);
        try self.verified.validate(&self.admission, self.admission.expected_id);
    }
    pub fn root(self: *const Node) !spans.RootStatement {
        try self.validate();
        return spans.RootStatement.init(self.statement);
    }
    pub fn deinit(self: *Node) void {
        self.verified.deinit();
        self.* = undefined;
    }
};
fn admitStatement(admission: *const protocol.Admission, expected: [32]u8, statement: spans.SpanStatement) !void {
    try admission.validate();
    if (!std.mem.eql(u8, &admission.expected_id, &expected)) return error.UntrustedBlake3ParentKey;
    const context = admission.key.context;
    if (context.statement_identity == null or context.span_binding_id == null) return error.MissingTreeSpan;
    const id = (try spans.identity.hash(&try statement.canonicalWords(), .statement)).bytes;
    if (!std.mem.eql(u8, &id, &context.statement_identity.?)) return error.UntrustedTreeSpan;
}
/// Borrows both nodes on every path. At most two child preparations and their
/// direct joined columns are live; no earlier tree witnesses are retained.
/// The result still requires proving under a caller-admitted parent key.
pub fn preparePair(a: std.mem.Allocator, left: *const Node, right: *const Node, capacity: u32) !aggregate.Fold {
    if (left == right) return error.AliasedAggregateChildren;
    try left.validate();
    try right.validate();
    // Reject unrelated jobs, gaps and wrong levels before allocating witnesses.
    _ = try spans.SpanStatement.fold(left.statement, right.statement);
    var l = try parent.prepare(a, &left.admission, &left.verified, left.admission.expected_id, capacity);
    var l_alive = true;
    defer if (l_alive) l.deinit();
    var r = try parent.prepare(a, &right.admission, &right.verified, right.admission.expected_id, capacity);
    // prepareOwned takes both distinct owners even when it returns an error.
    l_alive = false;
    return aggregate.prepareOwned(a, &l, &r, .{ left.statement, right.statement });
}
