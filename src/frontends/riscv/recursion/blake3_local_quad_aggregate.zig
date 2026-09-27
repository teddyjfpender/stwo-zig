//! Versioned intermediate parent over four genuine child STARK verifiers.
//! Every child contributes complete verifier rows; a digest alone is never a
//! substitute for its proof equations. Existing binary and exact-root keys
//! retain their v3 encoding when this optional subprotocol is absent.
const std = @import("std");
const core = @import("stwo_core");
const spans = @import("span_statement_blake3.zig");
const parent = @import("blake3_execution_parent_preparation.zig");
const protocol = @import("blake3_execution_parent_protocol.zig");
const proof = @import("blake3_execution_parent_proof.zig");
const tree = @import("blake3_execution_tree.zig");
const rebase = @import("air/blake3_parent_rebase.zig");
const join = @import("air/blake3_parent_join.zig");
const mixDigest = @import("../prover/blake3_execution_protocol.zig").mixDigest;

pub const VERSION: u32 = 1;
pub const Child = struct { statement: spans.SpanStatement, admission: protocol.Admission };
pub const Fold = struct {
    prepared: parent.Prepared,
    statement: spans.SpanStatement,
    roster_digest: [32]u8,
    pub fn deinit(self: *Fold) void {
        self.prepared.deinit();
        self.* = undefined;
    }
};

pub fn statement(children: [4]Child) !spans.SpanStatement {
    for (children) |child| {
        try child.statement.validate();
        try child.admission.validate();
        switch (child.statement.body) {
            .executed => {},
            .empty => return error.InvalidLocalQuadChild,
        }
        if (child.admission.key.context.statement_identity == null or
            child.admission.key.context.span_binding_id == null)
            return error.InvalidLocalQuadChild;
    }
    const height = children[0].statement.slots.height;
    for (children[1..]) |child| if (child.statement.slots.height != height)
        return error.InvalidLocalQuadHeight;
    const left = try spans.SpanStatement.fold(children[0].statement, children[1].statement);
    const right = try spans.SpanStatement.fold(children[2].statement, children[3].statement);
    return spans.SpanStatement.fold(left, right);
}

pub fn rosterDigest(children: [4]Child) ![32]u8 {
    _ = try statement(children);
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update("stwo-zig/blake3-local-quad-roster/v1\x00");
    var version: [4]u8 = undefined;
    std.mem.writeInt(u32, &version, VERSION, .little);
    hash.update(&version);
    for (children) |child| {
        const words = try child.statement.canonicalWords();
        for (words) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word.toU32(), .little);
            hash.update(&bytes);
        }
        hash.update(&child.admission.expected_id);
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

fn bindingDigest(children: [4]Child, statement_id: [32]u8, roster: [32]u8, namespaces: [4][32]u8) ![32]u8 {
    var binding = core.channel.blake3.Channel{};
    binding.mixU32s(&.{ 0x4233_5134, VERSION, 4 });
    mixDigest(&binding, roster);
    mixDigest(&binding, statement_id);
    for (children, namespaces, 0..) |child, namespace_id, index| {
        binding.mixU32s(&.{@intCast(index)});
        mixDigest(&binding, try protocol.contextIdentity(child.admission.key.context));
        mixDigest(&binding, namespace_id);
    }
    return binding.digestBytes();
}

pub fn prepare(a: std.mem.Allocator, nodes: [4]*const tree.Node, capacity: u32, expected_profile: protocol.Profile) !Fold {
    var children: [4]Child = undefined;
    for (nodes, &children) |node, *child| {
        try node.validate();
        if (node.admission.key.profile != expected_profile) return error.LocalQuadSecurityMismatch;
        child.* = .{ .statement = node.statement, .admission = node.admission };
    }
    const combined = try statement(children);
    const roster = try rosterDigest(children);
    const statement_id = (try spans.identity.hash(&try combined.canonicalWords(), .statement)).bytes;
    var next_namespace: u32 = 1;
    var namespaces: [4][32]u8 = undefined;
    var accumulated: ?parent.Prepared = null;
    errdefer if (accumulated) |*owned| owned.deinit();
    for (nodes, 0..) |node, index| {
        var child = try parent.prepare(a, &node.admission, &node.verified, node.admission.expected_id, capacity);
        var moved = false;
        defer if (!moved) child.deinit();
        var namespace = try rebase.prepare(a, &child.rows, next_namespace);
        defer namespace.deinit();
        next_namespace = try namespace.end();
        namespaces[index] = try namespace.identity();
        try rebase.apply(&child.rows, &namespace, namespaces[index]);
        if (accumulated) |*previous| {
            const joined = try join.joinDraining(a, &previous.rows, &child.rows, .{
                .{ .first = 1, .end = namespace.first },
                .{ .first = namespace.first, .end = next_namespace },
            });
            previous.rows.deinit();
            child.rows.deinit();
            previous.rows = joined;
            moved = true;
        } else {
            accumulated = child;
            moved = true;
        }
    }
    var result = accumulated.?;
    accumulated = null;
    errdefer result.deinit();
    const binding = try bindingDigest(children, statement_id, roster, namespaces);
    var quad = parent.QuadAggregation{
        .roster_digest = roster,
        .binding_digest = binding,
        .child_key_ids = undefined,
        .child_statement_ids = undefined,
        .child_span_binding_ids = undefined,
        .namespace_ids = namespaces,
    };
    for (children, 0..) |child, index| {
        quad.child_key_ids[index] = child.admission.expected_id;
        quad.child_statement_ids[index] = (try spans.identity.hash(&try child.statement.canonicalWords(), .statement)).bytes;
        quad.child_span_binding_ids[index] = child.admission.key.context.span_binding_id.?;
    }
    result.context.statement_identity = statement_id;
    result.context.span_binding_id = binding;
    result.context.aggregation = null;
    result.context.exact_aggregation = null;
    result.context.quad_aggregation = quad;
    _ = try protocol.contextIdentity(result.context);
    return .{ .prepared = result, .statement = combined, .roster_digest = roster };
}

/// Fresh-verifies the quartet proof under an independently supplied admission
/// and rechecks all four child edges before returning its admitted node.
pub fn verifyBytes(a: std.mem.Allocator, bytes: []const u8, admission: protocol.Admission, expected_key_id: [32]u8, children: [4]Child) !tree.Node {
    try admission.validate();
    if (!std.mem.eql(u8, &admission.expected_id, &expected_key_id)) return error.UntrustedBlake3ParentKey;
    const combined = try statement(children);
    const roster = try rosterDigest(children);
    const context = admission.key.context;
    const quad = context.quad_aggregation orelse return error.MissingLocalQuadBinding;
    if (context.aggregation != null or context.exact_aggregation != null or
        context.statement_identity == null or context.span_binding_id == null or
        !std.mem.eql(u8, &quad.roster_digest, &roster))
        return error.UntrustedLocalQuadBinding;
    const statement_id = (try spans.identity.hash(&try combined.canonicalWords(), .statement)).bytes;
    if (!std.mem.eql(u8, &context.statement_identity.?, &statement_id)) return error.UntrustedLocalQuadStatement;
    for (children, 0..) |child, index| {
        const child_statement_id = (try spans.identity.hash(&try child.statement.canonicalWords(), .statement)).bytes;
        if (child.admission.key.profile != admission.key.profile or
            !std.mem.eql(u8, &quad.child_key_ids[index], &child.admission.expected_id) or
            !std.mem.eql(u8, &quad.child_statement_ids[index], &child_statement_id) or
            !std.mem.eql(u8, &quad.child_span_binding_ids[index], &child.admission.key.context.span_binding_id.?))
            return error.UntrustedLocalQuadChild;
    }
    const binding = try bindingDigest(children, statement_id, roster, quad.namespace_ids);
    if (!std.mem.eql(u8, &quad.binding_digest, &binding) or
        !std.mem.eql(u8, &context.span_binding_id.?, &binding))
        return error.UntrustedLocalQuadBinding;
    var artifact = try proof.codec.decode(a, bytes, &admission);
    var node = try tree.Node.verifyOwned(&artifact, admission, expected_key_id, combined);
    errdefer node.deinit();
    try node.validate();
    return node;
}
