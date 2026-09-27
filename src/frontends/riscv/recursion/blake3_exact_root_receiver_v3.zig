//! Receiver-side custody for a block-v3 exact forest. Native and execution
//! sidecar proof verification precede these calls; no receipt may be supplied
//! directly by an untrusted public complete-block API.
const std = @import("std");
const core = @import("stwo_core");
const span = @import("span_statement_blake3.zig");
const parent = @import("blake3_execution_parent_protocol.zig");
const tree = @import("blake3_execution_tree.zig");
const codec = @import("blake3_native_parent_codec.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const exact = @import("blake3_exact_root_aggregate.zig");
const forest = @import("blake3_exact_forest_protocol.zig");
const v3 = @import("blake3_block_execution_span_v3.zig");
const public = @import("../air/public_data.zig");
const seal_mod = @import("../prover/block_memory_source_seal_v2.zig");
const sidecar = @import("../prover/block_execution_sidecar_batch_v2.zig");

pub const Descriptor = struct {
    statement: span.SpanStatement,
    admission: parent.Admission,
};

/// The caller must have obtained `receipt` from fresh native+sidecar proof
/// verification under the same sealed first-round roster. This function
/// independently verifies the recursive leaf artifact and binds its key to
/// the sidecar receipt, native key, and v3 statement before retaining metadata.
pub fn verifyLeafBytes(
    a: std.mem.Allocator,
    bytes: []const u8,
    admission: parent.Admission,
    expected_key_id: [32]u8,
    statement: span.SpanStatement,
    data: *const public.Blake3PublicData,
    config: core.pcs.PcsConfig,
    seal: seal_mod.SourceSeal,
    native_key_id: [32]u8,
    native_roots: [2][32]u8,
    witness_root: [32]u8,
    receipt: *const sidecar.VerifiedExecutionReceipt,
) !Descriptor {
    try admission.validate();
    if (!std.mem.eql(u8, &admission.expected_id, &expected_key_id))
        return error.UntrustedBlake3ParentKey;
    if (!std.meta.eql(admission.key.config, config))
        return error.ExecutionParentSecurityMismatch;
    try v3.validate(
        statement,
        data,
        config,
        seal,
        native_key_id,
        native_roots,
        witness_root,
        receipt,
    );
    const context = admission.key.context;
    const statement_id = (try span.identity.hash(
        &try statement.canonicalWords(),
        .statement,
    )).bytes;
    if (context.statement_identity == null or context.span_binding_id == null or
        context.aggregation != null or context.exact_aggregation != null or
        !std.meta.eql(context.child_config, config) or
        !std.mem.eql(u8, &context.child_key_id, &native_key_id) or
        !std.mem.eql(u8, &context.statement_identity.?, &statement_id) or
        !std.mem.eql(u8, &context.span_binding_id.?, &try v3.bindingIdentity(statement, native_key_id, receipt)))
        return error.UnlinkedBlockV3Leaf;
    return verifyOne(a, bytes, admission, statement);
}

/// Checks both semantic fold and key-level child IDs before opening the
/// recursive parent proof. Disjoint namespaces remain pinned by its key.
pub fn verifyDyadicBytes(
    a: std.mem.Allocator,
    bytes: []const u8,
    admission: parent.Admission,
    expected_key_id: [32]u8,
    left: Descriptor,
    right: Descriptor,
) !Descriptor {
    try admission.validate();
    if (!std.mem.eql(u8, &admission.expected_id, &expected_key_id))
        return error.UntrustedBlake3ParentKey;
    try left.admission.validate();
    try right.admission.validate();
    if (admission.key.profile != left.admission.key.profile or
        admission.key.profile != right.admission.key.profile)
        return error.ExecutionParentSecurityMismatch;
    const statement = try span.SpanStatement.fold(left.statement, right.statement);
    const context = admission.key.context;
    const aggregate = context.aggregation orelse return error.UnlinkedDyadicParent;
    if (context.statement_identity == null or context.span_binding_id == null or
        left.admission.key.context.span_binding_id == null or
        right.admission.key.context.span_binding_id == null)
        return error.UnlinkedDyadicParent;
    const left_id = (try span.identity.hash(&try left.statement.canonicalWords(), .statement)).bytes;
    const right_id = (try span.identity.hash(&try right.statement.canonicalWords(), .statement)).bytes;
    const statement_id = (try span.identity.hash(&try statement.canonicalWords(), .statement)).bytes;
    if (context.exact_aggregation != null or
        !std.mem.eql(u8, &context.child_key_id, &left.admission.expected_id) or
        !std.mem.eql(u8, &aggregate.right_child_key_id, &right.admission.expected_id) or
        !std.meta.eql(context.child_config, left.admission.key.config) or
        !std.meta.eql(aggregate.right_config, right.admission.key.config) or
        !std.mem.eql(u8, &aggregate.child_statement_ids[0], &left_id) or
        !std.mem.eql(u8, &aggregate.child_statement_ids[1], &right_id) or
        !std.mem.eql(u8, &aggregate.child_span_binding_ids[0], &left.admission.key.context.span_binding_id.?) or
        !std.mem.eql(u8, &aggregate.child_span_binding_ids[1], &right.admission.key.context.span_binding_id.?) or
        !std.mem.eql(u8, &context.statement_identity.?, &statement_id))
        return error.UnlinkedDyadicParent;
    return verifyOne(a, bytes, admission, statement);
}

/// Derives the only accepted roster digest from freshly verified dyadic root
/// descriptors. A public complete-block receiver must obtain descriptors via
/// `verifyLeafBytes`/`verifyDyadicBytes`, never from serialized metadata alone.
pub fn verifiedForestDigest(job: span.JobContext, roots: []const Descriptor) ![32]u8 {
    if (roots.len == 0 or roots.len > span.MAX_SLOT_HEIGHT + 1)
        return error.InvalidExactForestNodeCount;
    var entries: [span.MAX_SLOT_HEIGHT + 1]forest.Entry = undefined;
    for (roots, 0..) |root, i| {
        try root.admission.validate();
        entries[i] = .{
            .statement = root.statement,
            .expected_key_id = root.admission.expected_id,
        };
    }
    return forest.digest(job, entries[0..roots.len]);
}

/// Final one-root proof after the independently pinned `admission` has been
/// checked against complete-block policy. `roots` came from fresh child proof
/// verification; their digest is never accepted from the bundle itself.
pub fn verifyExactBytes(
    a: std.mem.Allocator,
    bytes: []const u8,
    admission: parent.Admission,
    expected_key_id: [32]u8,
    job: span.JobContext,
    roots: []const Descriptor,
) !tree.Node {
    if (!std.mem.eql(u8, &admission.expected_id, &expected_key_id))
        return error.UntrustedBlake3ParentKey;
    return exact.verifyBytes(a, bytes, admission, job, try verifiedForestDigest(job, roots));
}

/// Explicit diagnostic security path for focused fixtures only.
pub fn verifyDiagnosticExactBytes(
    a: std.mem.Allocator,
    bytes: []const u8,
    admission: parent.Admission,
    expected_key_id: [32]u8,
    job: span.JobContext,
    roots: []const Descriptor,
) !tree.Node {
    if (!std.mem.eql(u8, &admission.expected_id, &expected_key_id))
        return error.UntrustedBlake3ParentKey;
    return exact.verifyDiagnosticBytes(a, bytes, admission, job, try verifiedForestDigest(job, roots));
}

fn verifyOne(
    a: std.mem.Allocator,
    bytes: []const u8,
    admission: parent.Admission,
    statement: span.SpanStatement,
) !Descriptor {
    var received: artifact.Owned = try codec.decode(a, bytes, admission);
    var node = try tree.Node.verifyOwned(
        &received,
        admission,
        admission.expected_id,
        statement,
    );
    defer node.deinit();
    try node.validate();
    return .{ .statement = statement, .admission = admission };
}
