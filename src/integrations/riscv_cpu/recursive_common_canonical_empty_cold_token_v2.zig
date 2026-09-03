//! Canonical-empty projection into the generic process-local token wire.
//! Generic parameters avoid a dependency cycle with the cold-proof owner.

const std = @import("std");

const process_validation =
    @import("recursive_process_local_validation_token_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Error = error{
    CanonicalEmptyColdTokenMismatch,
};

pub fn validateConstructed(
    value: anytype,
    cohort: anytype,
    replay: anytype,
) !void {
    if (value.fresh.capture.commitments.len == 0)
        return error.CanonicalEmptyColdTokenMismatch;
    const expected_session = try cohort.session();
    try value.artifact_value.validateCustody();
    try value.artifact_value.statement.validateAgainstSession(&value.session);
    try value.query_authority.validateAgainst(replay, &value.fresh);
    if (!std.meta.eql(value.session, expected_session) or
        !std.meta.eql(value.fresh.statement, value.artifact_value.statement) or
        !std.meta.eql(value.claims, replay.claims) or
        !std.mem.eql(
            u8,
            &value.composition_capture.session_identity_sha256,
            &value.session.identity_sha256,
        ) or !std.mem.eql(
        u8,
        &value.composition_capture.statement_identity_sha256,
        &value.fresh.statement.identity_sha256,
    ) or !std.mem.eql(
        u8,
        &value.composition_capture.claims_sha256,
        &replay.claims.seal,
    ) or !std.meta.eql(
        value.geometry_value.preprocessed_root,
        value.fresh.capture.commitments[0],
    )) return error.CanonicalEmptyColdTokenMismatch;
}

pub fn snapshot(value: anytype) !process_validation.SnapshotV1 {
    if (value.artifact_value.proof_bytes.len == 0 or
        value.fresh.capture.commitments.len == 0 or
        value.fresh.capture.queries.raw.len == 0 or
        value.composition_capture.circuit.nodes.len == 0 or
        value.composition_capture.bindings.len == 0 or
        value.composition_capture.input_values.len == 0 or
        value.composition_capture.node_values.len == 0)
    {
        return error.CanonicalEmptyColdTokenMismatch;
    }
    var source_identity: [32]u8 = undefined;
    Sha256.hash(&value.source_bytes, &source_identity, .{});
    const node_public_bytes = try value.node_public.encodeCanonical();
    var node_public_identity: [32]u8 = undefined;
    Sha256.hash(&node_public_bytes, &node_public_identity, .{});
    return .{
        .authority_kind_sha256 = validationAuthorityKind(),
        .source_content_sha256 = source_identity,
        .session_identity_sha256 = value.session.identity_sha256,
        .retained_statement_identity_sha256 = value.artifact_value.statement.identity_sha256,
        .fresh_statement_identity_sha256 = value.fresh.statement.identity_sha256,
        .capture_identity_sha256 = captureIdTransportIdentity(
            value.fresh.statement.capture_id,
        ),
        .claims_identity_sha256 = value.claims.seal,
        .query_identity_sha256 = querySnapshotIdentity(
            &value.query_authority,
        ),
        .geometry_identity_sha256 = value.geometry_value.authority_identity_sha256,
        .node_public_identity_sha256 = node_public_identity,
        .graph_capture_identity_sha256 = value.composition_capture.identity_sha256,
        .graph_layout_identity_sha256 = value.composition_capture.layout.identity,
        .graph_circuit_identity_sha256 = value.composition_capture.circuit.identity_digest,
        .owner_anchor_ptr = @intFromPtr(value.validation),
        .proof_ptr = @intFromPtr(value.artifact_value.proof_bytes.ptr),
        .proof_len = value.artifact_value.proof_bytes.len,
        .commitment_ptr = @intFromPtr(value.fresh.capture.commitments.ptr),
        .commitment_len = value.fresh.capture.commitments.len,
        .query_ptr = @intFromPtr(value.fresh.capture.queries.raw.ptr),
        .query_len = value.fresh.capture.queries.raw.len,
        .graph_node_ptr = @intFromPtr(
            value.composition_capture.circuit.nodes.ptr,
        ),
        .graph_node_len = value.composition_capture.circuit.nodes.len,
        .graph_binding_ptr = @intFromPtr(
            value.composition_capture.bindings.ptr,
        ),
        .graph_binding_len = value.composition_capture.bindings.len,
        .graph_input_ptr = @intFromPtr(
            value.composition_capture.input_values.ptr,
        ),
        .graph_input_len = value.composition_capture.input_values.len,
        .graph_output_ptr = @intFromPtr(
            value.composition_capture.node_values.ptr,
        ),
        .graph_output_len = value.composition_capture.node_values.len,
    };
}

fn validationAuthorityKind() [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(
        "stwo-zig/canonical-empty-validated-cold-proof/v2\x00",
        &result,
        .{},
    );
    return result;
}

/// SHA transport identity of the field-native capture digest. Each canonical
/// u32 word is encoded explicitly little-endian; this is not proof authority.
fn captureIdTransportIdentity(words: anytype) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/secure-parent-capture-id-transport/v1\x00");
    for (words) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn querySnapshotIdentity(value: anytype) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/canonical-empty-query-snapshot/v2\x00");
    for (value.query_words) |word| hashInt(&hash, u32, word.toU32());
    hashInt(&hash, u32, value.query_log_size);
    hash.update(std.mem.asBytes(&value.final_transcript_digest));
    hashInt(&hash, u32, value.final_transcript_draw_count);
    hash.update(&value.query_words_identity_sha256);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
