const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const field_public = @import("recursive_field_node_public_v2.zig");
const subject = @import("recursive_node_artifact_v2.zig");

const recursion = frontend.recursion;

test "recursive node V2 codec binds field public semantics and transport SHA" {
    const job = try fixtureJob();
    const statement = try recursion.span_statement.SpanStatement.emptyLeaf(job, 210);
    const public = try field_public.NodePublicV2.initLeaf(
        try subject.TaskCoordinateV1.init(0, 210),
        try u32Words(statement),
        digest("empty-source"),
    );
    const artifact = try fixtureArtifact(public, fixtureRef(9));
    const encoded = try artifact.encodeCanonical();
    try std.testing.expectEqual(@as(usize, subject.ENCODED_BYTE_COUNT), encoded.len);
    const decoded = try subject.RecursiveNodeArtifactV2.decodeCanonical(&encoded);
    try std.testing.expectEqual(artifact, decoded);
    const reference = try artifact.artifactRef();
    try std.testing.expectEqual(@as(u32, 10), reference.kind);
    try std.testing.expectEqual(@as(u16, 2), reference.schema_version);
    try std.testing.expectEqual(@as(u64, subject.ENCODED_BYTE_COUNT), reference.byte_count);
}

test "recursive node V2 rejects SHA as semantics and every authority drift" {
    const job = try fixtureJob();
    const statement = try recursion.span_statement.SpanStatement.emptyLeaf(job, 210);
    const public = try field_public.NodePublicV2.initLeaf(
        try subject.TaskCoordinateV1.init(0, 210),
        try u32Words(statement),
        digest("empty-source"),
    );
    const canonical = try fixtureArtifact(public, fixtureRef(9));

    var mutation = canonical;
    mutation.field_public_transport_sha256[0] ^= 1;
    try std.testing.expectError(error.InvalidFieldPublicTransport, mutation.validate());
    mutation = canonical;
    mutation.node_public.source_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidFieldNodePublic, mutation.validate());
    mutation = canonical;
    mutation.node_public_abi_sha256[0] ^= 1;
    try std.testing.expectError(error.InvalidFieldPublicTransport, mutation.validate());
    mutation = canonical;
    mutation.proof_shape_identity_sha256[0] ^= 1;
    mutation = try subject.RecursiveNodeArtifactV2.seal(mutation);
    try std.testing.expect(!std.mem.eql(
        u8,
        &mutation.semantic_inputs_identity_sha256,
        &canonical.semantic_inputs_identity_sha256,
    ));
    mutation.production_activation = true;
    try std.testing.expectError(error.UnsupportedFormat, mutation.validate());
}

fn fixtureArtifact(
    public: field_public.NodePublicV2,
    native_ref: subject.ArtifactRefV1,
) !subject.RecursiveNodeArtifactV2 {
    return subject.RecursiveNodeArtifactV2.seal(.{
        .stage_kind = .leaf_wrapper,
        .node_kind = .empty,
        .child_count = 1,
        .coordinate = public.coordinate,
        .node_public = public,
        .campaign_namespace_sha256 = sha("campaign"),
        .circuit_identity_sha256 = sha("circuit"),
        .program_identity_sha256 = sha("program"),
        .profile_identity_sha256 = sha("profile"),
        .pcs_identity_sha256 = sha("pcs"),
        .padding_layout_identity_sha256 = sha("padding"),
        .registry_identity_sha256 = sha("registry"),
        .node_public_abi_sha256 = field_public.abiIdentitySha256(),
        .proof_shape_identity_sha256 = sha("proof-shape"),
        .ordered_children = .{ native_ref, subject.ArtifactRefV1.zero() },
        .proof_ref = fixtureRef(8),
        .preprocessed_root = digest("preprocessed"),
        .semantic_inputs_identity_sha256 = undefined,
        .field_public_transport_sha256 = undefined,
        .content_identity_sha256 = undefined,
    });
}

fn u32Words(
    statement: recursion.span_statement.SpanStatement,
) ![field_public.STATEMENT_WORD_COUNT]u32 {
    const words = try statement.canonicalWords();
    var result: [field_public.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&result, words) |*destination, word| destination.* = word.toU32();
    return result;
}

fn fixtureJob() !recursion.span_statement.JobContext {
    const initial = try recursion.span_statement.MachineState.init(
        0,
        [_]u32{0} ** 32,
        digest("entry-memory"),
        digest("entry-public"),
    );
    const final = try recursion.span_statement.MachineState.init(
        4,
        [_]u32{0} ** 32,
        digest("exit-memory"),
        digest("exit-public"),
    );
    const complete = try recursion.span_statement.CompleteExecution.init(
        recursion.protocol.PROTOCOL_ID_WORDS,
        digest("program"),
        initial,
        final,
        digest("input"),
        digest("output"),
        8,
    );
    return recursion.span_statement.JobContext.init(complete, 210);
}

fn fixtureRef(kind: u32) subject.ArtifactRefV1 {
    return .{
        .kind = kind,
        .format_version = 1,
        .schema_version = 1,
        .byte_count = 17,
        .sha256 = sha("artifact-ref"),
    };
}

fn digest(label: []const u8) recursion.poseidon2_channel.Digest {
    return recursion.poseidon2_channel.hashBytes(label, 0x4658);
}

fn sha(label: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &result, .{});
    return result;
}
