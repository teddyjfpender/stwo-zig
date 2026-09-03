const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const integration = @import("stwo_riscv_cpu_integration");

const adapter = integration.recursive_node_artifact_store_v2;
const artifact = adapter.recursive_node;
const field_public = integration.recursive_field_node_public_v2;
const cas = adapter.cas;

const recursion = frontend.recursion;

test "field recursive store publishes schema2 keys node and cold manifest" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.testing.allocator, &temporary);
    defer std.testing.allocator.free(root);
    var store = try cas.Store.openOrCreate(std.testing.allocator, root, false);
    defer store.deinit();

    const public = try emptyPublic(210, "empty-210");
    const node = try fixtureNode(
        .leaf_wrapper,
        public,
        .{ fixtureRef(8, 1, 37, 0x41), artifact.ArtifactRefV1.zero() },
    );
    const semantic = try node.semanticInputs();
    const secure = adapter.security.ProofSecurityV1.recursiveParentSecure();
    var keys = try adapter.deriveAndPublishStageKeysV2(
        std.testing.allocator,
        &store,
        &semantic,
        &secure,
        executionAuthority(),
    );
    defer keys.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        adapter.EMPTY_WRAPPER_STAGE_SCHEMA_VERSION,
        keys.semantic.fields.stage_schema_version,
    );
    try std.testing.expectEqual(
        semantic.identity_sha256,
        keys.semantic.fields.semantic_options_identity,
    );
    try std.testing.expectEqual(
        try adapter.statementCacheIdentityV2(&semantic),
        keys.semantic.fields.statement_identity,
    );

    const output_ref = try adapter.publishRecursiveNodeV2(&store, &node);
    try std.testing.expectEqual(cas.ArtifactKindV1.recursion_node, output_ref.kind);
    try std.testing.expectEqual(@as(u16, 2), output_ref.schema_version);
    try std.testing.expectEqual(@as(u64, artifact.ENCODED_BYTE_COUNT), output_ref.byte_count);
    const reopened = try adapter.coldOpenRecursiveNodeTransportV2(
        &store,
        output_ref,
    );
    try std.testing.expectEqual(node, reopened);

    const validation = try validationReceipt(&store, 0x61);
    const profile = try profileReceipt(&store, 0x63);
    const manifest = try adapter.createAndPublishStageManifestV2(
        std.testing.allocator,
        &store,
        &node,
        output_ref,
        &keys,
        &.{},
        &.{validation},
        &.{profile},
    );
    try manifest.validate();
    var manifest_blob = try store.openBlob(
        manifest.ref,
        .stage_manifest,
        adapter.STAGE_MANIFEST_SCHEMA_VERSION,
        4096,
    );
    defer manifest_blob.deinit(std.testing.allocator);
    var decoded = try cas.decodeStageManifestAlloc(
        std.testing.allocator,
        manifest_blob.bytes,
    );
    defer decoded.deinit(std.testing.allocator);
    try decoded.value.validateAgainstKeys(
        std.testing.allocator,
        keys.semantic,
        keys.execution,
    );
    try std.testing.expectEqual(
        adapter.EMPTY_WRAPPER_STAGE_SCHEMA_VERSION,
        decoded.value.fields.stage_schema_version,
    );
}

test "field recursive store binds Poseidon semantics and rejects schema1 children" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.testing.allocator, &temporary);
    defer std.testing.allocator.free(root);
    var store = try cas.Store.openOrCreate(std.testing.allocator, root, false);
    defer store.deinit();

    const left_public = try emptyPublic(210, "empty-210");
    const right_public = try emptyPublic(211, "empty-211");
    const parent_public = try field_public.NodePublicV2.initParent(
        &left_public,
        &right_public,
        try artifact.TaskCoordinateV1.init(1, 105),
    );
    const left = fixtureRef(10, 2, artifact.ENCODED_BYTE_COUNT, 0x71);
    const right = fixtureRef(10, 2, artifact.ENCODED_BYTE_COUNT, 0x72);
    const node = try fixtureNode(.fold, parent_public, .{ left, right });
    const secure = adapter.security.ProofSecurityV1.recursiveParentSecure();
    const semantic = try node.semanticInputs();
    var keys = try adapter.deriveAndPublishStageKeysV2(
        std.testing.allocator,
        &store,
        &semantic,
        &secure,
        executionAuthority(),
    );
    defer keys.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        adapter.COMMON_FOLD_STAGE_SCHEMA_VERSION,
        keys.semantic.fields.stage_schema_version,
    );

    var changed_public = parent_public;
    changed_public.source_digest[0] ^= 1;
    changed_public.subtree_digest = field_public.nodeSubtreeDigest(&changed_public);
    changed_public.output_digest = field_public.nodeOutputDigest(&changed_public);
    const changed_node = try fixtureNode(.fold, changed_public, .{ left, right });
    const changed_semantic = try changed_node.semanticInputs();
    var changed_keys = try adapter.deriveAndPublishStageKeysV2(
        std.testing.allocator,
        &store,
        &changed_semantic,
        &secure,
        executionAuthority(),
    );
    defer changed_keys.deinit(std.testing.allocator);
    try std.testing.expect(!std.mem.eql(
        u8,
        &keys.semantic.identity,
        &changed_keys.semantic.identity,
    ));

    var schema1 = left;
    schema1.schema_version = 1;
    const invalid = try fixtureNode(.fold, parent_public, .{ schema1, right });
    const invalid_semantic = try invalid.semanticInputs();
    try std.testing.expectError(
        error.InvalidRecursiveChildReference,
        adapter.deriveAndPublishStageKeysV2(
            std.testing.allocator,
            &store,
            &invalid_semantic,
            &secure,
            executionAuthority(),
        ),
    );
}

fn emptyPublic(index: u32, label: []const u8) !field_public.NodePublicV2 {
    const job = try fixtureJob();
    const statement = try recursion.span_statement.SpanStatement.emptyLeaf(job, index);
    const words = try statement.canonicalWords();
    var canonical: [field_public.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&canonical, words) |*destination, word| destination.* = word.toU32();
    return field_public.NodePublicV2.initLeaf(
        try artifact.TaskCoordinateV1.init(0, index),
        canonical,
        recursion.poseidon2_channel.hashBytes(label, 0x4658),
    );
}

fn fixtureNode(
    stage: artifact.StageKindV1,
    public: field_public.NodePublicV2,
    children: [artifact.MAX_CHILD_COUNT]artifact.ArtifactRefV1,
) !artifact.RecursiveNodeArtifactV2 {
    return artifact.RecursiveNodeArtifactV2.seal(.{
        .stage_kind = stage,
        .node_kind = public.node_kind,
        .child_count = if (stage == .leaf_wrapper) 1 else 2,
        .coordinate = public.coordinate,
        .node_public = public,
        .campaign_namespace_sha256 = digest(0x01),
        .circuit_identity_sha256 = digest(0x02),
        .program_identity_sha256 = digest(0x03),
        .profile_identity_sha256 = digest(0x04),
        .pcs_identity_sha256 = digest(0x05),
        .padding_layout_identity_sha256 = digest(0x06),
        .registry_identity_sha256 = digest(0x07),
        .node_public_abi_sha256 = field_public.abiIdentitySha256(),
        .proof_shape_identity_sha256 = digest(0x08),
        .ordered_children = children,
        .proof_ref = fixtureRef(8, 1, 101, 0x42),
        .preprocessed_root = [_]u32{11} ** 8,
        .semantic_inputs_identity_sha256 = undefined,
        .field_public_transport_sha256 = undefined,
        .content_identity_sha256 = undefined,
    });
}

fn fixtureJob() !recursion.span_statement.JobContext {
    const initial = try recursion.span_statement.MachineState.init(
        0,
        [_]u32{0} ** 32,
        [_]u32{1} ** 8,
        [_]u32{2} ** 8,
    );
    const final = try recursion.span_statement.MachineState.init(
        4,
        [_]u32{0} ** 32,
        [_]u32{3} ** 8,
        [_]u32{4} ** 8,
    );
    const complete = try recursion.span_statement.CompleteExecution.init(
        recursion.protocol.PROTOCOL_ID_WORDS,
        [_]u32{5} ** 8,
        initial,
        final,
        [_]u32{6} ** 8,
        [_]u32{7} ** 8,
        8,
    );
    return recursion.span_statement.JobContext.init(complete, 210);
}

fn executionAuthority() adapter.ExecutionAuthorityV1 {
    return .{
        .producer_identity = digest(0x51),
        .verifier_identity = digest(0x52),
        .source_identity = digest(0x53),
        .build_identity = digest(0x54),
        .executable_identity = digest(0x55),
        .toolchain_identity = digest(0x56),
        .backend_identity = digest(0x57),
        .optimization_identity = digest(0x58),
        .worker_policy_identity = digest(0x59),
        .memory_policy_identity = digest(0x5a),
        .retention_policy_identity = digest(0x5b),
        .timeout_policy_identity = digest(0x5c),
    };
}

fn validationReceipt(
    store: *cas.Store,
    seed: u8,
) !cas.ValidationReceiptRefV1 {
    return .{
        .validator_kind = 1,
        .validator_schema_version = 1,
        .authority_identity = digest(seed),
        .validator_identity = digest(seed + 1),
        .blob = try store.putBytes(.validation_receipt, 1, &.{seed}),
    };
}

fn profileReceipt(store: *cas.Store, seed: u8) !cas.ProfileReceiptRefV1 {
    return .{
        .profile_kind = 1,
        .profile_schema_version = 1,
        .profile_identity = digest(seed),
        .issuer_identity = digest(seed + 1),
        .blob = try store.putBytes(.profile_receipt, 1, &.{seed}),
    };
}

fn fixtureRef(
    kind: u32,
    schema_version: u16,
    byte_count: u64,
    seed: u8,
) artifact.ArtifactRefV1 {
    return .{
        .kind = kind,
        .format_version = 1,
        .schema_version = schema_version,
        .byte_count = byte_count,
        .sha256 = digest(seed),
    };
}

fn digest(seed: u8) [32]u8 {
    return [_]u8{seed} ** 32;
}

fn rootPath(
    allocator: std.mem.Allocator,
    temporary: *std.testing.TmpDir,
) ![]u8 {
    const parent = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(parent);
    return std.fs.path.join(allocator, &.{ parent, "artifact-store" });
}
