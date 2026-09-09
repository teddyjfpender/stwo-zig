const std = @import("std");
const integration = @import("stwo_riscv_cpu_integration");

const adapter = integration.recursive_node_artifact_store_v1;
const artifact = adapter.recursive_node;
const cas = adapter.cas;
const security = adapter.security;

const CHILD_REF_OFFSET: usize = 8 + artifact.TASK_COORDINATE_BYTE_COUNT +
    artifact.NODE_PUBLIC_BYTE_COUNT + 10 * 32;

test "recursive artifact store binds Lane C refs to Zig key and manifest goldens" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.testing.allocator, &temporary);
    defer std.testing.allocator.free(root);
    var store = try cas.Store.openOrCreate(std.testing.allocator, root, false);
    defer store.deinit();

    const leaf = try fixtureNode(
        .leaf_wrapper,
        try artifact.TaskCoordinateV1.init(0, 0),
        .{ fixtureRef(8, 1, 17, 0x41), artifact.ArtifactRefV1.zero() },
    );
    const semantic = try leaf.semanticInputs();
    const shared_direct = try adapter.toSharedRef(semantic.ordered_children[0]);
    const direct_bytes = try shared_direct.canonicalBytes();
    const direct_golden = [_]u8{
        0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    } ++ [_]u8{0x41} ** 32;
    try std.testing.expectEqualSlices(u8, &direct_golden, &direct_bytes);
    try std.testing.expectEqualDeep(
        semantic.ordered_children[0],
        try adapter.fromSharedRef(shared_direct),
    );
    const encoded_leaf = try leaf.encodeCanonical();
    try std.testing.expectEqualSlices(
        u8,
        &direct_bytes,
        encoded_leaf[CHILD_REF_OFFSET..][0..cas.BlobRefV1.canonical_size],
    );

    const wrapper_security = security.ProofSecurityV1.recursiveParentSecure();
    var keys = try adapter.deriveAndPublishStageKeysV1(
        std.testing.allocator,
        &store,
        &semantic,
        &wrapper_security,
        executionAuthority(),
    );
    defer keys.deinit(std.testing.allocator);
    try keys.validate(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 492), keys.published.semantic_ref.byte_count);
    try std.testing.expectEqual(
        @as(u64, cas.types.execution_canonical_size),
        keys.published.execution_ref.byte_count,
    );
    try std.testing.expectEqual(
        try hexDigest("aa48653dd587794e25afaa44fb7e0ac9f51b399cc0d1330965208d95daf88124"),
        keys.semantic.identity,
    );
    try std.testing.expectEqual(
        try hexDigest("799194ccfdfd41894be1ff215de9531783796ebe13c1404c1c656d232263d19f"),
        keys.execution.identity,
    );

    const output_ref = try adapter.publishRecursiveNodeV1(&store, &leaf);
    try std.testing.expectEqual(cas.ArtifactKindV1.recursion_node, output_ref.kind);
    try std.testing.expectEqual(
        @as(u64, artifact.ENCODED_BYTE_COUNT),
        output_ref.byte_count,
    );
    const validation = try validationReceipt(&store, 0x61, 1);
    const profile = try profileReceipt(&store, 0x63);
    const published_manifest = try adapter.createAndPublishStageManifestV1(
        std.testing.allocator,
        &store,
        &leaf,
        output_ref,
        &keys,
        &.{},
        &.{validation},
        &.{profile},
    );
    try published_manifest.validate();
    try std.testing.expectEqual(@as(u64, 514), published_manifest.ref.byte_count);
    try std.testing.expectEqual(
        try hexDigest("e2e1b92d8f7a86b175f3b322322c78250831e4d66322eb108786f5bcc0b02832"),
        published_manifest.identity,
    );
    var manifest_blob = try store.openBlob(
        published_manifest.ref,
        .stage_manifest,
        adapter.STAGE_MANIFEST_SCHEMA_VERSION,
        4096,
    );
    defer manifest_blob.deinit(std.testing.allocator);
    var reopened_manifest = try cas.decodeStageManifestAlloc(
        std.testing.allocator,
        manifest_blob.bytes,
    );
    defer reopened_manifest.deinit(std.testing.allocator);
    try reopened_manifest.value.validateAgainstKeys(
        std.testing.allocator,
        keys.semantic,
        keys.execution,
    );
    try std.testing.expectEqual(@as(usize, 1), reopened_manifest.outputs.len);
    try std.testing.expectEqual(cas.ArtifactKindV1.recursion_node, reopened_manifest.outputs[0].kind);

    const empty_leaf = try fixtureNode(
        .leaf_wrapper,
        try artifact.TaskCoordinateV1.init(0, artifact.REAL_LEAF_COUNT),
        .{ fixtureRef(8, 1, 17, 0x45), artifact.ArtifactRefV1.zero() },
    );
    try std.testing.expectEqual(artifact.NodeKindV1.empty, empty_leaf.node_kind);
    const empty_semantic = try empty_leaf.semanticInputs();
    var empty_keys = try adapter.deriveAndPublishStageKeysV1(
        std.testing.allocator,
        &store,
        &empty_semantic,
        &wrapper_security,
        executionAuthority(),
    );
    defer empty_keys.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        wrapper_security.identity,
        keys.semantic.fields.security_identity,
    );
    try std.testing.expectEqual(
        wrapper_security.identity,
        empty_keys.semantic.fields.security_identity,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &keys.semantic.fields.semantic_options_identity,
        &empty_keys.semantic.fields.semantic_options_identity,
    ));
    try std.testing.expect(!std.meta.eql(
        keys.ordered_inputs[0],
        empty_keys.ordered_inputs[0],
    ));
    const native_leaf_security = security.ProofSecurityV1
        .ethereumSegmentV3Poseidon2();
    try std.testing.expectError(
        error.InvalidRecursiveSecurity,
        adapter.deriveAndPublishStageKeysV1(
            std.testing.allocator,
            &store,
            &semantic,
            &native_leaf_security,
            executionAuthority(),
        ),
    );
    try std.testing.expectError(
        error.InvalidRecursiveSecurity,
        adapter.deriveAndPublishStageKeysV1(
            std.testing.allocator,
            &store,
            &empty_semantic,
            &native_leaf_security,
            executionAuthority(),
        ),
    );
}

test "recursive artifact store rejects child kind schema size security and binds order" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.testing.allocator, &temporary);
    defer std.testing.allocator.free(root);
    var store = try cas.Store.openOrCreate(std.testing.allocator, root, false);
    defer store.deinit();

    const left = fixtureRef(10, 1, artifact.ENCODED_BYTE_COUNT, 0x71);
    const right = fixtureRef(10, 1, artifact.ENCODED_BYTE_COUNT, 0x72);
    const fold = try fixtureNode(
        .fold,
        try artifact.TaskCoordinateV1.init(1, 0),
        .{ left, right },
    );
    const fold_semantic = try fold.semanticInputs();
    const parent_security = security.ProofSecurityV1.recursiveParentSecure();
    var keys = try adapter.deriveAndPublishStageKeysV1(
        std.testing.allocator,
        &store,
        &fold_semantic,
        &parent_security,
        executionAuthority(),
    );
    defer keys.deinit(std.testing.allocator);

    const reversed = try fixtureNode(
        .fold,
        try artifact.TaskCoordinateV1.init(1, 0),
        .{ right, left },
    );
    const reversed_semantic = try reversed.semanticInputs();
    var reversed_keys = try adapter.deriveAndPublishStageKeysV1(
        std.testing.allocator,
        &store,
        &reversed_semantic,
        &parent_security,
        executionAuthority(),
    );
    defer reversed_keys.deinit(std.testing.allocator);
    try std.testing.expect(!std.mem.eql(
        u8,
        &keys.semantic.identity,
        &reversed_keys.semantic.identity,
    ));

    var wrong_kind = left;
    wrong_kind.kind = 8;
    try expectChildMutation(&store, wrong_kind, right, &parent_security);
    var wrong_schema = left;
    wrong_schema.schema_version = 2;
    try expectChildMutation(&store, wrong_schema, right, &parent_security);
    var wrong_size = left;
    wrong_size.byte_count = artifact.ENCODED_BYTE_COUNT - 1;
    try expectChildMutation(&store, wrong_size, right, &parent_security);

    const native_leaf_security = security.ProofSecurityV1
        .ethereumSegmentV3Poseidon2();
    try std.testing.expectError(
        error.InvalidRecursiveSecurity,
        adapter.deriveAndPublishStageKeysV1(
            std.testing.allocator,
            &store,
            &fold_semantic,
            &native_leaf_security,
            executionAuthority(),
        ),
    );
}

test "recursive artifact store transport cold-open detects CAS corruption" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.testing.allocator, &temporary);
    defer std.testing.allocator.free(root);
    var store = try cas.Store.openOrCreate(std.testing.allocator, root, false);
    defer store.deinit();

    const missing_proof_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "missing-proof.bin" },
    );
    defer std.testing.allocator.free(missing_proof_path);
    try std.testing.expectError(
        error.InvalidRecursiveArtifactReference,
        adapter.ingestProofPathV1(&store, missing_proof_path, 0),
    );
    try std.testing.expectError(
        error.FileNotFound,
        adapter.ingestProofPathV1(&store, missing_proof_path, 3),
    );

    const empty_proof_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "empty-proof.bin" },
    );
    defer std.testing.allocator.free(empty_proof_path);
    const empty_proof_file = try std.fs.createFileAbsolute(empty_proof_path, .{
        .read = true,
        .exclusive = true,
        .mode = 0o600,
    });
    try empty_proof_file.sync();
    empty_proof_file.close();
    try std.testing.expectError(
        error.InvalidRecursiveArtifactReference,
        adapter.ingestProofPathV1(&store, empty_proof_path, 3),
    );

    const proof_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "source-proof.bin" },
    );
    defer std.testing.allocator.free(proof_path);
    const proof_file = try std.fs.createFileAbsolute(proof_path, .{
        .read = true,
        .exclusive = true,
        .mode = 0o600,
    });
    try proof_file.writeAll("proof-path-stream");
    try proof_file.sync();
    proof_file.close();
    const proof_ref = try adapter.ingestProofPathV1(
        &store,
        proof_path,
        3,
    );
    try std.testing.expectEqual(cas.ArtifactKindV1.proof_artifact, proof_ref.kind);
    try std.testing.expectEqual(
        cas.digestBytes("proof-path-stream"),
        proof_ref.sha256,
    );
    const local_proof_ref = try adapter.fromSharedRef(proof_ref);
    try std.testing.expectEqual(@as(u32, 8), local_proof_ref.kind);
    try std.testing.expectEqual(@as(u16, 3), local_proof_ref.schema_version);
    try std.testing.expectEqual(
        @as(u64, "proof-path-stream".len),
        local_proof_ref.byte_count,
    );

    const leaf = try fixtureNode(
        .leaf_wrapper,
        try artifact.TaskCoordinateV1.init(0, 0),
        .{ fixtureRef(8, 1, 17, 0x41), artifact.ArtifactRefV1.zero() },
    );
    const ref = try adapter.publishRecursiveNodeV1(&store, &leaf);
    const reopened = try adapter.coldOpenRecursiveNodeTransportV1(
        &store,
        ref,
    );
    try std.testing.expectEqualDeep(leaf, reopened);

    const path = try objectPath(std.testing.allocator, root, ref.sha256);
    defer std.testing.allocator.free(path);
    const read_only = try std.fs.openFileAbsolute(path, .{});
    try read_only.chmod(0o600);
    read_only.close();
    const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_write });
    try file.pwriteAll(&.{0xff}, 0);
    try file.chmod(0o400);
    try file.sync();
    file.close();
    try std.testing.expectError(
        error.ArtifactStoreCorrupt,
        adapter.coldOpenRecursiveNodeTransportV1(
            &store,
            ref,
        ),
    );
}

test "recursive artifact store validator receipt remint preserves proof keys" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.testing.allocator, &temporary);
    defer std.testing.allocator.free(root);
    var store = try cas.Store.openOrCreate(std.testing.allocator, root, false);
    defer store.deinit();
    const leaf = try fixtureNode(
        .leaf_wrapper,
        try artifact.TaskCoordinateV1.init(0, 0),
        .{ fixtureRef(8, 1, 17, 0x41), artifact.ArtifactRefV1.zero() },
    );
    const semantic = try leaf.semanticInputs();
    const wrapper_security = security.ProofSecurityV1.recursiveParentSecure();
    var keys = try adapter.deriveAndPublishStageKeysV1(
        std.testing.allocator,
        &store,
        &semantic,
        &wrapper_security,
        executionAuthority(),
    );
    defer keys.deinit(std.testing.allocator);
    const original_semantic = keys.semantic.identity;
    const original_execution = keys.execution.identity;
    const original_key_refs = keys.published;
    const output_ref = try adapter.publishRecursiveNodeV1(&store, &leaf);
    const profile = try profileReceipt(&store, 0x63);

    const first_receipt = try validationReceipt(&store, 0x61, 1);
    const first_manifest = try adapter.createAndPublishStageManifestV1(
        std.testing.allocator,
        &store,
        &leaf,
        output_ref,
        &keys,
        &.{},
        &.{first_receipt},
        &.{profile},
    );
    const second_receipt = try validationReceipt(&store, 0x65, 2);
    const second_manifest = try adapter.createAndPublishStageManifestV1(
        std.testing.allocator,
        &store,
        &leaf,
        output_ref,
        &keys,
        &.{},
        &.{second_receipt},
        &.{profile},
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &first_manifest.identity,
        &second_manifest.identity,
    ));
    try std.testing.expectEqual(original_semantic, keys.semantic.identity);
    try std.testing.expectEqual(original_execution, keys.execution.identity);
    try std.testing.expectEqualDeep(original_key_refs, keys.published);
}

fn expectChildMutation(
    store: *cas.Store,
    left: artifact.ArtifactRefV1,
    right: artifact.ArtifactRefV1,
    parent_security: *const security.ProofSecurityV1,
) !void {
    const fold = try fixtureNode(
        .fold,
        try artifact.TaskCoordinateV1.init(1, 0),
        .{ left, right },
    );
    const semantic = try fold.semanticInputs();
    try std.testing.expectError(
        error.InvalidRecursiveChildReference,
        adapter.deriveAndPublishStageKeysV1(
            std.testing.allocator,
            store,
            &semantic,
            parent_security,
            executionAuthority(),
        ),
    );
}

fn fixtureNode(
    stage: artifact.StageKindV1,
    coordinate: artifact.TaskCoordinateV1,
    children: [artifact.MAX_CHILD_COUNT]artifact.ArtifactRefV1,
) !artifact.RecursiveNodeArtifactV1 {
    var statement_words = [_]u32{0} ** artifact.STATEMENT_WORD_COUNT;
    statement_words[0] = 7;
    const public = try artifact.NodePublicV1.seal(.{
        .statement_words = statement_words,
        .statement_identity_sha256 = digest(0x31),
        .node_authority_sha256 = digest(0x32),
        .subtree_sha256 = digest(0x33),
        .subtree_digest = [_]u32{9} ** artifact.DIGEST_WORD_COUNT,
        .output_identity_sha256 = undefined,
    });
    return artifact.RecursiveNodeArtifactV1.seal(.{
        .stage_kind = stage,
        .node_kind = try artifact.expectedNodeKind(coordinate),
        .child_count = if (stage == .leaf_wrapper) 1 else 2,
        .coordinate = coordinate,
        .node_public = public,
        .campaign_namespace_sha256 = digest(0x01),
        .circuit_identity_sha256 = digest(0x02),
        .program_identity_sha256 = digest(0x03),
        .profile_identity_sha256 = digest(0x04),
        .pcs_identity_sha256 = digest(0x05),
        .padding_layout_identity_sha256 = digest(0x06),
        .registry_identity_sha256 = digest(0x07),
        .node_public_abi_sha256 = artifact.nodePublicAbiIdentity(),
        .statement_identity_sha256 = public.statement_identity_sha256,
        .output_identity_sha256 = public.output_identity_sha256,
        .ordered_children = children,
        .proof_ref = fixtureRef(8, 1, 101, 0x42),
        .preprocessed_root = [_]u32{11} ** artifact.DIGEST_WORD_COUNT,
        .semantic_inputs_identity_sha256 = undefined,
        .content_identity_sha256 = undefined,
    });
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
    schema_version: u16,
) !cas.ValidationReceiptRefV1 {
    const bytes = [_]u8{ seed, @intCast(schema_version) };
    return .{
        .validator_kind = 1,
        .validator_schema_version = schema_version,
        .authority_identity = digest(seed),
        .validator_identity = digest(seed + 1),
        .blob = try store.putBytes(.validation_receipt, 1, &bytes),
    };
}

fn profileReceipt(store: *cas.Store, seed: u8) !cas.ProfileReceiptRefV1 {
    const bytes = [_]u8{seed};
    return .{
        .profile_kind = 1,
        .profile_schema_version = 1,
        .profile_identity = digest(seed),
        .issuer_identity = digest(seed + 1),
        .blob = try store.putBytes(.profile_receipt, 1, &bytes),
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

fn hexDigest(encoded: []const u8) ![32]u8 {
    if (encoded.len != 64) return error.InvalidGoldenDigest;
    var result: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, encoded);
    return result;
}

fn rootPath(
    allocator: std.mem.Allocator,
    temporary: *std.testing.TmpDir,
) ![]u8 {
    const parent = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(parent);
    return std.fs.path.join(allocator, &.{ parent, "artifact-store" });
}

fn objectPath(
    allocator: std.mem.Allocator,
    root: []const u8,
    sha256: [32]u8,
) ![]u8 {
    const encoded = std.fmt.bytesToHex(sha256, .lower);
    return std.fmt.allocPrint(
        allocator,
        "{s}/objects/sha256/{s}/{s}.blob",
        .{ root, encoded[0..2], encoded },
    );
}
