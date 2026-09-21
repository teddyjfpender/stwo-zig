//! Shared-CAS projection for field-native recursive-node artifacts.
//!
//! Schema-2 nodes keep every recursive semantic in M31/Poseidon form. The
//! SHA-256 identities minted here are only cache, transport, and journal
//! authorities. A cache hit remains inert until the current Zig cold verifier
//! reopens the proof and returns a live verifier-owned lease.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const node_artifact = @import("recursive_node_artifact_v2.zig");
const node_artifact_v1 = @import("recursive_node_artifact_v1.zig");
const v1_adapter = @import("recursive_node_artifact_store_v1.zig");
const proof_security = @import("recursive_temporal_proof_security_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const cas = artifact_store;
pub const recursive_node = node_artifact;
pub const security = proof_security;

pub const FORMAT_VERSION: u16 = 1;
pub const KEY_SCHEMA_VERSION: u16 = 1;
pub const STAGE_MANIFEST_SCHEMA_VERSION: u16 = 1;
pub const REAL_WRAPPER_STAGE_SCHEMA_VERSION: u16 = 102;
pub const EMPTY_WRAPPER_STAGE_SCHEMA_VERSION: u16 = 103;
pub const COMMON_FOLD_STAGE_SCHEMA_VERSION: u16 = 104;
pub const PRODUCTION_ACTIVATION = false;

const LOCAL_TASK_DOMAIN =
    "stwo-zig/artifact-store/recursive-node-local-task/v2\x00";
const STATEMENT_CACHE_DOMAIN =
    "stwo-zig/artifact-store/recursive-node-statement/v2\x00";

pub const ExecutionAuthorityV1 = v1_adapter.ExecutionAuthorityV1;
pub const PublishedStageKeyRefsV1 = v1_adapter.PublishedStageKeyRefsV1;
pub const OwnedPublishedStageKeysV1 = v1_adapter.OwnedPublishedStageKeysV1;
pub const PublishedStageManifestV1 = v1_adapter.PublishedStageManifestV1;

pub const Error = node_artifact.Error || v1_adapter.Error || error{
    InvalidRecursiveArtifactReference,
    InvalidRecursiveChildReference,
    InvalidRecursiveKeyPublication,
    InvalidRecursiveManifestPublication,
    InvalidRecursiveSecurity,
    InvalidRecursiveSemanticProjection,
    InvalidRecursiveStageManifest,
};

pub const toSharedRef = v1_adapter.toSharedRef;
pub const fromSharedRef = v1_adapter.fromSharedRef;
pub const ingestProofPathV1 = v1_adapter.ingestProofPathV1;

pub fn sharedStageKindV2(
    stage: node_artifact.StageKindV1,
) artifact_store.StageKindV1 {
    return switch (stage) {
        .leaf_wrapper => .prove,
        .fold, .root => .fold,
    };
}

pub fn stageSchemaVersionV2(
    semantic: *const node_artifact.SemanticInputsV2,
) Error!u16 {
    try semantic.validate();
    return switch (semantic.stage_kind) {
        .leaf_wrapper => switch (semantic.node_kind) {
            .real => REAL_WRAPPER_STAGE_SCHEMA_VERSION,
            .empty => EMPTY_WRAPPER_STAGE_SCHEMA_VERSION,
            .mixed => error.InvalidRecursiveSemanticProjection,
        },
        .fold, .root => COMMON_FOLD_STAGE_SCHEMA_VERSION,
    };
}

pub fn localTaskIdentityV2(
    semantic: *const node_artifact.SemanticInputsV2,
) Error!artifact_store.Digest {
    try semantic.validate();
    var hash = Sha256.init(.{});
    hash.update(LOCAL_TASK_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, try stageSchemaVersionV2(semantic));
    hashInt(&hash, u8, @intFromEnum(semantic.stage_kind));
    hashInt(&hash, u8, @intFromEnum(semantic.node_kind));
    hashInt(&hash, u8, semantic.coordinate.height);
    hash.update(&semantic.coordinate.reserved);
    hashInt(&hash, u32, semantic.coordinate.index);
    hashInt(&hash, u32, semantic.coordinate.global_ordinal);
    hashInt(&hash, u8, semantic.child_count);
    return hash.finalResult();
}

/// Cache-key projection of the field-native statement digest. This SHA is not
/// a recursive proof claim and is never exposed through NodePublicV2.
pub fn statementCacheIdentityV2(
    semantic: *const node_artifact.SemanticInputsV2,
) Error!artifact_store.Digest {
    try semantic.validate();
    var hash = Sha256.init(.{});
    hash.update(STATEMENT_CACHE_DOMAIN);
    for (semantic.statement_digest) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

pub fn deriveAndPublishStageKeysV2(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    semantic: *const node_artifact.SemanticInputsV2,
    security_authority: *const proof_security.ProofSecurityV1,
    execution_authority: ExecutionAuthorityV1,
) !OwnedPublishedStageKeysV1 {
    try semantic.validate();
    try validateSecurity(security_authority);
    try execution_authority.validate();

    const ordered_inputs = try allocator.alloc(
        artifact_store.InputRefV1,
        semantic.child_count,
    );
    errdefer allocator.free(ordered_inputs);
    try fillOrderedInputs(semantic, ordered_inputs);

    const semantic_key = try artifact_store.SemanticKeyV1.create(allocator, .{
        .stage_kind = sharedStageKindV2(semantic.stage_kind),
        .stage_schema_version = try stageSchemaVersionV2(semantic),
        .campaign_namespace = semantic.campaign_namespace_sha256,
        .local_task_identity = try localTaskIdentityV2(semantic),
        .protocol_identity = semantic.circuit_identity_sha256,
        .program_identity = semantic.program_identity_sha256,
        .profile_identity = semantic.profile_identity_sha256,
        .pcs_identity = semantic.pcs_identity_sha256,
        .security_identity = security_authority.identity,
        .statement_identity = try statementCacheIdentityV2(semantic),
        .layout_identity = semantic.padding_layout_identity_sha256,
        .registry_identity = semantic.registry_identity_sha256,
        .semantic_options_identity = semantic.identity_sha256,
        .ordered_inputs = ordered_inputs,
    });
    const semantic_bytes = try semantic_key.canonicalBytesAlloc(allocator);
    defer allocator.free(semantic_bytes);
    const semantic_ref = try store.putBytes(
        .semantic_key,
        KEY_SCHEMA_VERSION,
        semantic_bytes,
    );
    if (!std.mem.eql(u8, &semantic_ref.sha256, &semantic_key.identity))
        return error.InvalidRecursiveKeyPublication;

    const execution_key = try artifact_store.ExecutionKeyV1.create(.{
        .semantic_key_identity = semantic_key.identity,
        .producer_identity = execution_authority.producer_identity,
        .verifier_identity = execution_authority.verifier_identity,
        .source_identity = execution_authority.source_identity,
        .build_identity = execution_authority.build_identity,
        .executable_identity = execution_authority.executable_identity,
        .toolchain_identity = execution_authority.toolchain_identity,
        .backend_identity = execution_authority.backend_identity,
        .optimization_identity = execution_authority.optimization_identity,
        .worker_policy_identity = execution_authority.worker_policy_identity,
        .memory_policy_identity = execution_authority.memory_policy_identity,
        .retention_policy_identity = execution_authority.retention_policy_identity,
        .timeout_policy_identity = execution_authority.timeout_policy_identity,
    });
    const execution_bytes = try execution_key.canonicalBytes();
    const execution_ref = try store.putBytes(
        .execution_key,
        KEY_SCHEMA_VERSION,
        &execution_bytes,
    );
    if (!std.mem.eql(u8, &execution_ref.sha256, &execution_key.identity))
        return error.InvalidRecursiveKeyPublication;

    const result = OwnedPublishedStageKeysV1{
        .semantic = semantic_key,
        .execution = execution_key,
        .ordered_inputs = ordered_inputs,
        .published = .{
            .semantic_ref = semantic_ref,
            .semantic_identity = semantic_key.identity,
            .execution_ref = execution_ref,
            .execution_identity = execution_key.identity,
        },
    };
    try result.validate(allocator);
    return result;
}

pub fn publishRecursiveNodeV2(
    store: *artifact_store.Store,
    node: *const node_artifact.RecursiveNodeArtifactV2,
) !artifact_store.BlobRefV1 {
    if (node.proof_ref.kind != @intFromEnum(
        artifact_store.ArtifactKindV1.proof_artifact,
    )) return error.InvalidRecursiveArtifactReference;
    const bytes = try node.encodeCanonical();
    const expected = try toSharedRef(try node.artifactRef());
    const published = try store.putBytes(
        .recursion_node,
        node_artifact.SCHEMA_VERSION,
        &bytes,
    );
    if (!artifact_store.BlobRefV1.eql(expected, published))
        return error.InvalidRecursiveArtifactReference;
    return published;
}

/// Transport reopen only. Proof freshness is reminted by the role-specific
/// wrapper verifier, never by this CAS decoder.
pub fn coldOpenRecursiveNodeTransportV2(
    store: *artifact_store.Store,
    ref: artifact_store.BlobRefV1,
) !node_artifact.RecursiveNodeArtifactV2 {
    try validateRecursiveChild(ref);
    var reopened = try store.openBlob(
        ref,
        .recursion_node,
        node_artifact.SCHEMA_VERSION,
        node_artifact.ENCODED_BYTE_COUNT,
    );
    defer reopened.deinit(store.allocator);
    const node = try node_artifact.RecursiveNodeArtifactV2.decodeCanonical(
        reopened.bytes,
    );
    const expected = try toSharedRef(try node.artifactRef());
    if (!artifact_store.BlobRefV1.eql(expected, ref))
        return error.InvalidRecursiveArtifactReference;
    return node;
}

pub fn createAndPublishStageManifestV2(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    node: *const node_artifact.RecursiveNodeArtifactV2,
    output_ref: artifact_store.BlobRefV1,
    keys: *const OwnedPublishedStageKeysV1,
    dependency_manifest_ids: []const artifact_store.Digest,
    validation_receipts: []const artifact_store.ValidationReceiptRefV1,
    profile_receipts: []const artifact_store.ProfileReceiptRefV1,
) !PublishedStageManifestV1 {
    try keys.validate(allocator);
    const semantic = try node.semanticInputs();
    try validateSemanticProjection(allocator, &semantic, &keys.semantic);
    const expected_output = try toSharedRef(try node.artifactRef());
    if (!artifact_store.BlobRefV1.eql(expected_output, output_ref) or
        validation_receipts.len == 0 or profile_receipts.len == 0)
    {
        return error.InvalidRecursiveStageManifest;
    }
    const expected_dependencies: usize = switch (semantic.stage_kind) {
        .leaf_wrapper => 0,
        .fold, .root => 2,
    };
    if (dependency_manifest_ids.len != expected_dependencies)
        return error.InvalidRecursiveStageManifest;

    const outputs = [_]artifact_store.BlobRefV1{output_ref};
    const manifest = try artifact_store.StageManifestV1.create(allocator, .{
        .stage_kind = sharedStageKindV2(semantic.stage_kind),
        .stage_schema_version = try stageSchemaVersionV2(&semantic),
        .node_identity = try localTaskIdentityV2(&semantic),
        .semantic_key_identity = keys.semantic.identity,
        .execution_key_identity = keys.execution.identity,
        .phase = .published,
        .status = .complete,
        .ordered_dependency_manifest_ids = dependency_manifest_ids,
        .ordered_inputs = keys.ordered_inputs,
        .ordered_outputs = &outputs,
        .validation_receipts = validation_receipts,
        .profile_receipts = profile_receipts,
    });
    const bytes = try manifest.canonicalBytesAlloc(allocator);
    defer allocator.free(bytes);
    const ref = try store.putBytes(
        .stage_manifest,
        STAGE_MANIFEST_SCHEMA_VERSION,
        bytes,
    );
    const result = PublishedStageManifestV1{
        .ref = ref,
        .identity = manifest.identity,
    };
    try result.validate();
    return result;
}

fn validateSecurity(
    value: *const proof_security.ProofSecurityV1,
) Error!void {
    value.validate() catch return error.InvalidRecursiveSecurity;
    if (value.kind != .recursive_parent_secure)
        return error.InvalidRecursiveSecurity;
}

fn fillOrderedInputs(
    semantic: *const node_artifact.SemanticInputsV2,
    output: []artifact_store.InputRefV1,
) Error!void {
    if (output.len != semantic.child_count)
        return error.InvalidRecursiveSemanticProjection;
    switch (semantic.stage_kind) {
        .leaf_wrapper => {
            if (output.len != 1) return error.InvalidRecursiveSemanticProjection;
            output[0] = .{
                .role = .direct,
                .ordinal = 0,
                .blob = try toSharedRef(semantic.ordered_children[0]),
            };
        },
        .fold, .root => {
            if (output.len != 2) return error.InvalidRecursiveSemanticProjection;
            const left = try toSharedRef(semantic.ordered_children[0]);
            const right = try toSharedRef(semantic.ordered_children[1]);
            try validateRecursiveChild(left);
            try validateRecursiveChild(right);
            output[0] = .{ .role = .child_left, .ordinal = 0, .blob = left };
            output[1] = .{ .role = .child_right, .ordinal = 0, .blob = right };
        },
    }
}

fn validateRecursiveChild(ref: artifact_store.BlobRefV1) Error!void {
    if (ref.kind != .recursion_node or
        ref.schema_version != node_artifact.SCHEMA_VERSION or
        ref.byte_count != node_artifact.ENCODED_BYTE_COUNT)
    {
        return error.InvalidRecursiveChildReference;
    }
}

fn validateSemanticProjection(
    allocator: std.mem.Allocator,
    semantic: *const node_artifact.SemanticInputsV2,
    key: *const artifact_store.SemanticKeyV1,
) !void {
    try semantic.validate();
    try key.validate(allocator);
    const fields = key.fields;
    const local_task_identity = try localTaskIdentityV2(semantic);
    const statement_identity = try statementCacheIdentityV2(semantic);
    const expected_security = proof_security.ProofSecurityV1
        .recursiveParentSecure();
    if (fields.stage_kind != sharedStageKindV2(semantic.stage_kind) or
        fields.stage_schema_version != try stageSchemaVersionV2(semantic) or
        !std.mem.eql(u8, &fields.campaign_namespace, &semantic.campaign_namespace_sha256) or
        !std.mem.eql(u8, &fields.local_task_identity, &local_task_identity) or
        !std.mem.eql(u8, &fields.protocol_identity, &semantic.circuit_identity_sha256) or
        !std.mem.eql(u8, &fields.program_identity, &semantic.program_identity_sha256) or
        !std.mem.eql(u8, &fields.profile_identity, &semantic.profile_identity_sha256) or
        !std.mem.eql(u8, &fields.pcs_identity, &semantic.pcs_identity_sha256) or
        !std.mem.eql(u8, &fields.security_identity, &expected_security.identity) or
        !std.mem.eql(u8, &fields.statement_identity, &statement_identity) or
        !artifact_store.encoding.isZeroDigest(fields.provider_identity) or
        !std.mem.eql(u8, &fields.layout_identity, &semantic.padding_layout_identity_sha256) or
        !std.mem.eql(u8, &fields.registry_identity, &semantic.registry_identity_sha256) or
        !std.mem.eql(u8, &fields.semantic_options_identity, &semantic.identity_sha256) or
        fields.ordered_inputs.len != semantic.child_count)
    {
        return error.InvalidRecursiveSemanticProjection;
    }
    var expected: [node_artifact.MAX_CHILD_COUNT]artifact_store.InputRefV1 =
        undefined;
    try fillOrderedInputs(semantic, expected[0..semantic.child_count]);
    for (fields.ordered_inputs, expected[0..semantic.child_count]) |actual, wanted| {
        if (!std.meta.eql(actual, wanted))
            return error.InvalidRecursiveSemanticProjection;
    }
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 1 or KEY_SCHEMA_VERSION != 1 or
        STAGE_MANIFEST_SCHEMA_VERSION != 1 or PRODUCTION_ACTIVATION or
        REAL_WRAPPER_STAGE_SCHEMA_VERSION != 102 or
        EMPTY_WRAPPER_STAGE_SCHEMA_VERSION != 103 or
        COMMON_FOLD_STAGE_SCHEMA_VERSION != 104 or
        @intFromEnum(artifact_store.ArtifactKindV1.recursion_node) !=
            node_artifact.RECURSIVE_NODE_ARTIFACT_KIND or
        artifact_store.BlobRefV1.canonical_size !=
            node_artifact_v1.ARTIFACT_REF_BYTE_COUNT)
    {
        @compileError("field-native recursive-node store contract drifted");
    }
}
