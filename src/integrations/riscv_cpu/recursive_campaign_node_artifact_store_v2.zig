//! Shared-CAS and StageManifest sibling for campaign-bound schema-2 nodes.
//!
//! The durable node bytes remain kind10/schema2/2380. This module changes
//! only the validation/key path: every operation receives an authenticated
//! campaign shape and consumes `CampaignSemanticInputsV2`. Legacy store APIs
//! and keys are untouched. A reopened blob still has no fresh capability.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const base_store = @import("recursive_node_artifact_store_v2.zig");
const proof_security = @import("recursive_temporal_proof_security_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const KEY_SCHEMA_VERSION = base_store.KEY_SCHEMA_VERSION;
pub const STAGE_MANIFEST_SCHEMA_VERSION =
    base_store.STAGE_MANIFEST_SCHEMA_VERSION;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const ExecutionAuthorityV1 = base_store.ExecutionAuthorityV1;
pub const OwnedPublishedStageKeysV1 = base_store.OwnedPublishedStageKeysV1;
pub const PublishedStageManifestV1 = base_store.PublishedStageManifestV1;
pub const CampaignShape = campaign_artifact.CampaignShape;
pub const Semantic = campaign_artifact.CampaignSemanticInputsV2;
pub const Artifact = campaign_artifact.Artifact;

const LOCAL_TASK_DOMAIN =
    "stwo-zig/artifact-store/recursive-campaign-node-local-task/v2\x00";
const STATEMENT_CACHE_DOMAIN =
    "stwo-zig/artifact-store/recursive-campaign-node-statement/v2\x00";

pub const Error = campaign_artifact.Error || base_store.Error || error{
    InvalidCampaignArtifactReference,
    InvalidCampaignChildReference,
    InvalidCampaignKeyPublication,
    InvalidCampaignSemanticProjection,
    InvalidCampaignStageManifest,
};

pub fn sharedStageKind(
    stage: campaign_artifact.StageKind,
) artifact_store.StageKindV1 {
    return switch (stage) {
        .leaf_wrapper => .prove,
        .fold, .root => .fold,
    };
}

pub fn stageSchemaVersion(
    shape: *const CampaignShape,
    semantic: *const Semantic,
) Error!u16 {
    try semantic.validate(shape);
    return switch (semantic.stage_kind) {
        .leaf_wrapper => switch (semantic.node_kind) {
            .real => base_store.REAL_WRAPPER_STAGE_SCHEMA_VERSION,
            .empty => base_store.EMPTY_WRAPPER_STAGE_SCHEMA_VERSION,
            .mixed => error.InvalidCampaignSemanticProjection,
        },
        .fold, .root => base_store.COMMON_FOLD_STAGE_SCHEMA_VERSION,
    };
}

pub fn localTaskIdentity(
    shape: *const CampaignShape,
    semantic: *const Semantic,
) Error!artifact_store.Digest {
    try semantic.validate(shape);
    var hash = Sha256.init(.{});
    hash.update(LOCAL_TASK_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, try stageSchemaVersion(shape, semantic));
    hash.update(&semantic.campaign_shape_identity_sha256);
    hashInt(&hash, u8, @intFromEnum(semantic.stage_kind));
    hashInt(&hash, u8, @intFromEnum(semantic.node_kind));
    hashInt(&hash, u8, semantic.coordinate.height);
    hash.update(&semantic.coordinate.reserved);
    hashInt(&hash, u32, semantic.coordinate.index);
    hashInt(&hash, u32, semantic.coordinate.global_ordinal);
    hashInt(&hash, u8, semantic.child_count);
    return hash.finalResult();
}

pub fn statementCacheIdentity(
    shape: *const CampaignShape,
    semantic: *const Semantic,
) Error!artifact_store.Digest {
    try semantic.validate(shape);
    var hash = Sha256.init(.{});
    hash.update(STATEMENT_CACHE_DOMAIN);
    hash.update(&semantic.campaign_shape_identity_sha256);
    for (semantic.statement_digest) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

pub fn deriveAndPublishStageKeys(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    shape: *const CampaignShape,
    semantic: *const Semantic,
    security_authority: *const proof_security.ProofSecurityV1,
    execution_authority: ExecutionAuthorityV1,
) !OwnedPublishedStageKeysV1 {
    try semantic.validate(shape);
    try validateSecurity(security_authority);
    try execution_authority.validate();
    const ordered_inputs = try allocator.alloc(
        artifact_store.InputRefV1,
        semantic.child_count,
    );
    errdefer allocator.free(ordered_inputs);
    try fillOrderedInputs(semantic, ordered_inputs);
    const semantic_key = try artifact_store.SemanticKeyV1.create(
        allocator,
        .{
            .stage_kind = sharedStageKind(semantic.stage_kind),
            .stage_schema_version = try stageSchemaVersion(shape, semantic),
            .campaign_namespace = semantic.campaign_namespace_sha256,
            .local_task_identity = try localTaskIdentity(shape, semantic),
            .protocol_identity = semantic.circuit_identity_sha256,
            .program_identity = semantic.program_identity_sha256,
            .profile_identity = semantic.profile_identity_sha256,
            .pcs_identity = semantic.pcs_identity_sha256,
            .security_identity = security_authority.identity,
            .statement_identity = try statementCacheIdentity(shape, semantic),
            .layout_identity = semantic.padding_layout_identity_sha256,
            .registry_identity = semantic.registry_identity_sha256,
            .semantic_options_identity = semantic.identity_sha256,
            .ordered_inputs = ordered_inputs,
        },
    );
    const semantic_bytes = try semantic_key.canonicalBytesAlloc(allocator);
    defer allocator.free(semantic_bytes);
    const semantic_ref = try store.putBytes(
        .semantic_key,
        KEY_SCHEMA_VERSION,
        semantic_bytes,
    );
    if (!std.mem.eql(u8, &semantic_ref.sha256, &semantic_key.identity))
        return error.InvalidCampaignKeyPublication;
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
        return error.InvalidCampaignKeyPublication;
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

pub fn publishRecursiveNode(
    store: *artifact_store.Store,
    shape: *const CampaignShape,
    node: *const Artifact,
) !artifact_store.BlobRefV1 {
    if (node.proof_ref.kind != @intFromEnum(
        artifact_store.ArtifactKindV1.proof_artifact,
    )) return error.InvalidCampaignArtifactReference;
    const bytes = try campaign_artifact.encodeCanonical(shape, node);
    const expected = try base_store.toSharedRef(
        try campaign_artifact.artifactRef(shape, node),
    );
    const published = try store.putBytes(
        .recursion_node,
        campaign_artifact.SCHEMA_VERSION,
        &bytes,
    );
    if (!artifact_store.BlobRefV1.eql(expected, published))
        return error.InvalidCampaignArtifactReference;
    return published;
}

pub fn coldOpenRecursiveNodeTransport(
    store: *artifact_store.Store,
    shape: *const CampaignShape,
    ref: artifact_store.BlobRefV1,
) !Artifact {
    try validateRecursiveChild(ref);
    var reopened = try store.openBlob(
        ref,
        .recursion_node,
        campaign_artifact.SCHEMA_VERSION,
        campaign_artifact.ENCODED_BYTE_COUNT,
    );
    defer reopened.deinit(store.allocator);
    const node = try campaign_artifact.coldDecodeForStore(
        shape,
        reopened.bytes,
    );
    const expected = try base_store.toSharedRef(
        try campaign_artifact.artifactRef(shape, &node),
    );
    if (!artifact_store.BlobRefV1.eql(expected, ref))
        return error.InvalidCampaignArtifactReference;
    return node;
}

pub fn validateSemanticProjection(
    allocator: std.mem.Allocator,
    shape: *const CampaignShape,
    semantic: *const Semantic,
    key: *const artifact_store.SemanticKeyV1,
) !void {
    try semantic.validate(shape);
    try key.validate(allocator);
    const fields = key.fields;
    const local_task = try localTaskIdentity(shape, semantic);
    const statement = try statementCacheIdentity(shape, semantic);
    const security = proof_security.ProofSecurityV1.recursiveParentSecure();
    if (fields.stage_kind != sharedStageKind(semantic.stage_kind) or
        fields.stage_schema_version != try stageSchemaVersion(shape, semantic) or
        !std.mem.eql(u8, &fields.campaign_namespace, &semantic.campaign_namespace_sha256) or
        !std.mem.eql(u8, &fields.local_task_identity, &local_task) or
        !std.mem.eql(u8, &fields.protocol_identity, &semantic.circuit_identity_sha256) or
        !std.mem.eql(u8, &fields.program_identity, &semantic.program_identity_sha256) or
        !std.mem.eql(u8, &fields.profile_identity, &semantic.profile_identity_sha256) or
        !std.mem.eql(u8, &fields.pcs_identity, &semantic.pcs_identity_sha256) or
        !std.mem.eql(u8, &fields.security_identity, &security.identity) or
        !std.mem.eql(u8, &fields.statement_identity, &statement) or
        !artifact_store.encoding.isZeroDigest(fields.provider_identity) or
        !std.mem.eql(u8, &fields.layout_identity, &semantic.padding_layout_identity_sha256) or
        !std.mem.eql(u8, &fields.registry_identity, &semantic.registry_identity_sha256) or
        !std.mem.eql(u8, &fields.semantic_options_identity, &semantic.identity_sha256) or
        fields.ordered_inputs.len != semantic.child_count)
    {
        return error.InvalidCampaignSemanticProjection;
    }
    var expected: [2]artifact_store.InputRefV1 = undefined;
    try fillOrderedInputs(semantic, expected[0..semantic.child_count]);
    for (fields.ordered_inputs, expected[0..semantic.child_count]) |
        actual,
        wanted,
    | if (!std.meta.eql(actual, wanted))
        return error.InvalidCampaignSemanticProjection;
}

pub fn createAndPublishStageManifest(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    shape: *const CampaignShape,
    node: *const Artifact,
    output_ref: artifact_store.BlobRefV1,
    keys: *const OwnedPublishedStageKeysV1,
    dependency_manifest_ids: []const artifact_store.Digest,
    validation_receipts: []const artifact_store.ValidationReceiptRefV1,
    profile_receipts: []const artifact_store.ProfileReceiptRefV1,
) !PublishedStageManifestV1 {
    try keys.validate(allocator);
    const semantic = try campaign_artifact.semanticInputsForStore(shape, node);
    try validateSemanticProjection(allocator, shape, &semantic, &keys.semantic);
    const expected_output = try base_store.toSharedRef(
        try campaign_artifact.artifactRef(shape, node),
    );
    if (!artifact_store.BlobRefV1.eql(expected_output, output_ref) or
        validation_receipts.len == 0 or profile_receipts.len == 0)
    {
        return error.InvalidCampaignStageManifest;
    }
    const expected_dependencies: usize = switch (semantic.stage_kind) {
        .leaf_wrapper => 0,
        .fold, .root => 2,
    };
    if (dependency_manifest_ids.len != expected_dependencies)
        return error.InvalidCampaignStageManifest;
    const outputs = [_]artifact_store.BlobRefV1{output_ref};
    const manifest = try artifact_store.StageManifestV1.create(allocator, .{
        .stage_kind = sharedStageKind(semantic.stage_kind),
        .stage_schema_version = try stageSchemaVersion(shape, &semantic),
        .node_identity = try localTaskIdentity(shape, &semantic),
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

fn validateSecurity(value: *const proof_security.ProofSecurityV1) Error!void {
    value.validate() catch return error.InvalidRecursiveSecurity;
    if (value.kind != .recursive_parent_secure)
        return error.InvalidRecursiveSecurity;
}

fn fillOrderedInputs(
    semantic: *const Semantic,
    output: []artifact_store.InputRefV1,
) Error!void {
    if (output.len != semantic.child_count)
        return error.InvalidCampaignSemanticProjection;
    switch (semantic.stage_kind) {
        .leaf_wrapper => {
            if (output.len != 1)
                return error.InvalidCampaignSemanticProjection;
            output[0] = .{
                .role = .direct,
                .ordinal = 0,
                .blob = try base_store.toSharedRef(semantic.ordered_children[0]),
            };
        },
        .fold, .root => {
            if (output.len != 2)
                return error.InvalidCampaignSemanticProjection;
            const left = try base_store.toSharedRef(semantic.ordered_children[0]);
            const right = try base_store.toSharedRef(semantic.ordered_children[1]);
            try validateRecursiveChild(left);
            try validateRecursiveChild(right);
            output[0] = .{ .role = .child_left, .ordinal = 0, .blob = left };
            output[1] = .{ .role = .child_right, .ordinal = 0, .blob = right };
        },
    }
}

fn validateRecursiveChild(ref: artifact_store.BlobRefV1) Error!void {
    if (ref.kind != .recursion_node or
        ref.schema_version != campaign_artifact.SCHEMA_VERSION or
        ref.byte_count != campaign_artifact.ENCODED_BYTE_COUNT)
    {
        return error.InvalidCampaignChildReference;
    }
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY or
        FORMAT_VERSION != 2 or KEY_SCHEMA_VERSION != 1 or
        STAGE_MANIFEST_SCHEMA_VERSION != 1)
    {
        @compileError("campaign recursive-node store contract drifted");
    }
}
