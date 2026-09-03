//! Shared-CAS projection for canonical recursive-node artifacts.
//!
//! Lane C owns the proof-semantic recursive envelope. This adapter preserves
//! that envelope byte-for-byte while making the host-neutral artifact store
//! the only cache-key and stage-manifest authority. A reopened transport is
//! still not a verifier lease or proof admission capability.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const node_artifact = @import("recursive_node_artifact_v1.zig");
const proof_security = @import("recursive_temporal_proof_security_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const cas = artifact_store;
pub const recursive_node = node_artifact;
pub const security = proof_security;

pub const FORMAT_VERSION: u16 = 1;
pub const KEY_SCHEMA_VERSION: u16 = 1;
pub const STAGE_MANIFEST_SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;

const LOCAL_TASK_DOMAIN =
    "stwo-zig/artifact-store/recursive-node-local-task/v1\x00";

pub const Error = node_artifact.Error || error{
    InvalidRecursiveArtifactReference,
    InvalidRecursiveChildReference,
    InvalidRecursiveExecutionAuthority,
    InvalidRecursiveKeyPublication,
    InvalidRecursiveManifestPublication,
    InvalidRecursiveSecurity,
    InvalidRecursiveSemanticProjection,
    InvalidRecursiveStageManifest,
};

/// Execution-only authority. The semantic-key identity is supplied only by
/// `deriveAndPublishStageKeysV1`, so a caller cannot bind execution policy to a
/// parallel or controller-authored semantic key.
pub const ExecutionAuthorityV1 = struct {
    producer_identity: artifact_store.Digest,
    verifier_identity: artifact_store.Digest,
    source_identity: artifact_store.Digest,
    build_identity: artifact_store.Digest,
    executable_identity: artifact_store.Digest,
    toolchain_identity: artifact_store.Digest,
    backend_identity: artifact_store.Digest,
    optimization_identity: artifact_store.Digest,
    worker_policy_identity: artifact_store.Digest,
    memory_policy_identity: artifact_store.Digest,
    retention_policy_identity: artifact_store.Digest,
    timeout_policy_identity: artifact_store.Digest,

    pub fn validate(self: ExecutionAuthorityV1) Error!void {
        inline for (@typeInfo(ExecutionAuthorityV1).@"struct".fields) |field| {
            if (artifact_store.encoding.isZeroDigest(@field(self, field.name)))
                return error.InvalidRecursiveExecutionAuthority;
        }
    }

    fn fields(
        self: ExecutionAuthorityV1,
        semantic_key_identity: artifact_store.Digest,
    ) artifact_store.ExecutionKeyFieldsV1 {
        return .{
            .semantic_key_identity = semantic_key_identity,
            .producer_identity = self.producer_identity,
            .verifier_identity = self.verifier_identity,
            .source_identity = self.source_identity,
            .build_identity = self.build_identity,
            .executable_identity = self.executable_identity,
            .toolchain_identity = self.toolchain_identity,
            .backend_identity = self.backend_identity,
            .optimization_identity = self.optimization_identity,
            .worker_policy_identity = self.worker_policy_identity,
            .memory_policy_identity = self.memory_policy_identity,
            .retention_policy_identity = self.retention_policy_identity,
            .timeout_policy_identity = self.timeout_policy_identity,
        };
    }
};

/// Pointer-free response projection for one future framed Zig worker. The
/// referenced bytes are the Zig canonical key encodings already in the CAS;
/// an external controller must not derive a second JSON key identity.
pub const PublishedStageKeyRefsV1 = struct {
    semantic_ref: artifact_store.BlobRefV1,
    semantic_identity: artifact_store.Digest,
    execution_ref: artifact_store.BlobRefV1,
    execution_identity: artifact_store.Digest,

    pub fn validate(self: PublishedStageKeyRefsV1) !void {
        try self.semantic_ref.validate();
        try self.execution_ref.validate();
        if (self.semantic_ref.kind != .semantic_key or
            self.semantic_ref.schema_version != KEY_SCHEMA_VERSION or
            !std.mem.eql(
                u8,
                &self.semantic_ref.sha256,
                &self.semantic_identity,
            ) or self.execution_ref.kind != .execution_key or
            self.execution_ref.schema_version != KEY_SCHEMA_VERSION or
            !std.mem.eql(
                u8,
                &self.execution_ref.sha256,
                &self.execution_identity,
            ))
        {
            return error.InvalidRecursiveKeyPublication;
        }
    }
};

/// Owns the ordered input slice borrowed by `semantic.fields`.
pub const OwnedPublishedStageKeysV1 = struct {
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
    ordered_inputs: []artifact_store.InputRefV1,
    published: PublishedStageKeyRefsV1,

    pub fn validate(
        self: *const OwnedPublishedStageKeysV1,
        allocator: std.mem.Allocator,
    ) !void {
        try self.semantic.validate(allocator);
        try self.execution.validate();
        try self.published.validate();
        const semantic_bytes = try self.semantic.canonicalBytesAlloc(allocator);
        defer allocator.free(semantic_bytes);
        const execution_bytes = try self.execution.canonicalBytes();
        const semantic_identity_matches = std.mem.eql(
            u8,
            &self.published.semantic_identity,
            &self.semantic.identity,
        );
        const execution_identity_matches = std.mem.eql(
            u8,
            &self.published.execution_identity,
            &self.execution.identity,
        );
        if (self.semantic.fields.ordered_inputs.ptr != self.ordered_inputs.ptr or
            self.semantic.fields.ordered_inputs.len != self.ordered_inputs.len or
            self.published.semantic_ref.byte_count !=
                @as(u64, @intCast(semantic_bytes.len)) or
            self.published.execution_ref.byte_count !=
                @as(u64, execution_bytes.len) or
            !std.mem.eql(
                u8,
                &self.execution.fields.semantic_key_identity,
                &self.semantic.identity,
            ) or !semantic_identity_matches or !execution_identity_matches)
        {
            return error.InvalidRecursiveKeyPublication;
        }
    }

    pub fn deinit(
        self: *OwnedPublishedStageKeysV1,
        allocator: std.mem.Allocator,
    ) void {
        allocator.free(self.ordered_inputs);
        self.* = undefined;
    }
};

pub const PublishedStageManifestV1 = struct {
    ref: artifact_store.BlobRefV1,
    identity: artifact_store.Digest,

    pub fn validate(self: PublishedStageManifestV1) !void {
        try self.ref.validate();
        if (self.ref.kind != .stage_manifest or
            self.ref.schema_version != STAGE_MANIFEST_SCHEMA_VERSION or
            !std.mem.eql(u8, &self.ref.sha256, &self.identity))
        {
            return error.InvalidRecursiveManifestPublication;
        }
    }
};

pub fn toSharedRef(
    value: node_artifact.ArtifactRefV1,
) Error!artifact_store.BlobRefV1 {
    try value.validate();
    return artifact_store.BlobRefV1.create(
        @enumFromInt(value.kind),
        value.schema_version,
        value.byte_count,
        value.sha256,
    ) catch return error.InvalidRecursiveArtifactReference;
}

pub fn fromSharedRef(
    value: artifact_store.BlobRefV1,
) Error!node_artifact.ArtifactRefV1 {
    value.validate() catch return error.InvalidRecursiveArtifactReference;
    const result = node_artifact.ArtifactRefV1{
        .kind = @intFromEnum(value.kind),
        .format_version = value.format_version,
        .schema_version = value.schema_version,
        .byte_count = value.byte_count,
        .sha256 = value.sha256,
    };
    try result.validate();
    return result;
}

pub fn sharedStageKindV1(
    stage: node_artifact.StageKindV1,
) artifact_store.StageKindV1 {
    return switch (stage) {
        .leaf_wrapper => .prove,
        .fold, .root => .fold,
    };
}

/// Stable topology/role identity. Direct artifact references and the Lane C
/// semantic seal are deliberately outside this value and enter the shared key
/// through `ordered_inputs` and `semantic_options_identity`, respectively.
pub fn localTaskIdentityV1(
    semantic: *const node_artifact.SemanticInputsV1,
) Error!artifact_store.Digest {
    try semantic.validate();
    var hash = Sha256.init(.{});
    hash.update(LOCAL_TASK_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u8, @intFromEnum(semantic.stage_kind));
    hashInt(&hash, u8, @intFromEnum(semantic.node_kind));
    hashInt(&hash, u8, semantic.coordinate.height);
    hash.update(&semantic.coordinate.reserved);
    hashInt(&hash, u32, semantic.coordinate.index);
    hashInt(&hash, u32, semantic.coordinate.global_ordinal);
    hashInt(&hash, u8, semantic.child_count);
    return hash.finalResult();
}

pub fn deriveAndPublishStageKeysV1(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    semantic: *const node_artifact.SemanticInputsV1,
    security_authority: *const proof_security.ProofSecurityV1,
    execution_authority: ExecutionAuthorityV1,
) !OwnedPublishedStageKeysV1 {
    try semantic.validate();
    try validateSecurity(semantic.stage_kind, security_authority);
    try execution_authority.validate();

    const ordered_inputs = try allocator.alloc(
        artifact_store.InputRefV1,
        semantic.child_count,
    );
    errdefer allocator.free(ordered_inputs);
    try fillOrderedInputs(semantic, ordered_inputs);

    const semantic_key = try artifact_store.SemanticKeyV1.create(allocator, .{
        .stage_kind = sharedStageKindV1(semantic.stage_kind),
        .stage_schema_version = node_artifact.SCHEMA_VERSION,
        .campaign_namespace = semantic.campaign_namespace_sha256,
        .local_task_identity = try localTaskIdentityV1(semantic),
        .protocol_identity = semantic.circuit_identity_sha256,
        .program_identity = semantic.program_identity_sha256,
        .profile_identity = semantic.profile_identity_sha256,
        .pcs_identity = semantic.pcs_identity_sha256,
        .security_identity = security_authority.identity,
        .statement_identity = semantic.statement_identity_sha256,
        .layout_identity = semantic.padding_layout_identity_sha256,
        .registry_identity = semantic.registry_identity_sha256,
        // The Lane C projection remains a typed semantic-options authority;
        // it is never itself used as the cache key.
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

    const execution_key = try artifact_store.ExecutionKeyV1.create(
        execution_authority.fields(semantic_key.identity),
    );
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

/// Streams or clones a proof file into the shared CAS inside Zig and returns
/// only its typed reference. A controller never has to materialize proof bytes.
pub fn ingestProofPathV1(
    store: *artifact_store.Store,
    source_path: []const u8,
    native_schema_version: u16,
) !artifact_store.BlobRefV1 {
    if (native_schema_version == 0)
        return error.InvalidRecursiveArtifactReference;
    var snapshot = store.ingestPath(source_path) catch |err| switch (err) {
        error.InvalidArtifact => return error.InvalidRecursiveArtifactReference,
        else => return err,
    };
    defer snapshot.deinit(store.allocator);
    if (snapshot.measurement.bytes == 0)
        return error.InvalidRecursiveArtifactReference;
    return artifact_store.BlobRefV1.create(
        .proof_artifact,
        native_schema_version,
        snapshot.measurement.bytes,
        snapshot.measurement.sha256,
    );
}

/// Publishes the exact Lane C envelope. The returned digest is transport
/// identity only; callers must still invoke the circuit-specific cold verifier.
pub fn publishRecursiveNodeV1(
    store: *artifact_store.Store,
    node: *const node_artifact.RecursiveNodeArtifactV1,
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

/// Exact transport reopen/rehash/decode. This function intentionally returns
/// a value, not a verifier-owned freshness capability or lease.
pub fn coldOpenRecursiveNodeTransportV1(
    store: *artifact_store.Store,
    ref: artifact_store.BlobRefV1,
) !node_artifact.RecursiveNodeArtifactV1 {
    if (ref.kind != .recursion_node or
        ref.schema_version != node_artifact.SCHEMA_VERSION or
        ref.byte_count != node_artifact.ENCODED_BYTE_COUNT)
    {
        return error.InvalidRecursiveArtifactReference;
    }
    var reopened = try store.openBlob(
        ref,
        .recursion_node,
        node_artifact.SCHEMA_VERSION,
        node_artifact.ENCODED_BYTE_COUNT,
    );
    defer reopened.deinit(store.allocator);
    const node = try node_artifact.RecursiveNodeArtifactV1.decodeCanonical(
        reopened.bytes,
    );
    const expected = try toSharedRef(try node.artifactRef());
    if (!artifact_store.BlobRefV1.eql(expected, ref))
        return error.InvalidRecursiveArtifactReference;
    return node;
}

/// Mints and publishes only the shared canonical stage manifest. Controller
/// cache/run JSON must use `.raw` or another separately allocated kind; kind 4
/// is exclusively `StageManifestV1`.
pub fn createAndPublishStageManifestV1(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    node: *const node_artifact.RecursiveNodeArtifactV1,
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
        .stage_kind = sharedStageKindV1(semantic.stage_kind),
        .stage_schema_version = node_artifact.SCHEMA_VERSION,
        .node_identity = try localTaskIdentityV1(&semantic),
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
    _: node_artifact.StageKindV1,
    value: *const proof_security.ProofSecurityV1,
) Error!void {
    value.validate() catch return error.InvalidRecursiveSecurity;
    if (value.kind != .recursive_parent_secure)
        return error.InvalidRecursiveSecurity;
}

fn fillOrderedInputs(
    semantic: *const node_artifact.SemanticInputsV1,
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
    semantic: *const node_artifact.SemanticInputsV1,
    key: *const artifact_store.SemanticKeyV1,
) !void {
    try semantic.validate();
    try key.validate(allocator);
    const fields = key.fields;
    const local_task_identity = try localTaskIdentityV1(semantic);
    const expected_security = proof_security.ProofSecurityV1
        .recursiveParentSecure();
    if (fields.stage_kind != sharedStageKindV1(semantic.stage_kind) or
        fields.stage_schema_version != node_artifact.SCHEMA_VERSION or
        !std.mem.eql(u8, &fields.campaign_namespace, &semantic.campaign_namespace_sha256) or
        !std.mem.eql(u8, &fields.local_task_identity, &local_task_identity) or
        !std.mem.eql(u8, &fields.protocol_identity, &semantic.circuit_identity_sha256) or
        !std.mem.eql(u8, &fields.program_identity, &semantic.program_identity_sha256) or
        !std.mem.eql(u8, &fields.profile_identity, &semantic.profile_identity_sha256) or
        !std.mem.eql(u8, &fields.pcs_identity, &semantic.pcs_identity_sha256) or
        !std.mem.eql(u8, &fields.security_identity, &expected_security.identity) or
        !std.mem.eql(u8, &fields.statement_identity, &semantic.statement_identity_sha256) or
        !artifact_store.encoding.isZeroDigest(fields.provider_identity) or
        !std.mem.eql(u8, &fields.layout_identity, &semantic.padding_layout_identity_sha256) or
        !std.mem.eql(u8, &fields.registry_identity, &semantic.registry_identity_sha256) or
        !std.mem.eql(u8, &fields.semantic_options_identity, &semantic.identity_sha256) or
        fields.ordered_inputs.len != semantic.child_count)
    {
        return error.InvalidRecursiveSemanticProjection;
    }
    var expected: [node_artifact.MAX_CHILD_COUNT]artifact_store.InputRefV1 = undefined;
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
        @intFromEnum(artifact_store.ArtifactKindV1.stage_manifest) != 4 or
        @intFromEnum(artifact_store.ArtifactKindV1.recursion_node) !=
            node_artifact.RECURSIVE_NODE_ARTIFACT_KIND or
        artifact_store.BlobRefV1.canonical_size !=
            node_artifact.ARTIFACT_REF_BYTE_COUNT)
    {
        @compileError("recursive-node shared artifact contract drifted");
    }
}
