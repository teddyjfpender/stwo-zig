//! Campaign-aware sibling for the frozen recursive-node schema-2 transport.
//!
//! Legacy methods retain their 210 -> 256 topology. These entry points parse,
//! seal, cold-open, project for the store, admit through the schema-4
//! registry, and validate worker output against an explicit campaign shape.
//! The canonical 2,380-byte wire is unchanged. No fresh verifier capability
//! is serialized or inferred from this transport admission.

const std = @import("std");

const artifact_v1 = @import("recursive_node_artifact_v1.zig");
const artifact_v2 = @import("recursive_node_artifact_v2.zig");
const field_public = @import("recursive_field_node_public_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION = artifact_v2.FORMAT_VERSION;
pub const SCHEMA_VERSION = artifact_v2.SCHEMA_VERSION;
pub const ENCODED_BYTE_COUNT = artifact_v2.ENCODED_BYTE_COUNT;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const Artifact = artifact_v2.RecursiveNodeArtifactV2;
pub const ArtifactRef = artifact_v2.ArtifactRefV1;
pub const NodePublic = artifact_v2.NodePublicV2;
pub const TaskCoordinate = artifact_v2.TaskCoordinateV1;
pub const StageKind = artifact_v2.StageKindV1;
pub const NodeKind = artifact_v2.NodeKindV1;
pub const CampaignShape = shape_mod.CampaignShapeAuthorityV2;
pub const Geometry = registry_mod.AuthenticatedGeometryV1;
pub const Registry = registry_mod.RecursiveCircuitRegistryV1;

const LEGACY_SEMANTIC_DOMAIN =
    "stwo-zig/recursive-node-semantic-inputs/v2\x00";
const LEGACY_CONTENT_DOMAIN =
    "stwo-zig/recursive-node-artifact-content/v2\x00";
const CAMPAIGN_SEMANTIC_DOMAIN =
    "stwo-zig/recursive-campaign-node-semantic-inputs/v2\x00";

pub const Error = artifact_v2.Error || campaign_public.Error ||
    registry_mod.Error || error{
    CampaignArtifactMismatch,
    CampaignRegistryMismatch,
    CampaignSemanticInputsMismatch,
    CampaignWorkerOutputMismatch,
    NonCanonicalCampaignArtifact,
};

/// Store/cache projection. The shape identity closes the topology seam which
/// the frozen legacy semantic projection intentionally does not contain.
pub const CampaignSemanticInputsV2 = struct {
    campaign_namespace_sha256: [32]u8,
    campaign_shape_identity_sha256: [32]u8,
    stage_kind: StageKind,
    node_kind: NodeKind,
    coordinate: TaskCoordinate,
    circuit_identity_sha256: [32]u8,
    program_identity_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    pcs_identity_sha256: [32]u8,
    padding_layout_identity_sha256: [32]u8,
    registry_identity_sha256: [32]u8,
    node_public_abi_sha256: [32]u8,
    proof_shape_identity_sha256: [32]u8,
    statement_digest: [field_public.DIGEST_WORD_COUNT]u32,
    source_digest: [field_public.DIGEST_WORD_COUNT]u32,
    subtree_digest: [field_public.DIGEST_WORD_COUNT]u32,
    output_digest: [field_public.DIGEST_WORD_COUNT]u32,
    child_count: u8,
    ordered_children: [artifact_v2.MAX_CHILD_COUNT]ArtifactRef,
    preprocessed_root: [artifact_v1.DIGEST_WORD_COUNT]u32,
    legacy_semantic_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn validate(
        self: *const CampaignSemanticInputsV2,
        shape: *const CampaignShape,
    ) Error!void {
        try shape.validateAgainstCampaign(self.campaign_namespace_sha256);
        if (!std.mem.eql(
            u8,
            &self.campaign_shape_identity_sha256,
            &shape.identity_sha256,
        )) return error.CampaignSemanticInputsMismatch;
        try campaign_public.validateStageCoordinate(
            shape,
            self.stage_kind,
            self.coordinate,
        );
        if (self.node_kind != try campaign_public.expectedNodeKind(
            shape,
            self.coordinate,
        )) return error.CampaignSemanticInputsMismatch;
        try validateIdentitySet(self);
        try validateChildRefs(
            self.stage_kind,
            self.child_count,
            &self.ordered_children,
        );
        if (!std.mem.eql(
            u8,
            &self.legacy_semantic_identity_sha256,
            &legacySemanticIdentityFromProjection(self),
        ) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &campaignSemanticIdentity(self),
        )) return error.CampaignSemanticInputsMismatch;
    }
};

/// Proof-ref-free input to semantic planning. A worker must know its semantic
/// key before proving, while the proof BlobRef only exists afterward. The
/// canonical semantic projection intentionally excludes that future ref and
/// can therefore be derived from the authenticated NodePublic, child refs,
/// registry, and cold-reminted role geometry alone.
pub const PlannedSemanticNodeV2 = struct {
    stage_kind: StageKind,
    node_public: NodePublic,
    child_count: u8,
    ordered_children: [artifact_v2.MAX_CHILD_COUNT]ArtifactRef,
};

pub fn semanticInputsForPlannedNode(
    shape: *const CampaignShape,
    registry: *const Registry,
    geometry: *const Geometry,
    planned: PlannedSemanticNodeV2,
) Error!CampaignSemanticInputsV2 {
    try shape.validate();
    try registry.validate();
    try geometry.validate();
    try campaign_public.validate(shape, &planned.node_public);
    try campaign_public.validateStageCoordinate(
        shape,
        planned.stage_kind,
        planned.node_public.coordinate,
    );
    try validateChildRefs(
        planned.stage_kind,
        planned.child_count,
        &planned.ordered_children,
    );
    const role = switch (planned.stage_kind) {
        .leaf_wrapper => switch (planned.node_public.node_kind) {
            .real => registry_mod.CircuitRoleV1
                .ethereum_incremental_leaf_wrapper_v4,
            .empty => registry_mod.CircuitRoleV1.canonical_empty_field_v2,
            .mixed => return error.CampaignRegistryMismatch,
        },
        .fold, .root => registry_mod.CircuitRoleV1.common_fold_field_v2,
    };
    const entry = try registry.entry(role);
    const expected_entry = try registry_mod.RegistryEntryV1.fromGeometry(
        geometry,
    );
    if (geometry.role != role or !std.meta.eql(entry.*, expected_entry))
        return error.CampaignRegistryMismatch;

    var result = CampaignSemanticInputsV2{
        .campaign_namespace_sha256 = shape.campaign_namespace_sha256,
        .campaign_shape_identity_sha256 = shape.identity_sha256,
        .stage_kind = planned.stage_kind,
        .node_kind = planned.node_public.node_kind,
        .coordinate = planned.node_public.coordinate,
        .circuit_identity_sha256 = entry.circuit_identity_sha256,
        .program_identity_sha256 = entry.program_identity_sha256,
        .profile_identity_sha256 = entry.profile_identity_sha256,
        .pcs_identity_sha256 = entry.pcs_identity_sha256,
        .padding_layout_identity_sha256 = entry
            .padding_layout_identity_sha256,
        .registry_identity_sha256 = registry.identity_sha256,
        .node_public_abi_sha256 = geometry.output_abi.node_public_abi_sha256,
        .proof_shape_identity_sha256 = geometry.proof_shape.identity_sha256,
        .statement_digest = planned.node_public.statement_digest,
        .source_digest = planned.node_public.source_digest,
        .subtree_digest = planned.node_public.subtree_digest,
        .output_digest = planned.node_public.output_digest,
        .child_count = planned.child_count,
        .ordered_children = planned.ordered_children,
        .preprocessed_root = geometry.preprocessed_root,
        .legacy_semantic_identity_sha256 = undefined,
        .identity_sha256 = undefined,
    };
    result.legacy_semantic_identity_sha256 =
        legacySemanticIdentityFromProjection(&result);
    result.identity_sha256 = campaignSemanticIdentity(&result);
    try result.validate(shape);
    return result;
}

pub fn seal(
    shape: *const CampaignShape,
    value: Artifact,
) Error!Artifact {
    var result = value;
    result.semantic_inputs_identity_sha256 = legacySemanticIdentity(&result);
    const public_bytes = try campaign_public.encodeCanonical(
        shape,
        &result.node_public,
    );
    result.field_public_transport_sha256 = sha256(&public_bytes);
    result.content_identity_sha256 = try contentIdentity(shape, &result);
    try validate(shape, &result);
    return result;
}

pub fn validate(
    shape: *const CampaignShape,
    value: *const Artifact,
) Error!void {
    try shape.validateAgainstCampaign(value.campaign_namespace_sha256);
    if (value.format_version != FORMAT_VERSION or
        value.schema_version != SCHEMA_VERSION or
        value.production_activation)
    {
        return error.CampaignArtifactMismatch;
    }
    try campaign_public.validateStageCoordinate(
        shape,
        value.stage_kind,
        value.coordinate,
    );
    if (value.node_kind != try campaign_public.expectedNodeKind(
        shape,
        value.coordinate,
    )) return error.CampaignArtifactMismatch;
    try campaign_public.validate(shape, &value.node_public);
    if (!std.meta.eql(value.coordinate, value.node_public.coordinate) or
        value.node_kind != value.node_public.node_kind)
    {
        return error.CampaignArtifactMismatch;
    }
    try value.proof_ref.validate();
    try validateChildRefs(
        value.stage_kind,
        value.child_count,
        &value.ordered_children,
    );
    const public_bytes = try campaign_public.encodeCanonical(
        shape,
        &value.node_public,
    );
    const expected_content_identity = try contentIdentity(shape, value);
    if (!std.mem.eql(
        u8,
        &value.node_public_abi_sha256,
        &field_public.abiIdentitySha256(),
    ) or !std.mem.eql(
        u8,
        &value.field_public_transport_sha256,
        &sha256(&public_bytes),
    ) or !std.mem.eql(
        u8,
        &value.semantic_inputs_identity_sha256,
        &legacySemanticIdentity(value),
    ) or !std.mem.eql(
        u8,
        &value.content_identity_sha256,
        &expected_content_identity,
    )) return error.CampaignArtifactMismatch;
    const semantic = semanticInputsUnchecked(shape, value);
    try semantic.validate(shape);
}

pub fn encodeCanonical(
    shape: *const CampaignShape,
    value: *const Artifact,
) Error![ENCODED_BYTE_COUNT]u8 {
    try validate(shape, value);
    var result: [ENCODED_BYTE_COUNT]u8 = undefined;
    var writer = Writer{ .bytes = &result };
    try writeArtifact(shape, &writer, value, true);
    std.debug.assert(writer.at == result.len);
    return result;
}

pub fn decodeCanonical(
    shape: *const CampaignShape,
    bytes: []const u8,
) Error!Artifact {
    if (bytes.len != ENCODED_BYTE_COUNT)
        return error.NonCanonicalCampaignArtifact;
    var reader = Reader{ .bytes = bytes };
    const result = Artifact{
        .format_version = try reader.u16Value(),
        .schema_version = try reader.u16Value(),
        .production_activation = try reader.boolValue(),
        .stage_kind = std.meta.intToEnum(
            StageKind,
            try reader.u8Value(),
        ) catch return error.NonCanonicalCampaignArtifact,
        .node_kind = std.meta.intToEnum(
            NodeKind,
            try reader.u8Value(),
        ) catch return error.NonCanonicalCampaignArtifact,
        .child_count = try reader.u8Value(),
        .coordinate = try readCoordinate(&reader),
        .node_public = try campaign_public.decodeCanonical(
            shape,
            try reader.take(field_public.ENCODED_BYTE_COUNT),
        ),
        .campaign_namespace_sha256 = try reader.array(32),
        .circuit_identity_sha256 = try reader.array(32),
        .program_identity_sha256 = try reader.array(32),
        .profile_identity_sha256 = try reader.array(32),
        .pcs_identity_sha256 = try reader.array(32),
        .padding_layout_identity_sha256 = try reader.array(32),
        .registry_identity_sha256 = try reader.array(32),
        .node_public_abi_sha256 = try reader.array(32),
        .proof_shape_identity_sha256 = try reader.array(32),
        .ordered_children = .{
            try readArtifactRef(&reader),
            try readArtifactRef(&reader),
        },
        .proof_ref = try readArtifactRef(&reader),
        .preprocessed_root = try reader.words(artifact_v1.DIGEST_WORD_COUNT),
        .semantic_inputs_identity_sha256 = try reader.array(32),
        .field_public_transport_sha256 = try reader.array(32),
        .content_identity_sha256 = try reader.array(32),
    };
    if (reader.at != bytes.len)
        return error.NonCanonicalCampaignArtifact;
    try validate(shape, &result);
    const canonical = try encodeCanonical(shape, &result);
    if (!std.mem.eql(u8, bytes, &canonical))
        return error.NonCanonicalCampaignArtifact;
    return result;
}

/// Campaign-aware store reopen. This authenticates transport and semantic
/// inputs only; the role-specific cold verifier must still mint freshness.
pub fn coldDecodeForStore(
    shape: *const CampaignShape,
    bytes: []const u8,
) Error!Artifact {
    return decodeCanonical(shape, bytes);
}

pub fn semanticInputsForStore(
    shape: *const CampaignShape,
    value: *const Artifact,
) Error!CampaignSemanticInputsV2 {
    try validate(shape, value);
    return semanticInputsUnchecked(shape, value);
}

pub fn artifactRef(
    shape: *const CampaignShape,
    value: *const Artifact,
) Error!ArtifactRef {
    const bytes = try encodeCanonical(shape, value);
    const result = ArtifactRef{
        .kind = artifact_v2.RECURSIVE_NODE_ARTIFACT_KIND,
        .format_version = artifact_v1.ARTIFACT_REF_FORMAT_VERSION,
        .schema_version = SCHEMA_VERSION,
        .byte_count = bytes.len,
        .sha256 = sha256(&bytes),
    };
    try result.validate();
    return result;
}

/// Registry sibling for non-legacy campaign coordinates. Geometry remains
/// role-specific and must have been minted by a genuine cold proof owner.
pub fn admitRegistry(
    registry: *const Registry,
    shape: *const CampaignShape,
    value: *const Artifact,
    geometry: *const Geometry,
) Error!void {
    try registry.validate();
    try validate(shape, value);
    try geometry.validate();
    const role = try roleForArtifact(value);
    if (geometry.role != role or !std.meta.eql(
        geometry.output_abi,
        registry_mod.OutputAbiV1.fieldNodePublicV2(),
    )) return error.CampaignRegistryMismatch;
    const registered = try registry.entry(role);
    if (!std.mem.eql(
        u8,
        &value.registry_identity_sha256,
        &registry.identity_sha256,
    ) or !std.mem.eql(
        u8,
        &value.circuit_identity_sha256,
        &registered.circuit_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &value.program_identity_sha256,
        &registered.program_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &value.profile_identity_sha256,
        &registered.profile_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &value.pcs_identity_sha256,
        &registered.pcs_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &value.padding_layout_identity_sha256,
        &registered.padding_layout_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &value.node_public_abi_sha256,
        &registered.node_public_abi_sha256,
    ) or !std.mem.eql(
        u8,
        &value.proof_shape_identity_sha256,
        &geometry.proof_shape.identity_sha256,
    ) or !std.mem.eql(
        u8,
        &geometry.authority_identity_sha256,
        &registered.geometry_authority_identity_sha256,
    ) or !std.meta.eql(
        value.preprocessed_root,
        registered.preprocessed_root,
    ) or !std.meta.eql(
        geometry.preprocessed_root,
        registered.preprocessed_root,
    )) return error.CampaignRegistryMismatch;
}

/// Worker-output sibling. It deliberately accepts an expected semantic
/// projection rather than recomputing a global campaign inventory key.
pub fn validateWorkerOutput(
    shape: *const CampaignShape,
    value: *const Artifact,
    expected: *const CampaignSemanticInputsV2,
) Error!void {
    try validate(shape, value);
    try expected.validate(shape);
    const actual = semanticInputsUnchecked(shape, value);
    if (!std.meta.eql(expected.*, actual))
        return error.CampaignWorkerOutputMismatch;
}

fn roleForArtifact(value: *const Artifact) Error!registry_mod.CircuitRoleV1 {
    return switch (value.stage_kind) {
        .leaf_wrapper => switch (value.node_kind) {
            .real => .ethereum_incremental_leaf_wrapper_v4,
            .empty => .canonical_empty_field_v2,
            .mixed => error.CampaignRegistryMismatch,
        },
        .fold, .root => .common_fold_field_v2,
    };
}

fn semanticInputsUnchecked(
    shape: *const CampaignShape,
    value: *const Artifact,
) CampaignSemanticInputsV2 {
    var result = CampaignSemanticInputsV2{
        .campaign_namespace_sha256 = value.campaign_namespace_sha256,
        .campaign_shape_identity_sha256 = shape.identity_sha256,
        .stage_kind = value.stage_kind,
        .node_kind = value.node_kind,
        .coordinate = value.coordinate,
        .circuit_identity_sha256 = value.circuit_identity_sha256,
        .program_identity_sha256 = value.program_identity_sha256,
        .profile_identity_sha256 = value.profile_identity_sha256,
        .pcs_identity_sha256 = value.pcs_identity_sha256,
        .padding_layout_identity_sha256 = value.padding_layout_identity_sha256,
        .registry_identity_sha256 = value.registry_identity_sha256,
        .node_public_abi_sha256 = value.node_public_abi_sha256,
        .proof_shape_identity_sha256 = value.proof_shape_identity_sha256,
        .statement_digest = value.node_public.statement_digest,
        .source_digest = value.node_public.source_digest,
        .subtree_digest = value.node_public.subtree_digest,
        .output_digest = value.node_public.output_digest,
        .child_count = value.child_count,
        .ordered_children = value.ordered_children,
        .preprocessed_root = value.preprocessed_root,
        .legacy_semantic_identity_sha256 = value.semantic_inputs_identity_sha256,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = campaignSemanticIdentity(&result);
    return result;
}

fn validateIdentitySet(value: *const CampaignSemanticInputsV2) Error!void {
    inline for (.{
        value.campaign_namespace_sha256,
        value.campaign_shape_identity_sha256,
        value.circuit_identity_sha256,
        value.program_identity_sha256,
        value.profile_identity_sha256,
        value.pcs_identity_sha256,
        value.padding_layout_identity_sha256,
        value.registry_identity_sha256,
        value.node_public_abi_sha256,
        value.proof_shape_identity_sha256,
        value.legacy_semantic_identity_sha256,
    }) |identity| if (std.mem.allEqual(u8, &identity, 0))
        return error.CampaignSemanticInputsMismatch;
    if (!std.mem.eql(
        u8,
        &value.node_public_abi_sha256,
        &field_public.abiIdentitySha256(),
    ) or allWordsZero(value.statement_digest) or
        allWordsZero(value.source_digest) or
        allWordsZero(value.subtree_digest) or
        allWordsZero(value.output_digest) or
        allWordsZero(value.preprocessed_root))
    {
        return error.CampaignSemanticInputsMismatch;
    }
}

fn validateChildRefs(
    stage: StageKind,
    child_count: u8,
    children: *const [artifact_v2.MAX_CHILD_COUNT]ArtifactRef,
) Error!void {
    const expected: u8 = if (stage == .leaf_wrapper) 1 else 2;
    if (child_count != expected) return error.CampaignArtifactMismatch;
    for (children[0..child_count]) |child| try child.validate();
    for (children[child_count..]) |child|
        if (!child.isZero()) return error.CampaignArtifactMismatch;
}

fn legacySemanticIdentity(value: *const Artifact) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(LEGACY_SEMANTIC_DOMAIN);
    hash.update(&value.campaign_namespace_sha256);
    hashInt(&hash, u8, @intFromEnum(value.stage_kind));
    hashInt(&hash, u8, @intFromEnum(value.node_kind));
    hashCoordinate(&hash, value.coordinate);
    inline for (.{
        value.circuit_identity_sha256,
        value.program_identity_sha256,
        value.profile_identity_sha256,
        value.pcs_identity_sha256,
        value.padding_layout_identity_sha256,
        value.registry_identity_sha256,
        value.node_public_abi_sha256,
        value.proof_shape_identity_sha256,
    }) |identity| hash.update(&identity);
    inline for (.{
        value.node_public.statement_digest,
        value.node_public.source_digest,
        value.node_public.subtree_digest,
        value.node_public.output_digest,
    }) |digest| for (digest) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u8, value.child_count);
    for (value.ordered_children) |child| hashArtifactRef(&hash, child);
    for (value.preprocessed_root) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn campaignSemanticIdentity(value: *const CampaignSemanticInputsV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CAMPAIGN_SEMANTIC_DOMAIN);
    hash.update(&value.campaign_namespace_sha256);
    hash.update(&value.campaign_shape_identity_sha256);
    hash.update(&value.legacy_semantic_identity_sha256);
    return hash.finalResult();
}

fn legacySemanticIdentityFromProjection(
    value: *const CampaignSemanticInputsV2,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(LEGACY_SEMANTIC_DOMAIN);
    hash.update(&value.campaign_namespace_sha256);
    hashInt(&hash, u8, @intFromEnum(value.stage_kind));
    hashInt(&hash, u8, @intFromEnum(value.node_kind));
    hashCoordinate(&hash, value.coordinate);
    inline for (.{
        value.circuit_identity_sha256,
        value.program_identity_sha256,
        value.profile_identity_sha256,
        value.pcs_identity_sha256,
        value.padding_layout_identity_sha256,
        value.registry_identity_sha256,
        value.node_public_abi_sha256,
        value.proof_shape_identity_sha256,
    }) |identity| hash.update(&identity);
    inline for (.{
        value.statement_digest,
        value.source_digest,
        value.subtree_digest,
        value.output_digest,
    }) |digest| for (digest) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u8, value.child_count);
    for (value.ordered_children) |child| hashArtifactRef(&hash, child);
    for (value.preprocessed_root) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn contentIdentity(
    shape: *const CampaignShape,
    value: *const Artifact,
) Error![32]u8 {
    var bytes: [ENCODED_BYTE_COUNT - 32]u8 = undefined;
    var writer = Writer{ .bytes = &bytes };
    try writeArtifact(shape, &writer, value, false);
    std.debug.assert(writer.at == bytes.len);
    var hash = Sha256.init(.{});
    hash.update(LEGACY_CONTENT_DOMAIN);
    hash.update(&bytes);
    return hash.finalResult();
}

fn writeArtifact(
    shape: *const CampaignShape,
    writer: *Writer,
    value: *const Artifact,
    include_content_identity: bool,
) Error!void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u8Value(@intFromBool(value.production_activation));
    writer.u8Value(@intFromEnum(value.stage_kind));
    writer.u8Value(@intFromEnum(value.node_kind));
    writer.u8Value(value.child_count);
    writeCoordinate(writer, value.coordinate);
    const public_bytes = try campaign_public.encodeCanonical(
        shape,
        &value.node_public,
    );
    writer.bytesValue(&public_bytes);
    inline for (.{
        value.campaign_namespace_sha256,
        value.circuit_identity_sha256,
        value.program_identity_sha256,
        value.profile_identity_sha256,
        value.pcs_identity_sha256,
        value.padding_layout_identity_sha256,
        value.registry_identity_sha256,
        value.node_public_abi_sha256,
        value.proof_shape_identity_sha256,
    }) |identity| writer.bytesValue(&identity);
    for (value.ordered_children) |child| writeArtifactRef(writer, child);
    writeArtifactRef(writer, value.proof_ref);
    for (value.preprocessed_root) |word| writer.u32Value(word);
    writer.bytesValue(&value.semantic_inputs_identity_sha256);
    writer.bytesValue(&value.field_public_transport_sha256);
    if (include_content_identity)
        writer.bytesValue(&value.content_identity_sha256);
}

fn writeCoordinate(writer: *Writer, value: TaskCoordinate) void {
    writer.u8Value(value.height);
    writer.bytesValue(&value.reserved);
    writer.u32Value(value.index);
    writer.u32Value(value.global_ordinal);
}

fn readCoordinate(reader: *Reader) Error!TaskCoordinate {
    return .{
        .height = try reader.u8Value(),
        .reserved = try reader.array(3),
        .index = try reader.u32Value(),
        .global_ordinal = try reader.u32Value(),
    };
}

fn writeArtifactRef(writer: *Writer, value: ArtifactRef) void {
    writer.u32Value(value.kind);
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u64Value(value.byte_count);
    writer.bytesValue(&value.sha256);
}

fn readArtifactRef(reader: *Reader) Error!ArtifactRef {
    return .{
        .kind = try reader.u32Value(),
        .format_version = try reader.u16Value(),
        .schema_version = try reader.u16Value(),
        .byte_count = try reader.u64Value(),
        .sha256 = try reader.array(32),
    };
}

fn hashArtifactRef(hash: *Sha256, value: ArtifactRef) void {
    hashInt(hash, u32, value.kind);
    hashInt(hash, u16, value.format_version);
    hashInt(hash, u16, value.schema_version);
    hashInt(hash, u64, value.byte_count);
    hash.update(&value.sha256);
}

fn hashCoordinate(hash: *Sha256, value: TaskCoordinate) void {
    hashInt(hash, u8, value.height);
    hash.update(&value.reserved);
    hashInt(hash, u32, value.index);
    hashInt(hash, u32, value.global_ordinal);
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

fn allWordsZero(words: [artifact_v1.DIGEST_WORD_COUNT]u32) bool {
    var aggregate: u32 = 0;
    for (words) |word| aggregate |= word;
    return aggregate == 0;
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn bytesValue(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.at..][0..value.len], value);
        self.at += value.len;
    }
    fn u8Value(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }
    fn u16Value(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.at..][0..2], value, .little);
        self.at += 2;
    }
    fn u32Value(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.at..][0..4], value, .little);
        self.at += 4;
    }
    fn u64Value(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.at..][0..8], value, .little);
        self.at += 8;
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Reader, count: usize) Error![]const u8 {
        const end = std.math.add(usize, self.at, count) catch
            return error.NonCanonicalCampaignArtifact;
        if (end > self.bytes.len)
            return error.NonCanonicalCampaignArtifact;
        const result = self.bytes[self.at..end];
        self.at = end;
        return result;
    }
    fn array(self: *Reader, comptime count: usize) Error![count]u8 {
        return (try self.take(count))[0..count].*;
    }
    fn words(self: *Reader, comptime count: usize) Error![count]u32 {
        var result: [count]u32 = undefined;
        for (&result) |*word| word.* = try self.u32Value();
        return result;
    }
    fn u8Value(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }
    fn boolValue(self: *Reader) Error!bool {
        return switch (try self.u8Value()) {
            0 => false,
            1 => true,
            else => error.NonCanonicalCampaignArtifact,
        };
    }
    fn u16Value(self: *Reader) Error!u16 {
        const bytes = try self.take(2);
        return std.mem.readInt(u16, @ptrCast(bytes.ptr), .little);
    }
    fn u32Value(self: *Reader) Error!u32 {
        const bytes = try self.take(4);
        return std.mem.readInt(u32, @ptrCast(bytes.ptr), .little);
    }
    fn u64Value(self: *Reader) Error!u64 {
        const bytes = try self.take(8);
        return std.mem.readInt(u64, @ptrCast(bytes.ptr), .little);
    }
};

comptime {
    if (PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY or
        ENCODED_BYTE_COUNT != 2380 or SCHEMA_VERSION != 2)
    {
        @compileError("campaign recursive-node V2 sibling drifted");
    }
}
