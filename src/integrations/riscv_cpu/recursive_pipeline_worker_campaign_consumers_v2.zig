//! Campaign-aware, unrouteable Stage103/Stage104 worker consumers.
//!
//! One provider supplies runtime shape/registry/geometry. Campaign validation
//! precedes every q193 cold-owned lease; no verifier capability has a codec.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_store = @import("recursive_campaign_node_artifact_store_v2.zig");
const campaign_empty =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const final_authority =
    @import("recursive_pipeline_campaign_final_remint_v2.zig");
const base_store = @import("recursive_node_artifact_store_v2.zig");
const campaign_cas =
    @import("recursive_pipeline_worker_campaign_cas_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const STAGE103_SCHEMA_VERSION: u16 =
    base_store.EMPTY_WRAPPER_STAGE_SCHEMA_VERSION;
pub const STAGE104_SCHEMA_VERSION: u16 =
    base_store.COMMON_FOLD_STAGE_SCHEMA_VERSION;
pub const OUTPUT_SCHEMA_VERSION: u16 = campaign_artifact.SCHEMA_VERSION;
pub const PROOF_SCHEMA_VERSION: u16 = campaign_cas.PROOF_SCHEMA_VERSION;
pub const STAGE_MANIFEST_SCHEMA_VERSION: u16 =
    campaign_cas.STAGE_MANIFEST_SCHEMA_VERSION;
pub const STAGE103_SOURCE_SCHEMA_VERSION: u16 = campaign_cas.SOURCE_SCHEMA_VERSION;
pub const STAGE103_SOURCE_BYTE_COUNT: u64 =
    campaign_cas.SOURCE_BYTE_COUNT;
pub const OUTPUT_BYTE_COUNT: u64 = campaign_artifact.ENCODED_BYTE_COUNT;
pub const STAGE103_DEPENDENCY_COUNT: usize = 0;
pub const STAGE104_DEPENDENCY_COUNT: usize = 2;
pub const semantic_options_schema =
    "stwo.recursive-campaign-node-options.v2";
pub const stage103_adapter_name = "campaign_canonical_empty_v2";
pub const stage104_adapter_name = "campaign_common_fold_v2";

pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const EVERY_COLD_OPEN_REQUIRES_INDEPENDENT_Q193 = true;
pub const CHILD_LEASES_BORROWED_DURING_BUILD = true;
pub const BUILD_FAILURE_RETAINS_CHILD_LEASES = true;

pub const Shape = shape_mod.CampaignShapeAuthorityV2;
pub const Registry = registry_mod.RecursiveCircuitRegistryV1;
pub const Geometry = registry_mod.AuthenticatedGeometryV1;
pub const Role = registry_mod.CircuitRoleV1;
pub const Artifact = campaign_artifact.Artifact;
pub const CampaignFinalRemintAuthorityV2 =
    final_authority.CampaignFinalRemintAuthorityV2;

pub const Error = campaign_artifact.Error || campaign_store.Error || error{
    CampaignWorkerAuthorityUnavailable,
    CampaignWorkerBackendUnavailable,
    CampaignWorkerDependencyMismatch,
    CampaignWorkerExecutionAuthorityUnavailable,
    CampaignWorkerInputMismatch,
    CampaignWorkerOutputMismatch,
    CampaignWorkerProofReferenceMismatch,
    CampaignWorkerProjectionMismatch,
};

pub const CasRoleV2 = campaign_cas.RoleV2;
pub const validateCasRef = campaign_cas.validate;

pub const StageContractV2 = struct {
    stage_kind: artifact_store.StageKindV1,
    stage_schema_version: u16,
    output_kind: artifact_store.ArtifactKindV1 = .recursion_node,
    output_schema_version: u16 = OUTPUT_SCHEMA_VERSION,
    dependency_count: u8,
    root_cold_open_transitive: bool = true,
    production: bool = false,
};

pub fn stage103Contract() StageContractV2 {
    return .{
        .stage_kind = .prove,
        .stage_schema_version = STAGE103_SCHEMA_VERSION,
        .dependency_count = STAGE103_DEPENDENCY_COUNT,
    };
}

pub fn stage104Contract() StageContractV2 {
    return .{
        .stage_kind = .fold,
        .stage_schema_version = STAGE104_SCHEMA_VERSION,
        .dependency_count = STAGE104_DEPENDENCY_COUNT,
    };
}

/// Canonical options transported through the generic worker key. The JSON
/// digest remains `SemanticKeyV1.semantic_options_identity`; the carried
/// digest independently binds the complete typed campaign projection.
pub fn semanticOptionsValueV2(
    allocator: std.mem.Allocator,
    projected: *const campaign_artifact.CampaignSemanticInputsV2,
) !protocol.Json {
    var result = protocol.jsonObject(allocator);
    try protocol.put(
        &result,
        "schema",
        protocol.string(semantic_options_schema),
    );
    try protocol.putDigest(
        allocator,
        &result,
        "campaign_semantic_inputs_identity_sha256",
        projected.identity_sha256,
    );
    return result;
}

/// Runtime authority contract:
/// - `available: bool`
/// - `finalRemintForCampaign([32]u8) !*const CampaignFinalRemintAuthorityV2`
///
/// The single returned authority supplies shape, registry, and role geometry.
/// Each extraction revalidates its shape/remint binding; this layer never
/// assembles those values from independent providers.
pub fn Stage103For(
    comptime AuthorityProvider: type,
    comptime Backend: type,
) type {
    assertAuthorityProvider(AuthorityProvider);
    assertStage103Backend(Backend);
    return struct {
        pub const available = AuthorityProvider.available and Backend.available;
        pub const production = PRODUCTION_ACTIVATION;
        pub const LeasePayload = Backend.LeasePayload;
        pub const adapter_name = stage103_adapter_name;

        pub fn describe(
            stage_kind: artifact_store.StageKindV1,
            stage_schema_version: u16,
        ) !protocol.StageDescription {
            if (stage_kind != .prove or
                stage_schema_version != STAGE103_SCHEMA_VERSION)
            {
                return error.CampaignWorkerInputMismatch;
            }
            return description(stage103Contract());
        }

        pub fn buildOutputWithLeases(
            _: std.mem.Allocator,
            _: *artifact_store.Store,
            _: protocol.Node,
            _: artifact_store.SemanticKeyV1,
            _: []const artifact_store.InputRefV1,
            _: u64,
            _: []const *const LeasePayload,
        ) ![]u8 {
            return error.CampaignWorkerExecutionAuthorityUnavailable;
        }

        pub fn buildOutputWithExecutionAndLeases(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const LeasePayload,
        ) ![]u8 {
            if (comptime !available)
                return error.CampaignWorkerBackendUnavailable;
            if (dependency_leases.len != 0)
                return error.CampaignWorkerDependencyMismatch;
            const authorities = try authoritiesFor(
                AuthorityProvider,
                semantic.fields.campaign_namespace,
                .canonical_empty_field_v2,
            );
            try validateStage103Node(node, ordered_inputs);
            const source_ref = try stage103SourceRef(ordered_inputs);
            try validateCasRef(source_ref, .stage103_source);
            var source_blob = try store.openBlob(
                source_ref,
                .source,
                campaign_empty.SCHEMA_VERSION,
                campaign_empty.SOURCE_ENCODED_BYTE_COUNT,
            );
            defer source_blob.deinit(store.allocator);
            const source = try campaign_empty.ColdInputV2.open(
                authorities.shape,
                source_blob.bytes,
            );
            var proved = try Backend.proveAndColdVerify(
                allocator,
                store,
                authorities,
                &source,
                node,
                semantic,
                execution,
                ordered_inputs,
                candidate_ordinal,
            );
            defer proved.deinit();
            try proved.validate(authorities, &source);
            const proof_bytes = proved.proofBytes();
            if (proof_bytes.len == 0)
                return error.CampaignWorkerProofReferenceMismatch;
            const proof_ref = try store.putBytes(
                .proof_artifact,
                PROOF_SCHEMA_VERSION,
                proof_bytes,
            );
            try validateProofRef(proof_ref);
            const artifact = proved.nodeArtifact();
            try validateProjection(
                allocator,
                node,
                &semantic,
                ordered_inputs,
                authorities,
                artifact,
                .canonical_empty_field_v2,
            );
            const expected_proof = try base_store.toSharedRef(
                artifact.proof_ref,
            );
            if (!artifact_store.BlobRefV1.eql(proof_ref, expected_proof))
                return error.CampaignWorkerProofReferenceMismatch;
            const bytes = try campaign_artifact.encodeCanonical(
                authorities.shape,
                artifact,
            );
            return allocator.dupe(u8, &bytes);
        }

        pub fn validateOutput(
            allocator: std.mem.Allocator,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !void {
            if (comptime !available)
                return error.CampaignWorkerBackendUnavailable;
            const authorities = try authoritiesFor(
                AuthorityProvider,
                semantic.fields.campaign_namespace,
                .canonical_empty_field_v2,
            );
            try validateStage103Node(node, ordered_inputs);
            const artifact = try campaign_artifact.decodeCanonical(
                authorities.shape,
                bytes,
            );
            try validateProjection(
                allocator,
                node,
                &semantic,
                ordered_inputs,
                authorities,
                &artifact,
                .canonical_empty_field_v2,
            );
        }

        /// A durable receipt is not reused as authority. Every new process
        /// reaches `Backend.coldOpenOwned`, which must independently q193/PCS
        /// verify before returning its nonserializable payload.
        pub fn coldOpenLease(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !LeasePayload {
            if (comptime !available)
                return error.CampaignWorkerBackendUnavailable;
            const authorities = try authoritiesFor(
                AuthorityProvider,
                semantic.fields.campaign_namespace,
                .canonical_empty_field_v2,
            );
            try validateStage103Node(node, ordered_inputs);
            const source_ref = try stage103SourceRef(ordered_inputs);
            var source_blob = try store.openBlob(
                source_ref,
                .source,
                campaign_empty.SCHEMA_VERSION,
                campaign_empty.SOURCE_ENCODED_BYTE_COUNT,
            );
            defer source_blob.deinit(store.allocator);
            const source = try campaign_empty.ColdInputV2.open(
                authorities.shape,
                source_blob.bytes,
            );
            const artifact = try campaign_artifact.decodeCanonical(
                authorities.shape,
                bytes,
            );
            try validateProjection(
                allocator,
                node,
                &semantic,
                ordered_inputs,
                authorities,
                &artifact,
                .canonical_empty_field_v2,
            );
            const proof_ref = try base_store.toSharedRef(artifact.proof_ref);
            try validateProofRef(proof_ref);
            var proof_blob = try store.openBlob(
                proof_ref,
                .proof_artifact,
                PROOF_SCHEMA_VERSION,
                campaign_cas.MAX_PROOF_BYTE_COUNT,
            );
            defer proof_blob.deinit(store.allocator);
            var result = try Backend.coldOpenOwned(
                allocator,
                store,
                authorities,
                &source,
                proof_blob.bytes,
                bytes,
            );
            errdefer Backend.deinitLeasePayload(&result);
            try Backend.validateLease(
                &result,
                authorities,
                &source,
                &artifact,
            );
            try result.validateForCampaign(authorities.final_remint);
            const projection = try result.foldProjection(
                authorities.registry,
            );
            try projection.validateAgainst(authorities.registry);
            if (projection.role != .canonical_empty_field_v2 or
                projection.geometry != authorities.geometry)
            {
                return error.CampaignWorkerProjectionMismatch;
            }
            return result;
        }

        pub fn deinitLeasePayload(
            value: *LeasePayload,
            _: std.mem.Allocator,
        ) void {
            Backend.deinitLeasePayload(value);
        }
    };
}

pub fn Stage104For(
    comptime AuthorityProvider: type,
    comptime Backend: type,
) type {
    assertAuthorityProvider(AuthorityProvider);
    assertStage104Backend(Backend);
    return struct {
        pub const available = AuthorityProvider.available and Backend.available;
        pub const production = PRODUCTION_ACTIVATION;
        pub const DependencyLease = Backend.DependencyLease;
        pub const LeasePayload = Backend.LeasePayload;
        pub const adapter_name = stage104_adapter_name;

        pub fn describe(
            stage_kind: artifact_store.StageKindV1,
            stage_schema_version: u16,
        ) !protocol.StageDescription {
            if (stage_kind != .fold or
                stage_schema_version != STAGE104_SCHEMA_VERSION)
            {
                return error.CampaignWorkerInputMismatch;
            }
            return description(stage104Contract());
        }

        pub fn buildOutputWithLeases(
            _: std.mem.Allocator,
            _: *artifact_store.Store,
            _: protocol.Node,
            _: artifact_store.SemanticKeyV1,
            _: []const artifact_store.InputRefV1,
            _: u64,
            _: []const *const DependencyLease,
        ) ![]u8 {
            return error.CampaignWorkerExecutionAuthorityUnavailable;
        }

        pub fn buildOutputWithExecutionAndLeases(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const DependencyLease,
        ) ![]u8 {
            if (comptime !available)
                return error.CampaignWorkerBackendUnavailable;
            const authorities = try authoritiesFor(
                AuthorityProvider,
                semantic.fields.campaign_namespace,
                .common_fold_field_v2,
            );
            try validateStage104Node(node, ordered_inputs);
            if (dependency_leases.len != STAGE104_DEPENDENCY_COUNT)
                return error.CampaignWorkerDependencyMismatch;
            try Backend.validateBorrowedChildren(
                dependency_leases,
                authorities,
                ordered_inputs,
            );
            for (dependency_leases) |lease| {
                try lease.validateAgainst(authorities.final_remint);
                _ = try lease.foldProjection(authorities.final_remint);
            }
            var proved = try Backend.proveAndColdVerify(
                allocator,
                store,
                authorities,
                node,
                semantic,
                execution,
                ordered_inputs,
                candidate_ordinal,
                dependency_leases,
            );
            defer proved.deinit();
            try proved.validate(authorities, dependency_leases);
            const proof_bytes = proved.proofBytes();
            if (proof_bytes.len == 0)
                return error.CampaignWorkerProofReferenceMismatch;
            const proof_ref = try store.putBytes(
                .proof_artifact,
                PROOF_SCHEMA_VERSION,
                proof_bytes,
            );
            try validateProofRef(proof_ref);
            const artifact = proved.nodeArtifact();
            try validateProjection(
                allocator,
                node,
                &semantic,
                ordered_inputs,
                authorities,
                artifact,
                .common_fold_field_v2,
            );
            const expected_proof = try base_store.toSharedRef(
                artifact.proof_ref,
            );
            if (!artifact_store.BlobRefV1.eql(proof_ref, expected_proof))
                return error.CampaignWorkerProofReferenceMismatch;
            const encoded = try campaign_artifact.encodeCanonical(
                authorities.shape,
                artifact,
            );
            return allocator.dupe(u8, &encoded);
        }

        pub fn validateOutput(
            allocator: std.mem.Allocator,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !void {
            if (comptime !available)
                return error.CampaignWorkerBackendUnavailable;
            const authorities = try authoritiesFor(
                AuthorityProvider,
                semantic.fields.campaign_namespace,
                .common_fold_field_v2,
            );
            try validateStage104Node(node, ordered_inputs);
            const artifact = try campaign_artifact.decodeCanonical(
                authorities.shape,
                bytes,
            );
            try validateProjection(
                allocator,
                node,
                &semantic,
                ordered_inputs,
                authorities,
                &artifact,
                .common_fold_field_v2,
            );
        }

        pub fn coldOpenLease(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !LeasePayload {
            if (comptime !available)
                return error.CampaignWorkerBackendUnavailable;
            const authorities = try authoritiesFor(
                AuthorityProvider,
                semantic.fields.campaign_namespace,
                .common_fold_field_v2,
            );
            try validateStage104Node(node, ordered_inputs);
            const artifact = try campaign_artifact.decodeCanonical(
                authorities.shape,
                bytes,
            );
            try validateProjection(
                allocator,
                node,
                &semantic,
                ordered_inputs,
                authorities,
                &artifact,
                .common_fold_field_v2,
            );
            const proof_ref = try base_store.toSharedRef(artifact.proof_ref);
            try validateProofRef(proof_ref);
            var proof_blob = try store.openBlob(
                proof_ref,
                .proof_artifact,
                PROOF_SCHEMA_VERSION,
                campaign_cas.MAX_PROOF_BYTE_COUNT,
            );
            defer proof_blob.deinit(store.allocator);
            var result = try Backend.coldOpenOwned(
                allocator,
                store,
                authorities,
                node,
                semantic,
                ordered_inputs,
                proof_blob.bytes,
                bytes,
            );
            errdefer Backend.deinitLeasePayload(&result);
            try Backend.validateLease(&result, authorities, &artifact);
            try result.validateForCampaign(authorities.final_remint);
            const projection = try result.foldProjection(
                authorities.registry,
            );
            try projection.validateAgainst(authorities.registry);
            if (projection.role != .common_fold_field_v2 or
                projection.geometry != authorities.geometry)
            {
                return error.CampaignWorkerProjectionMismatch;
            }
            return result;
        }

        pub fn deinitLeasePayload(
            value: *LeasePayload,
            _: std.mem.Allocator,
        ) void {
            Backend.deinitLeasePayload(value);
        }
    };
}

pub const AuthoritiesV2 = struct {
    final_remint: *const CampaignFinalRemintAuthorityV2,
    shape: *const Shape,
    registry: *const Registry,
    geometry: *const Geometry,

    pub fn validate(self: AuthoritiesV2, role: Role) !void {
        try self.final_remint.validateAgainstCampaign(
            self.shape.campaign_namespace_sha256,
        );
        try self.shape.validate();
        try self.registry.validate();
        try self.geometry.validate();
        const expected_registry =
            try self.final_remint.registryAuthority();
        const expected_geometry =
            try self.final_remint.geometryForRole(role);
        if (self.shape != self.final_remint.shape or
            self.registry != expected_registry or
            self.geometry != expected_geometry or self.geometry.role != role)
        {
            return error.CampaignWorkerAuthorityUnavailable;
        }
    }
};

/// Seal-last helper shared by campaign Stage103 and Stage104. It publishes no
/// verifier capability: only the canonical node and StageManifest refs.
pub fn publishCommittedOutput(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    authorities: AuthoritiesV2,
    role: Role,
    artifact: *const Artifact,
    keys: *const campaign_store.OwnedPublishedStageKeysV1,
    dependency_manifest_ids: []const artifact_store.Digest,
    validation_receipts: []const artifact_store.ValidationReceiptRefV1,
    profile_receipts: []const artifact_store.ProfileReceiptRefV1,
) !struct {
    output_ref: artifact_store.BlobRefV1,
    manifest: campaign_store.PublishedStageManifestV1,
} {
    try authorities.validate(role);
    try campaign_artifact.admitRegistry(
        authorities.registry,
        authorities.shape,
        artifact,
        authorities.geometry,
    );
    const output_ref = try campaign_store.publishRecursiveNode(
        store,
        authorities.shape,
        artifact,
    );
    try validateCasRef(output_ref, .recursion_node);
    const manifest = try campaign_store.createAndPublishStageManifest(
        allocator,
        store,
        authorities.shape,
        artifact,
        output_ref,
        keys,
        dependency_manifest_ids,
        validation_receipts,
        profile_receipts,
    );
    try validateCasRef(manifest.ref, .stage_manifest);
    return .{ .output_ref = output_ref, .manifest = manifest };
}

fn authoritiesFor(
    comptime Provider: type,
    campaign_namespace: [32]u8,
    role: Role,
) !AuthoritiesV2 {
    if (comptime !Provider.available)
        return error.CampaignWorkerAuthorityUnavailable;
    const final_remint = try Provider.finalRemintForCampaign(
        campaign_namespace,
    );
    try final_remint.validateAgainstCampaign(campaign_namespace);
    const result = AuthoritiesV2{
        .final_remint = final_remint,
        .shape = final_remint.shape,
        .registry = try final_remint.registryAuthority(),
        .geometry = try final_remint.geometryForRole(role),
    };
    try result.shape.validateAgainstCampaign(campaign_namespace);
    try result.validate(role);
    return result;
}

fn description(contract: StageContractV2) protocol.StageDescription {
    return .{
        .stage_kind = contract.stage_kind,
        .stage_schema_version = contract.stage_schema_version,
        .output_kind = contract.output_kind,
        .output_schema_version = contract.output_schema_version,
        .minimum_cpu_tokens = 1,
        .minimum_rss_tokens = 1,
        .root_cold_open_transitive = true,
    };
}

fn validateStage103Node(
    node: protocol.Node,
    ordered_inputs: []const artifact_store.InputRefV1,
) !void {
    if (node.stage_kind != .prove or
        node.stage_schema_version != STAGE103_SCHEMA_VERSION or
        node.dependencies.len != STAGE103_DEPENDENCY_COUNT or
        node.external_inputs.len != 1 or ordered_inputs.len != 1 or
        node.output_kind != .recursion_node or
        node.output_schema_version != OUTPUT_SCHEMA_VERSION or
        !std.meta.eql(node.external_inputs[0], ordered_inputs[0]))
    {
        return error.CampaignWorkerInputMismatch;
    }
    _ = try stage103SourceRef(ordered_inputs);
}

fn stage103SourceRef(
    ordered_inputs: []const artifact_store.InputRefV1,
) !artifact_store.BlobRefV1 {
    if (ordered_inputs.len != 1 or ordered_inputs[0].role != .direct or
        ordered_inputs[0].ordinal != 0 or
        ordered_inputs[0].blob.kind != .source or
        ordered_inputs[0].blob.schema_version != campaign_empty.SCHEMA_VERSION or
        ordered_inputs[0].blob.byte_count !=
            campaign_empty.SOURCE_ENCODED_BYTE_COUNT)
    {
        return error.CampaignWorkerInputMismatch;
    }
    try ordered_inputs[0].blob.validate();
    return ordered_inputs[0].blob;
}

fn validateStage104Node(
    node: protocol.Node,
    ordered_inputs: []const artifact_store.InputRefV1,
) !void {
    if (node.stage_kind != .fold or
        node.stage_schema_version != STAGE104_SCHEMA_VERSION or
        node.dependencies.len != STAGE104_DEPENDENCY_COUNT or
        node.external_inputs.len != 0 or
        ordered_inputs.len != STAGE104_DEPENDENCY_COUNT or
        node.output_kind != .recursion_node or
        node.output_schema_version != OUTPUT_SCHEMA_VERSION)
    {
        return error.CampaignWorkerInputMismatch;
    }
    const roles = [_]artifact_store.InputRoleV1{ .child_left, .child_right };
    for (node.dependencies, ordered_inputs, roles) |dependency, input, role| {
        if (dependency.role != @intFromEnum(role) or
            dependency.ordinal != 0 or input.role != role or
            input.ordinal != 0)
        {
            return error.CampaignWorkerDependencyMismatch;
        }
        try validateNodeRef(input.blob);
    }
}

fn validateProjection(
    allocator: std.mem.Allocator,
    node: protocol.Node,
    semantic: *const artifact_store.SemanticKeyV1,
    ordered_inputs: []const artifact_store.InputRefV1,
    authorities: AuthoritiesV2,
    artifact: *const Artifact,
    role: Role,
) !void {
    try authorities.validate(role);
    try campaign_artifact.validate(authorities.shape, artifact);
    try campaign_artifact.admitRegistry(
        authorities.registry,
        authorities.shape,
        artifact,
        authorities.geometry,
    );
    const projected = try campaign_artifact.semanticInputsForStore(
        authorities.shape,
        artifact,
    );
    try validateSemanticProjectionV2(
        allocator,
        authorities.shape,
        node,
        semantic,
        ordered_inputs,
        &projected,
    );
    const local_task = try campaign_store.localTaskIdentity(
        authorities.shape,
        &projected,
    );
    if (!std.mem.eql(
        u8,
        &node.local_task_identity_sha256,
        &local_task,
    ) or ordered_inputs.len != projected.child_count)
        return error.CampaignWorkerProjectionMismatch;
    for (ordered_inputs, projected.ordered_children[0..projected.child_count]) |
        input,
        child,
    | {
        const expected = try base_store.toSharedRef(child);
        if (!artifact_store.BlobRefV1.eql(input.blob, expected))
            return error.CampaignWorkerProjectionMismatch;
    }
    switch (role) {
        .canonical_empty_field_v2 => if (artifact.stage_kind != .leaf_wrapper or
            artifact.node_kind != .empty or artifact.child_count != 1)
        {
            return error.CampaignWorkerOutputMismatch;
        },
        .common_fold_field_v2 => if ((artifact.stage_kind != .fold and
            artifact.stage_kind != .root) or artifact.child_count != 2)
        {
            return error.CampaignWorkerOutputMismatch;
        },
        .ethereum_incremental_leaf_wrapper_v4 => return error.CampaignWorkerAuthorityUnavailable,
    }
}

/// Exact bridge between generic-worker JSON keying and the typed campaign
/// store projection. Neither identity is substituted for the other.
pub fn validateSemanticProjectionV2(
    allocator: std.mem.Allocator,
    shape: *const Shape,
    node: protocol.Node,
    semantic: *const artifact_store.SemanticKeyV1,
    ordered_inputs: []const artifact_store.InputRefV1,
    projected: *const campaign_artifact.CampaignSemanticInputsV2,
) !void {
    try projected.validate(shape);
    try semantic.validate(allocator);
    const expected_stage_schema = try campaign_store.stageSchemaVersion(
        shape,
        projected,
    );
    if (expected_stage_schema == STAGE103_SCHEMA_VERSION) {
        try validateStage103Node(node, ordered_inputs);
    } else if (expected_stage_schema == STAGE104_SCHEMA_VERSION) {
        try validateStage104Node(node, ordered_inputs);
    } else return error.CampaignWorkerProjectionMismatch;

    const options = protocol.objectValue(node.semantic_options) catch
        return error.CampaignWorkerProjectionMismatch;
    protocol.exactKeys(options, &.{
        "schema",
        "campaign_semantic_inputs_identity_sha256",
    }) catch return error.CampaignWorkerProjectionMismatch;
    const options_schema = protocol.stringField(options, "schema") catch
        return error.CampaignWorkerProjectionMismatch;
    const projected_identity = protocol.digestField(
        options,
        "campaign_semantic_inputs_identity_sha256",
        true,
    ) catch return error.CampaignWorkerProjectionMismatch;
    if (!std.mem.eql(u8, options_schema, semantic_options_schema) or
        !std.mem.eql(
            u8,
            &projected_identity,
            &projected.identity_sha256,
        )) return error.CampaignWorkerProjectionMismatch;

    const options_identity = try protocol.canonicalDigest(
        allocator,
        node.semantic_options,
    );
    const local_task = try campaign_store.localTaskIdentity(shape, projected);
    const statement = try campaign_store.statementCacheIdentity(
        shape,
        projected,
    );
    const security = base_store.security.ProofSecurityV1
        .recursiveParentSecure();
    const fields = semantic.fields;
    if (fields.stage_kind != campaign_store.sharedStageKind(
        projected.stage_kind,
    ) or fields.stage_schema_version != expected_stage_schema or
        !std.mem.eql(
            u8,
            &fields.campaign_namespace,
            &projected.campaign_namespace_sha256,
        ) or !std.mem.eql(
        u8,
        &fields.local_task_identity,
        &local_task,
    ) or !std.mem.eql(
        u8,
        &node.local_task_identity_sha256,
        &local_task,
    ) or !std.mem.eql(
        u8,
        &fields.protocol_identity,
        &projected.circuit_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.program_identity,
        &projected.program_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.profile_identity,
        &projected.profile_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.pcs_identity,
        &projected.pcs_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.security_identity,
        &security.identity,
    ) or !std.mem.eql(
        u8,
        &fields.statement_identity,
        &statement,
    ) or !artifact_store.encoding.isZeroDigest(fields.provider_identity) or
        !std.mem.eql(
            u8,
            &fields.layout_identity,
            &projected.padding_layout_identity_sha256,
        ) or !std.mem.eql(
        u8,
        &fields.registry_identity,
        &projected.registry_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.semantic_options_identity,
        &options_identity,
    ) or !semanticAuthoritiesEqual(node.semantic_authorities, fields) or
        fields.ordered_inputs.len != ordered_inputs.len)
    {
        return error.CampaignWorkerProjectionMismatch;
    }
    for (fields.ordered_inputs, ordered_inputs) |actual, expected| {
        if (!std.meta.eql(actual, expected))
            return error.CampaignWorkerProjectionMismatch;
    }
    if (ordered_inputs.len != projected.child_count)
        return error.CampaignWorkerProjectionMismatch;
    for (ordered_inputs, projected.ordered_children[0..projected.child_count]) |
        actual,
        expected,
    | if (!artifact_store.BlobRefV1.eql(
        actual.blob,
        try base_store.toSharedRef(expected),
    )) return error.CampaignWorkerProjectionMismatch;
}

fn semanticAuthoritiesEqual(
    node: protocol.SemanticAuthorities,
    fields: artifact_store.SemanticKeyFieldsV1,
) bool {
    return std.mem.eql(
        u8,
        &node.protocol_identity_sha256,
        &fields.protocol_identity,
    ) and std.mem.eql(
        u8,
        &node.program_identity_sha256,
        &fields.program_identity,
    ) and std.mem.eql(
        u8,
        &node.profile_identity_sha256,
        &fields.profile_identity,
    ) and std.mem.eql(
        u8,
        &node.pcs_identity_sha256,
        &fields.pcs_identity,
    ) and std.mem.eql(
        u8,
        &node.security_identity_sha256,
        &fields.security_identity,
    ) and std.mem.eql(
        u8,
        &node.statement_identity_sha256,
        &fields.statement_identity,
    ) and std.mem.eql(
        u8,
        &node.provider_identity_sha256,
        &fields.provider_identity,
    ) and std.mem.eql(
        u8,
        &node.layout_identity_sha256,
        &fields.layout_identity,
    ) and std.mem.eql(
        u8,
        &node.registry_identity_sha256,
        &fields.registry_identity,
    );
}

fn validateProofRef(ref: artifact_store.BlobRefV1) !void {
    try validateCasRef(ref, .proof);
}

fn validateNodeRef(ref: artifact_store.BlobRefV1) !void {
    try validateCasRef(ref, .recursion_node);
}

fn assertAuthorityProvider(comptime Provider: type) void {
    inline for (.{ "available", "finalRemintForCampaign" }) |name| if (!@hasDecl(Provider, name))
        @compileError("campaign worker authority provider missing " ++ name);
}

fn assertStage103Backend(comptime Backend: type) void {
    inline for (.{
        "available",
        "LeasePayload",
        "proveAndColdVerify",
        "coldOpenOwned",
        "validateLease",
        "deinitLeasePayload",
    }) |name| if (!@hasDecl(Backend, name))
        @compileError("campaign Stage103 backend missing " ++ name);
    assertRoleLeaseContract(
        Backend.LeasePayload,
        .canonical_empty_field_v2,
    );
}

fn assertStage104Backend(comptime Backend: type) void {
    inline for (.{
        "available",
        "DependencyLease",
        "LeasePayload",
        "validateBorrowedChildren",
        "proveAndColdVerify",
        "coldOpenOwned",
        "validateLease",
        "deinitLeasePayload",
    }) |name| if (!@hasDecl(Backend, name))
        @compileError("campaign Stage104 backend missing " ++ name);
    if (!@hasDecl(Backend.DependencyLease, "foldProjection"))
        @compileError(
            "campaign Stage104 dependency lease missing foldProjection",
        );
    if (!@hasDecl(Backend.DependencyLease, "validateAgainst"))
        @compileError(
            "campaign Stage104 dependency lease missing validateAgainst",
        );
    assertRoleLeaseContract(
        Backend.LeasePayload,
        .common_fold_field_v2,
    );
}

fn assertRoleLeaseContract(comptime Lease: type, comptime role: Role) void {
    if (!@hasDecl(Lease, "ROLE") or Lease.ROLE != role)
        @compileError("campaign worker output lease has wrong role");
    inline for (.{ "validateForCampaign", "foldProjection" }) |name|
        if (!@hasDecl(Lease, name))
            @compileError("campaign worker output lease missing " ++ name);
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(Lease, name))
            @compileError("campaign worker output lease gained a codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        STAGE103_SCHEMA_VERSION != 103 or STAGE104_SCHEMA_VERSION != 104 or
        OUTPUT_SCHEMA_VERSION != 2 or OUTPUT_BYTE_COUNT != 2380 or
        STAGE_MANIFEST_SCHEMA_VERSION != 1 or
        STAGE103_SOURCE_SCHEMA_VERSION != 2 or
        STAGE103_SOURCE_BYTE_COUNT != 1892 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        !EVERY_COLD_OPEN_REQUIRES_INDEPENDENT_Q193 or
        !CHILD_LEASES_BORROWED_DURING_BUILD or
        !BUILD_FAILURE_RETAINS_CHILD_LEASES)
    {
        @compileError("campaign Stage103/104 consumer contract drifted");
    }
}
