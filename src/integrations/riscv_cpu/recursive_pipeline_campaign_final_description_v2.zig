//! Zig-owned Stage103/Stage104 controller descriptions for a final campaign.
//!
//! A description carries the exact worker node, semantic key, execution key,
//! and CAS inputs derived from one authenticated runtime campaign.  It never
//! carries a verifier capability or a live worker lease selector.  Stage104
//! planning is incremental: both children must first be cold-opened through a
//! process-local binder satisfying `BoundChildContractV2`.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const support = @import("recursive_pipeline_worker_support_v1.zig");
const consumers = @import("recursive_pipeline_worker_campaign_consumers_v2.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const campaign_store = @import("recursive_campaign_node_artifact_store_v2.zig");
const campaign_cas = @import("recursive_pipeline_worker_campaign_cas_v2.zig");
const empty_source = @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT = "stwo.recursive-pipeline.campaign-final-stage-description.v2";
pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const SERIALIZABLE_LIVE_LEASE_SELECTOR = false;
pub const STAGE104_IS_INCREMENTAL = true;

pub const FinalRemint = final_mod.CampaignFinalRemintAuthorityV2;
pub const Policy = policy_mod.PolicyV2;
pub const Artifact = campaign_artifact.Artifact;
pub const PlannedSemantic = campaign_artifact.CampaignSemanticInputsV2;

const DESCRIPTION_DOMAIN =
    "stwo-zig/recursive-pipeline-campaign-final-description/v2\x00";

pub const Error = error{
    CampaignFinalDescriptionChildMismatch,
    CampaignFinalDescriptionIdentityMismatch,
    CampaignFinalDescriptionInputMismatch,
    CampaignFinalDescriptionLeaseUnavailable,
    CampaignFinalDescriptionNodeMismatch,
    CampaignFinalDescriptionPolicyMismatch,
};

/// Heap-stable owner for every slice referenced by `node` and `semantic`.
/// The owner is controller metadata only; the worker independently derives
/// and validates the same keys before proving or cold-opening anything.
pub const OwnedStageDescriptionV2 = struct {
    backing_allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    final_remint: *const FinalRemint,
    policy: *const Policy,
    execution_authorities: protocol.ExecutionAuthorities,
    planned_semantic: PlannedSemantic,
    planned_node_public: campaign_artifact.NodePublic,
    node: protocol.Node,
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
    ordered_inputs: []const artifact_store.InputRefV1,
    dependency_stage_manifest_refs: []const artifact_store.BlobRefV1,
    identity_sha256: artifact_store.Digest,

    pub fn deinit(self: *OwnedStageDescriptionV2) void {
        const backing_allocator = self.backing_allocator;
        self.arena.deinit();
        self.* = undefined;
        backing_allocator.destroy(self);
    }

    pub fn validate(
        self: *const OwnedStageDescriptionV2,
        scratch: std.mem.Allocator,
    ) !void {
        try self.final_remint.validateAgainstCampaign(
            self.planned_semantic.campaign_namespace_sha256,
        );
        try self.policy.validate();
        const shape = self.final_remint.shape;
        const registry = try self.final_remint.registryAuthority();
        const role = try roleForPlanned(&self.planned_semantic);
        const geometry = try self.final_remint.geometryForRole(role);
        const expected = try campaign_artifact.semanticInputsForPlannedNode(
            shape,
            registry,
            geometry,
            .{
                .stage_kind = self.planned_semantic.stage_kind,
                .node_public = self.planned_node_public,
                .child_count = self.planned_semantic.child_count,
                .ordered_children = self.planned_semantic.ordered_children,
            },
        );
        if (!std.meta.eql(expected, self.planned_semantic))
            return error.CampaignFinalDescriptionIdentityMismatch;
        try artifact_store.types.validateOrderedInputs(self.ordered_inputs);
        try support.validateKeys(
            scratch,
            self.node,
            self.ordered_inputs,
            self.semantic,
            self.execution,
        );
        try consumers.validateSemanticProjectionV2(
            scratch,
            shape,
            self.node,
            &self.semantic,
            self.ordered_inputs,
            &self.planned_semantic,
        );
        try self.policy.validateAgainstExecution(self.execution);
        const expected_execution = try artifact_store.ExecutionKeyV1.create(
            self.execution_authorities.fields(self.semantic.identity),
        );
        if (!std.meta.eql(expected_execution, self.execution) or
            self.node.cpu_tokens != self.policy.cpu_tokens_per_node or
            self.node.rss_tokens != self.policy.rss_bytes_per_node)
        {
            return error.CampaignFinalDescriptionPolicyMismatch;
        }
        switch (self.planned_semantic.stage_kind) {
            .leaf_wrapper => try self.validateStage103(scratch),
            .fold, .root => try self.validateStage104(scratch),
        }
        if (!std.mem.eql(
            u8,
            &self.identity_sha256,
            &descriptionIdentity(self),
        )) return error.CampaignFinalDescriptionIdentityMismatch;
    }

    pub fn encodeCanonicalJsonAlloc(
        self: *const OwnedStageDescriptionV2,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        try self.validate(allocator);
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const temporary = arena.allocator();
        var root = protocol.jsonObject(temporary);
        try protocol.put(&root, "format", protocol.string(FORMAT));
        try protocol.put(
            &root,
            "format_version",
            protocol.integer(FORMAT_VERSION),
        );
        try protocol.put(
            &root,
            "schema_version",
            protocol.integer(SCHEMA_VERSION),
        );
        try protocol.put(&root, "production", .{ .bool = false });
        try protocol.put(
            &root,
            "serializable_fresh_capability",
            .{ .bool = false },
        );
        try protocol.putDigest(
            temporary,
            &root,
            "campaign_namespace_sha256",
            self.planned_semantic.campaign_namespace_sha256,
        );
        try protocol.putDigest(
            temporary,
            &root,
            "campaign_shape_identity_sha256",
            self.planned_semantic.campaign_shape_identity_sha256,
        );
        try protocol.putDigest(
            temporary,
            &root,
            "final_remint_binding_identity_sha256",
            self.final_remint.binding_identity_sha256,
        );
        try protocol.putDigest(
            temporary,
            &root,
            "registry_identity_sha256",
            self.planned_semantic.registry_identity_sha256,
        );
        try protocol.putDigest(
            temporary,
            &root,
            "planned_semantic_identity_sha256",
            self.planned_semantic.identity_sha256,
        );
        try protocol.putDigest(
            temporary,
            &root,
            "semantic_key_identity_sha256",
            self.semantic.identity,
        );
        try protocol.putDigest(
            temporary,
            &root,
            "execution_key_identity_sha256",
            self.execution.identity,
        );
        try protocol.putDigest(
            temporary,
            &root,
            "description_identity_sha256",
            self.identity_sha256,
        );
        try protocol.put(&root, "node", try nodeJson(temporary, self.node));
        var inputs = protocol.array(temporary);
        for (self.ordered_inputs) |input|
            try protocol.append(&inputs, try inputJson(temporary, input));
        try protocol.put(&root, "ordered_inputs", inputs);
        var manifests = protocol.array(temporary);
        for (self.dependency_stage_manifest_refs) |ref|
            try protocol.append(&manifests, try blobRefJson(temporary, ref));
        try protocol.put(
            &root,
            "dependency_stage_manifest_refs",
            manifests,
        );
        try protocol.sealObject(temporary, &root);
        return protocol.canonicalAlloc(allocator, root, false);
    }

    fn validateStage103(
        self: *const OwnedStageDescriptionV2,
        scratch: std.mem.Allocator,
    ) !void {
        if (self.planned_semantic.node_kind != .empty or
            self.node.stage_kind != .prove or
            self.node.stage_schema_version != consumers.STAGE103_SCHEMA_VERSION or
            !std.mem.eql(u8, self.node.adapter, consumers.stage103_adapter_name) or
            self.node.dependencies.len != 0 or
            self.node.external_inputs.len != 1 or
            self.ordered_inputs.len != 1 or
            self.dependency_stage_manifest_refs.len != 0)
        {
            return error.CampaignFinalDescriptionNodeMismatch;
        }
        try campaign_cas.validate(
            self.ordered_inputs[0].blob,
            .stage103_source,
        );
        const expected_id = try std.fmt.allocPrint(
            scratch,
            "empty/{d}",
            .{self.planned_semantic.coordinate.index},
        );
        defer scratch.free(expected_id);
        if (!std.mem.eql(u8, self.node.node_id, expected_id))
            return error.CampaignFinalDescriptionNodeMismatch;
    }

    fn validateStage104(
        self: *const OwnedStageDescriptionV2,
        scratch: std.mem.Allocator,
    ) !void {
        if (self.node.stage_kind != .fold or
            self.node.stage_schema_version != consumers.STAGE104_SCHEMA_VERSION or
            !std.mem.eql(u8, self.node.adapter, consumers.stage104_adapter_name) or
            self.node.dependencies.len != 2 or
            self.node.external_inputs.len != 0 or
            self.ordered_inputs.len != 2 or
            self.dependency_stage_manifest_refs.len != 2)
        {
            return error.CampaignFinalDescriptionNodeMismatch;
        }
        for (self.ordered_inputs) |input|
            try campaign_cas.validate(input.blob, .recursion_node);
        for (self.dependency_stage_manifest_refs) |ref|
            try campaign_cas.validate(ref, .stage_manifest);
        const expected_id = try std.fmt.allocPrint(
            scratch,
            "fold/{d}/{d}",
            .{
                self.planned_semantic.coordinate.height,
                self.planned_semantic.coordinate.index,
            },
        );
        defer scratch.free(expected_id);
        if (!std.mem.eql(u8, self.node.node_id, expected_id))
            return error.CampaignFinalDescriptionNodeMismatch;
    }
};

pub fn describeStage103(
    backing_allocator: std.mem.Allocator,
    final_remint: *const FinalRemint,
    policy: *const Policy,
    execution_authorities: protocol.ExecutionAuthorities,
    source_ref: artifact_store.BlobRefV1,
    source: *const empty_source.ColdInputV2,
) !*OwnedStageDescriptionV2 {
    try final_remint.validateAgainstCampaign(
        final_remint.shape.campaign_namespace_sha256,
    );
    try policy.validate();
    const source_bytes = try source.source.encodeCanonical(&source.shape);
    try source.validate(&source_bytes);
    if (!std.meta.eql(source.shape, final_remint.shape.*))
        return error.CampaignFinalDescriptionInputMismatch;
    const source_artifact_ref = try source.source.artifactRef(&source.shape);
    const expected_source_ref = try node_store.toSharedRef(source_artifact_ref);
    if (!artifact_store.BlobRefV1.eql(source_ref, expected_source_ref))
        return error.CampaignFinalDescriptionInputMismatch;
    try campaign_cas.validate(source_ref, .stage103_source);
    const planned = campaign_artifact.PlannedSemanticNodeV2{
        .stage_kind = .leaf_wrapper,
        .node_public = source.node_public,
        .child_count = 1,
        .ordered_children = .{
            source_artifact_ref,
            campaign_artifact.ArtifactRef.zero(),
        },
    };
    const registry = try final_remint.registryAuthority();
    const geometry = try final_remint.geometryForRole(
        .canonical_empty_field_v2,
    );
    const projected = try campaign_artifact.semanticInputsForPlannedNode(
        final_remint.shape,
        registry,
        geometry,
        planned,
    );
    const inputs = [_]artifact_store.InputRefV1{.{
        .role = .direct,
        .ordinal = 0,
        .blob = source_ref,
    }};
    const no_dependencies = [_]protocol.Dependency{};
    const no_manifests = [_]artifact_store.BlobRefV1{};
    const node_id = try std.fmt.allocPrint(
        backing_allocator,
        "empty/{d}",
        .{source.node_public.coordinate.index},
    );
    defer backing_allocator.free(node_id);
    return initOwned(
        backing_allocator,
        final_remint,
        policy,
        execution_authorities,
        projected,
        source.node_public,
        node_id,
        consumers.stage103_adapter_name,
        &no_dependencies,
        &inputs,
        &inputs,
        &no_manifests,
    );
}

/// Structural contract consumed from Mill's process-local live receipt
/// binder.  The concrete type is deliberately a comptime parameter; no
/// nominal child is cast into another role and no `anyopaque` is admitted.
pub fn DescriberFor(
    comptime LeftBoundChild: type,
    comptime RightBoundChild: type,
) type {
    assertBoundChild(LeftBoundChild);
    assertBoundChild(RightBoundChild);
    return struct {
        pub fn describeStage104(
            backing_allocator: std.mem.Allocator,
            final_remint: *const FinalRemint,
            policy: *const Policy,
            execution_authorities: protocol.ExecutionAuthorities,
            left: *const LeftBoundChild,
            right: *const RightBoundChild,
        ) !*OwnedStageDescriptionV2 {
            try left.validate();
            try right.validate();
            const left_lease = left.liveLeaseSelector();
            const right_lease = right.liveLeaseSelector();
            if (left_lease.len == 0 or right_lease.len == 0 or
                std.mem.eql(u8, left_lease, right_lease))
            {
                return error.CampaignFinalDescriptionLeaseUnavailable;
            }
            try final_remint.validateAgainstCampaign(
                final_remint.shape.campaign_namespace_sha256,
            );
            try policy.validate();
            const shape = final_remint.shape;
            const left_artifact = left.nodeArtifact();
            const right_artifact = right.nodeArtifact();
            try validateChild(final_remint, left_artifact, left.outputRef());
            try validateChild(final_remint, right_artifact, right.outputRef());
            if (left.node() == right.node() or
                left_artifact == right_artifact or
                left_artifact.coordinate.height !=
                    right_artifact.coordinate.height or
                left_artifact.coordinate.index % 2 != 0 or
                right_artifact.coordinate.index !=
                    left_artifact.coordinate.index + 1)
            {
                return error.CampaignFinalDescriptionChildMismatch;
            }
            const parent_height = std.math.add(
                u8,
                left_artifact.coordinate.height,
                1,
            ) catch return error.CampaignFinalDescriptionChildMismatch;
            const parent_coordinate = try campaign_public.coordinate(
                shape,
                parent_height,
                left_artifact.coordinate.index / 2,
            );
            const node_public = try campaign_public.initParent(
                shape,
                &left_artifact.node_public,
                &right_artifact.node_public,
                parent_coordinate,
            );
            const stage_kind: campaign_artifact.StageKind =
                if (parent_height == shape.root_height) .root else .fold;
            const left_ref = try campaign_artifact.artifactRef(
                shape,
                left_artifact,
            );
            const right_ref = try campaign_artifact.artifactRef(
                shape,
                right_artifact,
            );
            const planned = campaign_artifact.PlannedSemanticNodeV2{
                .stage_kind = stage_kind,
                .node_public = node_public,
                .child_count = 2,
                .ordered_children = .{ left_ref, right_ref },
            };
            const registry = try final_remint.registryAuthority();
            const geometry = try final_remint.geometryForRole(
                .common_fold_field_v2,
            );
            const projected = try campaign_artifact
                .semanticInputsForPlannedNode(
                shape,
                registry,
                geometry,
                planned,
            );
            const dependencies = [_]protocol.Dependency{
                .{
                    .node_id = left.node().node_id,
                    .role = @intFromEnum(artifact_store.InputRoleV1.child_left),
                    .ordinal = 0,
                },
                .{
                    .node_id = right.node().node_id,
                    .role = @intFromEnum(artifact_store.InputRoleV1.child_right),
                    .ordinal = 0,
                },
            };
            const inputs = [_]artifact_store.InputRefV1{
                .{ .role = .child_left, .ordinal = 0, .blob = left.outputRef() },
                .{ .role = .child_right, .ordinal = 0, .blob = right.outputRef() },
            };
            const manifests = [_]artifact_store.BlobRefV1{
                left.stageManifestRef(),
                right.stageManifestRef(),
            };
            const node_id = try std.fmt.allocPrint(
                backing_allocator,
                "fold/{d}/{d}",
                .{ parent_coordinate.height, parent_coordinate.index },
            );
            defer backing_allocator.free(node_id);
            return initOwned(
                backing_allocator,
                final_remint,
                policy,
                execution_authorities,
                projected,
                node_public,
                node_id,
                consumers.stage104_adapter_name,
                &dependencies,
                &.{},
                &inputs,
                &manifests,
            );
        }
    };
}

fn initOwned(
    backing_allocator: std.mem.Allocator,
    final_remint: *const FinalRemint,
    policy: *const Policy,
    execution_authorities: protocol.ExecutionAuthorities,
    planned_semantic: PlannedSemantic,
    planned_node_public: campaign_artifact.NodePublic,
    node_id: []const u8,
    adapter: []const u8,
    dependencies: []const protocol.Dependency,
    external_inputs: []const artifact_store.InputRefV1,
    ordered_inputs: []const artifact_store.InputRefV1,
    dependency_stage_manifest_refs: []const artifact_store.BlobRefV1,
) !*OwnedStageDescriptionV2 {
    const owner = try backing_allocator.create(OwnedStageDescriptionV2);
    owner.* = undefined;
    owner.backing_allocator = backing_allocator;
    owner.arena = std.heap.ArenaAllocator.init(backing_allocator);
    errdefer {
        owner.arena.deinit();
        backing_allocator.destroy(owner);
    }
    const arena = owner.arena.allocator();
    const owned_inputs = try arena.dupe(
        artifact_store.InputRefV1,
        ordered_inputs,
    );
    const owned_external = try arena.dupe(
        artifact_store.InputRefV1,
        external_inputs,
    );
    const owned_manifests = try arena.dupe(
        artifact_store.BlobRefV1,
        dependency_stage_manifest_refs,
    );
    const owned_dependencies = try arena.alloc(
        protocol.Dependency,
        dependencies.len,
    );
    for (dependencies, owned_dependencies) |source, *destination| {
        destination.* = source;
        destination.node_id = try arena.dupe(u8, source.node_id);
    }
    const local_task = try campaign_store.localTaskIdentity(
        final_remint.shape,
        &planned_semantic,
    );
    const statement = try campaign_store.statementCacheIdentity(
        final_remint.shape,
        &planned_semantic,
    );
    const security = node_store.security.ProofSecurityV1
        .recursiveParentSecure();
    const options = try consumers.semanticOptionsValueV2(
        arena,
        &planned_semantic,
    );
    const node = protocol.Node{
        .node_id = try arena.dupe(u8, node_id),
        .stage_kind = campaign_store.sharedStageKind(
            planned_semantic.stage_kind,
        ),
        .stage_schema_version = try campaign_store.stageSchemaVersion(
            final_remint.shape,
            &planned_semantic,
        ),
        .adapter = try arena.dupe(u8, adapter),
        .dependencies = owned_dependencies,
        .external_inputs = owned_external,
        .local_task_identity_sha256 = local_task,
        .semantic_authorities = .{
            .protocol_identity_sha256 = planned_semantic.circuit_identity_sha256,
            .program_identity_sha256 = planned_semantic.program_identity_sha256,
            .profile_identity_sha256 = planned_semantic.profile_identity_sha256,
            .pcs_identity_sha256 = planned_semantic.pcs_identity_sha256,
            .security_identity_sha256 = security.identity,
            .statement_identity_sha256 = statement,
            .provider_identity_sha256 = [_]u8{0} ** 32,
            .layout_identity_sha256 = planned_semantic.padding_layout_identity_sha256,
            .registry_identity_sha256 = planned_semantic.registry_identity_sha256,
        },
        .semantic_options = options,
        .cpu_tokens = policy.cpu_tokens_per_node,
        .rss_tokens = policy.rss_bytes_per_node,
        .output_kind = .recursion_node,
        .output_schema_version = campaign_artifact.SCHEMA_VERSION,
    };
    const semantic = try support.createSemanticKey(
        arena,
        node,
        owned_inputs,
        planned_semantic.campaign_namespace_sha256,
    );
    const execution = try artifact_store.ExecutionKeyV1.create(
        execution_authorities.fields(semantic.identity),
    );
    owner.final_remint = final_remint;
    owner.policy = policy;
    owner.execution_authorities = execution_authorities;
    owner.planned_semantic = planned_semantic;
    owner.planned_node_public = planned_node_public;
    owner.node = node;
    owner.semantic = semantic;
    owner.execution = execution;
    owner.ordered_inputs = owned_inputs;
    owner.dependency_stage_manifest_refs = owned_manifests;
    owner.identity_sha256 = descriptionIdentity(owner);
    try owner.validate(backing_allocator);
    return owner;
}

fn validateChild(
    final_remint: *const FinalRemint,
    artifact: *const Artifact,
    output_ref: artifact_store.BlobRefV1,
) !void {
    const shape = final_remint.shape;
    try campaign_artifact.validate(shape, artifact);
    const role = try roleForArtifact(artifact);
    try campaign_artifact.admitRegistry(
        try final_remint.registryAuthority(),
        shape,
        artifact,
        try final_remint.geometryForRole(role),
    );
    const expected_ref = try node_store.toSharedRef(
        try campaign_artifact.artifactRef(shape, artifact),
    );
    if (!artifact_store.BlobRefV1.eql(expected_ref, output_ref))
        return error.CampaignFinalDescriptionChildMismatch;
    try campaign_cas.validate(output_ref, .recursion_node);
}

fn roleForPlanned(value: *const PlannedSemantic) !registry_mod.CircuitRoleV1 {
    return switch (value.stage_kind) {
        .leaf_wrapper => switch (value.node_kind) {
            .real => .ethereum_incremental_leaf_wrapper_v4,
            .empty => .canonical_empty_field_v2,
            .mixed => error.CampaignFinalDescriptionNodeMismatch,
        },
        .fold, .root => .common_fold_field_v2,
    };
}

fn roleForArtifact(value: *const Artifact) !registry_mod.CircuitRoleV1 {
    return switch (value.stage_kind) {
        .leaf_wrapper => switch (value.node_kind) {
            .real => .ethereum_incremental_leaf_wrapper_v4,
            .empty => .canonical_empty_field_v2,
            .mixed => error.CampaignFinalDescriptionChildMismatch,
        },
        .fold, .root => .common_fold_field_v2,
    };
}

fn assertBoundChild(comptime BoundChild: type) void {
    inline for (.{
        "validate",
        "node",
        "outputRef",
        "stageManifestRef",
        "nodeArtifact",
        "liveLeaseSelector",
    }) |name| if (!@hasDecl(BoundChild, name))
        @compileError("campaign bound child missing " ++ name);
}

fn descriptionIdentity(
    value: *const OwnedStageDescriptionV2,
) artifact_store.Digest {
    var hash = Sha256.init(.{});
    hash.update(DESCRIPTION_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&value.final_remint.binding_identity_sha256);
    hash.update(&value.policy.host.identity_sha256);
    hash.update(&value.policy.worker_policy_identity);
    hash.update(&value.policy.memory_policy_identity);
    hash.update(&value.planned_semantic.identity_sha256);
    hash.update(&value.semantic.identity);
    hash.update(&value.execution.identity);
    hashInt(&hash, u32, @as(u32, @intCast(value.node.node_id.len)));
    hash.update(value.node.node_id);
    hashInt(&hash, u32, @as(u32, @intCast(value.node.adapter.len)));
    hash.update(value.node.adapter);
    hashInt(&hash, u32, @intFromEnum(value.node.stage_kind));
    hashInt(&hash, u16, value.node.stage_schema_version);
    hashInt(&hash, u64, value.node.cpu_tokens);
    hashInt(&hash, u64, value.node.rss_tokens);
    hashInt(&hash, u32, @as(u32, @intCast(value.node.dependencies.len)));
    for (value.node.dependencies) |dependency| {
        hashInt(&hash, u32, @as(u32, @intCast(dependency.node_id.len)));
        hash.update(dependency.node_id);
        hashInt(&hash, u32, dependency.role);
        hashInt(&hash, u32, dependency.ordinal);
    }
    hashInt(&hash, u32, @as(u32, @intCast(value.ordered_inputs.len)));
    for (value.ordered_inputs) |input| hashInput(&hash, input);
    hashInt(
        &hash,
        u32,
        @as(u32, @intCast(value.dependency_stage_manifest_refs.len)),
    );
    for (value.dependency_stage_manifest_refs) |ref| hashBlob(&hash, ref);
    return hash.finalResult();
}

fn nodeJson(
    allocator: std.mem.Allocator,
    node: protocol.Node,
) !protocol.Json {
    var result = protocol.jsonObject(allocator);
    try protocol.put(&result, "node_id", protocol.string(node.node_id));
    try protocol.put(
        &result,
        "stage_kind",
        protocol.integer(@intFromEnum(node.stage_kind)),
    );
    try protocol.put(
        &result,
        "stage_schema_version",
        protocol.integer(node.stage_schema_version),
    );
    try protocol.put(&result, "adapter", protocol.string(node.adapter));
    var dependencies = protocol.array(allocator);
    for (node.dependencies) |dependency| {
        var item = protocol.jsonObject(allocator);
        try protocol.put(
            &item,
            "node_id",
            protocol.string(dependency.node_id),
        );
        try protocol.put(&item, "role", protocol.integer(dependency.role));
        try protocol.put(
            &item,
            "ordinal",
            protocol.integer(dependency.ordinal),
        );
        try protocol.append(&dependencies, item);
    }
    try protocol.put(&result, "dependencies", dependencies);
    var external = protocol.array(allocator);
    for (node.external_inputs) |input|
        try protocol.append(&external, try inputJson(allocator, input));
    try protocol.put(&result, "external_inputs", external);
    try protocol.putDigest(
        allocator,
        &result,
        "local_task_identity_sha256",
        node.local_task_identity_sha256,
    );
    try protocol.put(
        &result,
        "semantic_authorities",
        try authoritiesJson(allocator, node.semantic_authorities),
    );
    try protocol.put(&result, "semantic_options", node.semantic_options);
    try protocol.put(
        &result,
        "cpu_tokens",
        try protocol.integerU64(allocator, node.cpu_tokens),
    );
    try protocol.put(
        &result,
        "rss_tokens",
        try protocol.integerU64(allocator, node.rss_tokens),
    );
    try protocol.put(
        &result,
        "output_kind",
        protocol.integer(@intFromEnum(node.output_kind)),
    );
    try protocol.put(
        &result,
        "output_schema_version",
        protocol.integer(node.output_schema_version),
    );
    return result;
}

fn authoritiesJson(
    allocator: std.mem.Allocator,
    value: protocol.SemanticAuthorities,
) !protocol.Json {
    var result = protocol.jsonObject(allocator);
    inline for (.{
        .{ "protocol_identity_sha256", value.protocol_identity_sha256 },
        .{ "program_identity_sha256", value.program_identity_sha256 },
        .{ "profile_identity_sha256", value.profile_identity_sha256 },
        .{ "pcs_identity_sha256", value.pcs_identity_sha256 },
        .{ "security_identity_sha256", value.security_identity_sha256 },
        .{ "statement_identity_sha256", value.statement_identity_sha256 },
        .{ "provider_identity_sha256", value.provider_identity_sha256 },
        .{ "layout_identity_sha256", value.layout_identity_sha256 },
        .{ "registry_identity_sha256", value.registry_identity_sha256 },
    }) |field| try protocol.putDigest(
        allocator,
        &result,
        field[0],
        field[1],
    );
    return result;
}

fn inputJson(
    allocator: std.mem.Allocator,
    value: artifact_store.InputRefV1,
) !protocol.Json {
    var result = protocol.jsonObject(allocator);
    try protocol.put(&result, "blob", try blobRefJson(allocator, value.blob));
    try protocol.put(
        &result,
        "role",
        protocol.integer(@intFromEnum(value.role)),
    );
    try protocol.put(&result, "ordinal", protocol.integer(value.ordinal));
    return result;
}

fn blobRefJson(
    allocator: std.mem.Allocator,
    value: artifact_store.BlobRefV1,
) !protocol.Json {
    var result = protocol.jsonObject(allocator);
    try protocol.put(
        &result,
        "kind",
        protocol.integer(@intFromEnum(value.kind)),
    );
    try protocol.put(
        &result,
        "format_version",
        protocol.integer(value.format_version),
    );
    try protocol.put(
        &result,
        "schema_version",
        protocol.integer(value.schema_version),
    );
    try protocol.put(
        &result,
        "byte_count",
        try protocol.integerU64(allocator, value.byte_count),
    );
    try protocol.putDigest(allocator, &result, "sha256", value.sha256);
    return result;
}

fn hashInput(hash: *Sha256, value: artifact_store.InputRefV1) void {
    hashInt(hash, u32, @intFromEnum(value.role));
    hashInt(hash, u32, value.ordinal);
    hashBlob(hash, value.blob);
}

fn hashBlob(hash: *Sha256, value: artifact_store.BlobRefV1) void {
    hashInt(hash, u32, @intFromEnum(value.kind));
    hashInt(hash, u16, value.format_version);
    hashInt(hash, u16, value.schema_version);
    hashInt(hash, u64, value.byte_count);
    hash.update(&value.sha256);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or SERIALIZABLE_LIVE_LEASE_SELECTOR or
        !STAGE104_IS_INCREMENTAL or
        @hasField(OwnedStageDescriptionV2, "lease_id") or
        @hasField(OwnedStageDescriptionV2, "live_lease_selector") or
        @hasDecl(OwnedStageDescriptionV2, "decode"))
    {
        @compileError("campaign final description contract drifted");
    }
}
