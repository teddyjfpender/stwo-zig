const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const frontend = @import("stwo_riscv_frontend");

const subject = @import("recursive_common_wrapper_padding_remint_v2.zig");
const registry = @import("recursive_circuit_registry_v1.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const campaign_pipeline = @import("recursive_campaign_node_pipeline_v2.zig");
const campaign_shape = @import("recursive_pipeline_campaign_shape_v2.zig");
const campaign_empty = @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const campaign_final =
    @import("recursive_pipeline_campaign_final_remint_v2.zig");
const campaign_target =
    @import("recursive_pipeline_campaign_padding_target_v2.zig");
const campaign_fold_lease =
    @import("recursive_pipeline_campaign_fold_lease_v2.zig");
const final_description =
    @import("recursive_pipeline_campaign_final_description_v2.zig");
const execution_policy =
    @import("recursive_pipeline_worker_execution_policy_v2.zig");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");

const air = frontend.recursion.air;
const roster = air.universal_roster;
const universal_manifest = air.universal_manifest;
const Manifest = air.universal_adapter_manifest.Manifest;

const RealSource = FixtureSource(.ethereum_incremental_leaf_wrapper_v4);
const EmptySource = FixtureSource(.canonical_empty_field_v2);
const CommonSource = FixtureSource(.common_fold_field_v2);

test "three cold active roles derive unequal-provider target and only remints mint parity" {
    var fixture = try Fixture.init();
    const active_sources = fixture.activeSources();
    const target = try subject.PaddingTargetV2.derive(active_sources);
    try target.validateAgainst(active_sources);

    const provider_row: usize = @intFromEnum(roster.Component.poseidon2);
    try std.testing.expectEqual(
        @as(u8, 8),
        target.active_component_log_sizes[0][provider_row],
    );
    try std.testing.expectEqual(
        @as(u8, 7),
        target.active_component_log_sizes[1][provider_row],
    );
    try std.testing.expectEqual(
        @as(u8, 7),
        target.active_component_log_sizes[2][provider_row],
    );
    try std.testing.expectEqual(
        @as(u8, 8),
        target.target_padded_log_sizes[provider_row],
    );
    try std.testing.expect(!std.mem.allEqual(
        u8,
        &target.padding_table_layout_identity_sha256,
        0,
    ));
    try std.testing.expect(!@hasField(subject.PaddingTargetV2, "registry"));
    try std.testing.expect(!@hasField(subject.PaddingTargetV2, "parity"));

    fixture.remintForTarget(&target);
    const final_sources = fixture.finalSources();
    const admitted = try subject.FinalRemintAuthorityV2.mint(
        &target,
        active_sources,
        final_sources,
    );
    try admitted.validateAgainst(active_sources, final_sources);
    try admitted.validateSelf();
    try std.testing.expectEqual(@as(u16, 4), admitted.registry.schema_version);
    try std.testing.expectEqual(@as(u16, 4), admitted.parity.schema_version);
    try std.testing.expect(!admitted.registry.production_activation);
    try std.testing.expect(!admitted.parity.production_activation);
    try std.testing.expectEqualSlices(
        u8,
        target.target_padded_log_sizes[0..subject.COMPONENT_COUNT],
        admitted.parity.target_component_log_sizes[0..subject.COMPONENT_COUNT],
    );
    for (admitted.final_geometries) |geometry| {
        try std.testing.expectEqualSlices(
            u8,
            &target.padding_table_layout_identity_sha256,
            &geometry.padding_layout_identity_sha256,
        );
        try std.testing.expectEqualSlices(
            u8,
            &target.padding_table_layout_identity_sha256,
            &geometry.proof_shape.table_layout_identity_sha256,
        );
    }
}

test "padding remint rejects clone, active drift, layout drift, and failed cold source" {
    var fixture = try Fixture.init();
    const active_sources = fixture.activeSources();
    const target = try subject.PaddingTargetV2.derive(active_sources);
    fixture.remintForTarget(&target);

    fixture.active_empty.valid = false;
    try std.testing.expectError(
        error.RejectedFixtureColdGeometry,
        subject.PaddingTargetV2.derive(fixture.activeSources()),
    );
    fixture.active_empty.valid = true;

    var cloned = fixture.active_real.geometry_value;
    cloned.role = .canonical_empty_field_v2;
    cloned.authority_identity_sha256 = undefined;
    fixture.active_empty.geometry_value = try registry.AuthenticatedGeometryV1
        .seal(cloned);
    try std.testing.expectError(
        error.ColdGeometryClone,
        subject.PaddingTargetV2.derive(fixture.activeSources()),
    );
    fixture.active_empty.geometry_value = fixture.original_active_empty;

    const provider_row: usize = @intFromEnum(roster.Component.poseidon2);
    var active_drift = fixture.final_empty.geometry_value;
    active_drift.active_component_log_sizes[provider_row] = 8;
    active_drift.authority_identity_sha256 = undefined;
    fixture.final_empty.geometry_value = try registry.AuthenticatedGeometryV1
        .seal(active_drift);
    try std.testing.expectError(
        error.FinalSemanticActiveLogMismatch,
        subject.FinalRemintAuthorityV2.mint(
            &target,
            active_sources,
            fixture.finalSources(),
        ),
    );
    fixture.remintForTarget(&target);

    var padding_drift = fixture.final_common.geometry_value;
    padding_drift.padding_layout_identity_sha256[0] ^= 1;
    padding_drift.authority_identity_sha256 = undefined;
    fixture.final_common.geometry_value = try registry.AuthenticatedGeometryV1
        .seal(padding_drift);
    try std.testing.expectError(
        error.FinalGeometryLayoutMismatch,
        subject.FinalRemintAuthorityV2.mint(
            &target,
            active_sources,
            fixture.finalSources(),
        ),
    );
    fixture.remintForTarget(&target);

    var proof_drift = fixture.final_real.geometry_value;
    proof_drift.proof_shape.table_layout_identity_sha256[0] ^= 1;
    proof_drift.proof_shape.identity_sha256 = undefined;
    proof_drift.proof_shape = try registry.FixedProofShapeV3.seal(
        proof_drift.proof_shape,
    );
    proof_drift.authority_identity_sha256 = undefined;
    fixture.final_real.geometry_value = try registry.AuthenticatedGeometryV1
        .seal(proof_drift);
    try std.testing.expectError(
        error.FinalGeometryProofLayoutMismatch,
        subject.FinalRemintAuthorityV2.mint(
            &target,
            active_sources,
            fixture.finalSources(),
        ),
    );
}

test "final registry admits campaign-bound artifact through store and worker siblings" {
    var fixture = try Fixture.init();
    const active_sources = fixture.activeSources();
    const target = try subject.PaddingTargetV2.derive(active_sources);
    fixture.remintForTarget(&target);
    const final_sources = fixture.finalSources();
    const admitted = try subject.FinalRemintAuthorityV2.mint(
        &target,
        active_sources,
        final_sources,
    );
    const shape = try campaign_shape.CampaignShapeAuthorityV2.init(
        sha(701),
        sha(702),
        13,
    );
    const final_authority = try campaign_final.CampaignFinalRemintAuthorityV2
        .init(&shape, &admitted);
    try final_authority.validateAgainstCampaign(
        shape.campaign_namespace_sha256,
    );
    try std.testing.expect(
        try final_authority.registryAuthority() == &admitted.registry,
    );
    for (std.enums.values(registry.CircuitRoleV1)) |role| {
        const geometry = try final_authority.geometryForRole(role);
        try std.testing.expect(
            geometry == &admitted.final_geometries[@intFromEnum(role)],
        );
    }
    const real_lease = FixtureRealLease{
        .authority = &final_authority,
        .geometry = try final_authority.geometryForRole(
            .ethereum_incremental_leaf_wrapper_v4,
        ),
    };
    const empty_lease = FixtureEmptyLease{
        .authority = &final_authority,
        .geometry = try final_authority.geometryForRole(
            .canonical_empty_field_v2,
        ),
    };
    const common_lease = FixtureCommonLease{
        .authority = &final_authority,
        .geometry = try final_authority.geometryForRole(
            .common_fold_field_v2,
        ),
    };
    const tagged_real = try FixtureTypedLease.fromReal(
        &final_authority,
        &real_lease,
    );
    const tagged_empty = try FixtureTypedLease.fromEmpty(
        &final_authority,
        &empty_lease,
    );
    const tagged_common = try FixtureTypedLease.fromCommon(
        &final_authority,
        &common_lease,
    );
    try std.testing.expectEqual(
        registry.CircuitRoleV1.ethereum_incremental_leaf_wrapper_v4,
        (try tagged_real.foldProjection(&final_authority)).role,
    );
    try std.testing.expectEqual(
        registry.CircuitRoleV1.canonical_empty_field_v2,
        (try tagged_empty.foldProjection(&final_authority)).role,
    );
    try std.testing.expectEqual(
        registry.CircuitRoleV1.common_fold_field_v2,
        (try tagged_common.foldProjection(&final_authority)).role,
    );
    var copied_empty_geometry = empty_lease.geometry.*;
    const copied_empty_lease = PermissiveEmptyLease{
        .authority = &final_authority,
        .geometry = &copied_empty_geometry,
    };
    try std.testing.expectError(
        error.CampaignFoldLeaseProjectionMismatch,
        PointerClosureTypedLease.fromEmpty(
            &final_authority,
            &copied_empty_lease,
        ),
    );
    var copied_final_authority = final_authority;
    try std.testing.expectError(
        error.CampaignFoldLeaseAuthorityMismatch,
        tagged_real.foldProjection(&copied_final_authority),
    );
    var wrong_real_lease = real_lease;
    wrong_real_lease.geometry = empty_lease.geometry;
    try std.testing.expectError(
        error.FixtureCampaignLeaseMismatch,
        FixtureTypedLease.fromReal(&final_authority, &wrong_real_lease),
    );
    var hostile_final_authority = final_authority;
    hostile_final_authority.binding_identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.CampaignFinalRemintMismatch,
        hostile_final_authority.validateAgainstCampaign(
            shape.campaign_namespace_sha256,
        ),
    );
    var leaf: leaf_mod.LeafOrEmptyV1 = undefined;
    try leaf_mod.admitEmptyInto(
        &leaf,
        try campaignJob(13),
        13,
        poseidonDigest(703),
        poseidonDigest(704),
        poseidonDigest(705),
    );
    const source = try campaign_empty.SourceArtifactV2.seal(&shape, &leaf);
    const source_bytes = try source.encodeCanonical(&shape);
    const cold = try campaign_empty.ColdInputV2.open(&shape, &source_bytes);
    const geometry = &admitted.final_geometries[
        @intFromEnum(registry.CircuitRoleV1.canonical_empty_field_v2)
    ];
    const artifact = try campaign_artifact.seal(&shape, .{
        .stage_kind = .leaf_wrapper,
        .node_kind = .empty,
        .child_count = 1,
        .coordinate = cold.node_public.coordinate,
        .node_public = cold.node_public,
        .campaign_namespace_sha256 = shape.campaign_namespace_sha256,
        .circuit_identity_sha256 = geometry.circuit_identity_sha256,
        .program_identity_sha256 = geometry.program_identity_sha256,
        .profile_identity_sha256 = geometry.profile_identity_sha256,
        .pcs_identity_sha256 = geometry.pcs.identity_sha256,
        .padding_layout_identity_sha256 = geometry.padding_layout_identity_sha256,
        .registry_identity_sha256 = admitted.registry.identity_sha256,
        .node_public_abi_sha256 = fieldPublicAbi(),
        .proof_shape_identity_sha256 = geometry.proof_shape.identity_sha256,
        .ordered_children = .{
            try source.artifactRef(&shape),
            campaign_artifact.ArtifactRef.zero(),
        },
        .proof_ref = fixtureArtifactRef(8, 706),
        .preprocessed_root = geometry.preprocessed_root,
        .semantic_inputs_identity_sha256 = undefined,
        .field_public_transport_sha256 = undefined,
        .content_identity_sha256 = undefined,
    });
    const bytes = try campaign_artifact.encodeCanonical(&shape, &artifact);
    const reopened = try campaign_artifact.coldDecodeForStore(&shape, &bytes);
    const semantic = try campaign_artifact.semanticInputsForStore(
        &shape,
        &reopened,
    );
    const planned_semantic = try campaign_artifact
        .semanticInputsForPlannedNode(
        &shape,
        &admitted.registry,
        geometry,
        .{
            .stage_kind = artifact.stage_kind,
            .node_public = artifact.node_public,
            .child_count = artifact.child_count,
            .ordered_children = artifact.ordered_children,
        },
    );
    try std.testing.expectEqualDeep(semantic, planned_semantic);
    try campaign_artifact.validateWorkerOutput(
        &shape,
        &reopened,
        &semantic,
    );
    try campaign_artifact.admitRegistry(
        &admitted.registry,
        &shape,
        &reopened,
        geometry,
    );
    const store_view = try campaign_pipeline.CampaignStoreViewV2.coldOpen(
        &shape,
        &bytes,
    );
    const worker_admission =
        try campaign_pipeline.RegistryWorkerAdmissionV2.mint(
            &store_view,
            &admitted.registry,
            geometry,
        );
    try worker_admission.validate(
        &store_view,
        &admitted.registry,
        geometry,
    );
    var worker_mutation = worker_admission;
    worker_mutation.semantic_identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.CampaignNodePipelineMismatch,
        worker_mutation.validate(
            &store_view,
            &admitted.registry,
            geometry,
        ),
    );
    try std.testing.expectEqualDeep(
        try campaign_artifact.artifactRef(&shape, &artifact),
        try campaign_artifact.artifactRef(&shape, &reopened),
    );

    var global_ordinal = artifact;
    global_ordinal.coordinate.global_ordinal += 1;
    global_ordinal.node_public.coordinate.global_ordinal += 1;
    try std.testing.expectError(
        error.InvalidCampaignShapeCoordinateV2,
        campaign_artifact.validate(&shape, &global_ordinal),
    );
    var node_kind = artifact;
    node_kind.node_kind = .real;
    node_kind.node_public.node_kind = .real;
    try std.testing.expectError(
        error.CampaignArtifactMismatch,
        campaign_artifact.validate(&shape, &node_kind),
    );
    var root_height = artifact;
    root_height.coordinate.height = 8;
    root_height.node_public.coordinate.height = 8;
    try std.testing.expectError(
        error.InvalidCampaignShapeCoordinateV2,
        campaign_artifact.validate(&shape, &root_height),
    );

    const campaign_root = try campaign_public.coordinate(
        &shape,
        shape.root_height,
        0,
    );
    try std.testing.expectEqual(@as(u32, 30), campaign_root.global_ordinal);
    const legacy_root = try campaign_artifact.TaskCoordinate.init(4, 0);
    try std.testing.expectError(
        error.InvalidCampaignShapeCoordinateV2,
        campaign_public.validateCoordinate(&shape, legacy_root),
    );
}

test "campaign Stage103 and Stage104 descriptions are Zig-owned and lease-free" {
    var fixture = try Fixture.init();
    const active_sources = fixture.activeSources();
    const target = try subject.PaddingTargetV2.derive(active_sources);
    fixture.remintForTarget(&target);
    const final_sources = fixture.finalSources();
    const remint = try subject.FinalRemintAuthorityV2.mint(
        &target,
        active_sources,
        final_sources,
    );
    const shape = try campaign_shape.CampaignShapeAuthorityV2.init(
        sha(801),
        sha(802),
        13,
    );
    const authority = try campaign_final.CampaignFinalRemintAuthorityV2.init(
        &shape,
        &remint,
    );
    const host = try execution_policy.HostExecutionAuthorityV2.init(
        8,
        80_000,
    );
    const policy = try execution_policy.PolicyV2.init(host, .{
        .total_cpu_tokens = 8,
        .cpu_tokens_per_node = 4,
        .proof_worker_count = 4,
        .maximum_parallel_nodes = 2,
        .total_rss_bytes = 80_000,
        .rss_bytes_per_node = 40_000,
    });
    const execution = executionAuthorities(&policy, 810);
    const geometry = try authority.geometryForRole(
        .canonical_empty_field_v2,
    );
    var left_fixture = try emptyDescriptionFixture(
        &shape,
        &remint.registry,
        geometry,
        14,
        820,
    );
    var right_fixture = try emptyDescriptionFixture(
        &shape,
        &remint.registry,
        geometry,
        15,
        830,
    );
    const left_source_ref = try node_store.toSharedRef(
        try left_fixture.source.artifactRef(&shape),
    );
    const right_source_ref = try node_store.toSharedRef(
        try right_fixture.source.artifactRef(&shape),
    );
    const left_plan = try final_description.describeStage103(
        std.testing.allocator,
        &authority,
        &policy,
        execution,
        left_source_ref,
        &left_fixture.cold,
    );
    defer left_plan.deinit();
    const right_plan = try final_description.describeStage103(
        std.testing.allocator,
        &authority,
        &policy,
        execution,
        right_source_ref,
        &right_fixture.cold,
    );
    defer right_plan.deinit();
    try left_plan.validate(std.testing.allocator);
    try right_plan.validate(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 103), left_plan.node.stage_schema_version);
    try std.testing.expectEqual(@as(u64, 4), left_plan.node.cpu_tokens);
    try std.testing.expectEqual(@as(u64, 40_000), left_plan.node.rss_tokens);
    const left_json = try left_plan.encodeCanonicalJsonAlloc(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(left_json);
    try std.testing.expect(std.mem.indexOf(u8, left_json, "lease") == null);

    const left_output = try node_store.toSharedRef(
        try campaign_artifact.artifactRef(&shape, &left_fixture.artifact),
    );
    const right_output = try node_store.toSharedRef(
        try campaign_artifact.artifactRef(&shape, &right_fixture.artifact),
    );
    var left = BoundDescriptionChild{
        .node_value = &left_plan.node,
        .artifact_value = &left_fixture.artifact,
        .output_ref = left_output,
        .stage_manifest_ref = try artifact_store.BlobRefV1.create(
            .stage_manifest,
            1,
            512,
            sha(840),
        ),
        .lease_selector = "lease-left",
    };
    var right = BoundDescriptionChild{
        .node_value = &right_plan.node,
        .artifact_value = &right_fixture.artifact,
        .output_ref = right_output,
        .stage_manifest_ref = try artifact_store.BlobRefV1.create(
            .stage_manifest,
            1,
            512,
            sha(841),
        ),
        .lease_selector = "lease-right",
    };
    const Describer = final_description.DescriberFor(
        BoundDescriptionChild,
        BoundDescriptionChild,
    );
    const parent = try Describer.describeStage104(
        std.testing.allocator,
        &authority,
        &policy,
        execution,
        &left,
        &right,
    );
    defer parent.deinit();
    try parent.validate(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 104), parent.node.stage_schema_version);
    try std.testing.expectEqual(@as(u8, 1), parent.planned_semantic.coordinate.height);
    try std.testing.expectEqual(@as(u32, 7), parent.planned_semantic.coordinate.index);
    try std.testing.expectEqual(@as(usize, 2), parent.node.dependencies.len);
    const parent_json = try parent.encodeCanonicalJsonAlloc(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(parent_json);
    try std.testing.expect(std.mem.indexOf(u8, parent_json, "lease") == null);

    right.lease_selector = left.lease_selector;
    try std.testing.expectError(
        error.CampaignFinalDescriptionLeaseUnavailable,
        Describer.describeStage104(
            std.testing.allocator,
            &authority,
            &policy,
            execution,
            &left,
            &right,
        ),
    );
    right.lease_selector = "lease-right";
    right.output_ref.sha256[0] ^= 1;
    try std.testing.expectError(
        error.CampaignFinalDescriptionChildMismatch,
        Describer.describeStage104(
            std.testing.allocator,
            &authority,
            &policy,
            execution,
            &left,
            &right,
        ),
    );
}

const EmptyDescriptionFixture = struct {
    source: campaign_empty.SourceArtifactV2,
    cold: campaign_empty.ColdInputV2,
    artifact: campaign_artifact.Artifact,
};

const BoundDescriptionChild = struct {
    valid: bool = true,
    node_value: *const protocol.Node,
    artifact_value: *const campaign_artifact.Artifact,
    output_ref: artifact_store.BlobRefV1,
    stage_manifest_ref: artifact_store.BlobRefV1,
    lease_selector: []const u8,

    pub fn validate(self: BoundDescriptionChild) !void {
        if (!self.valid) return error.RejectedBoundDescriptionChild;
    }

    pub fn node(self: BoundDescriptionChild) *const protocol.Node {
        return self.node_value;
    }

    pub fn outputRef(self: BoundDescriptionChild) artifact_store.BlobRefV1 {
        return self.output_ref;
    }

    pub fn stageManifestRef(
        self: BoundDescriptionChild,
    ) artifact_store.BlobRefV1 {
        return self.stage_manifest_ref;
    }

    pub fn nodeArtifact(
        self: BoundDescriptionChild,
    ) *const campaign_artifact.Artifact {
        return self.artifact_value;
    }

    pub fn liveLeaseSelector(self: BoundDescriptionChild) []const u8 {
        return self.lease_selector;
    }
};

fn emptyDescriptionFixture(
    shape: *const campaign_shape.CampaignShapeAuthorityV2,
    registry_authority: *const registry.RecursiveCircuitRegistryV1,
    geometry: *const registry.AuthenticatedGeometryV1,
    index: u32,
    seed: u32,
) !EmptyDescriptionFixture {
    var leaf: leaf_mod.LeafOrEmptyV1 = undefined;
    try leaf_mod.admitEmptyInto(
        &leaf,
        try campaignJob(shape.real_leaf_count),
        @intCast(index),
        poseidonDigest(seed),
        poseidonDigest(seed + 1),
        poseidonDigest(seed + 2),
    );
    const source = try campaign_empty.SourceArtifactV2.seal(shape, &leaf);
    const source_bytes = try source.encodeCanonical(shape);
    const cold = try campaign_empty.ColdInputV2.open(shape, &source_bytes);
    const artifact = try campaign_artifact.seal(shape, .{
        .stage_kind = .leaf_wrapper,
        .node_kind = .empty,
        .child_count = 1,
        .coordinate = cold.node_public.coordinate,
        .node_public = cold.node_public,
        .campaign_namespace_sha256 = shape.campaign_namespace_sha256,
        .circuit_identity_sha256 = geometry.circuit_identity_sha256,
        .program_identity_sha256 = geometry.program_identity_sha256,
        .profile_identity_sha256 = geometry.profile_identity_sha256,
        .pcs_identity_sha256 = geometry.pcs.identity_sha256,
        .padding_layout_identity_sha256 = geometry.padding_layout_identity_sha256,
        .registry_identity_sha256 = registry_authority.identity_sha256,
        .node_public_abi_sha256 = fieldPublicAbi(),
        .proof_shape_identity_sha256 = geometry.proof_shape.identity_sha256,
        .ordered_children = .{
            try source.artifactRef(shape),
            campaign_artifact.ArtifactRef.zero(),
        },
        .proof_ref = fixtureArtifactRef(8, seed + 3),
        .preprocessed_root = geometry.preprocessed_root,
        .semantic_inputs_identity_sha256 = undefined,
        .field_public_transport_sha256 = undefined,
        .content_identity_sha256 = undefined,
    });
    return .{ .source = source, .cold = cold, .artifact = artifact };
}

fn executionAuthorities(
    policy: *const execution_policy.PolicyV2,
    seed: u32,
) protocol.ExecutionAuthorities {
    return .{
        .producer_identity_sha256 = sha(seed),
        .verifier_identity_sha256 = sha(seed + 1),
        .source_identity_sha256 = sha(seed + 2),
        .build_identity_sha256 = sha(seed + 3),
        .executable_identity_sha256 = sha(seed + 4),
        .toolchain_identity_sha256 = sha(seed + 5),
        .backend_identity_sha256 = sha(seed + 6),
        .optimization_identity_sha256 = sha(seed + 7),
        .worker_policy_identity_sha256 = policy.worker_policy_identity,
        .memory_policy_identity_sha256 = policy.memory_policy_identity,
        .retention_policy_identity_sha256 = sha(seed + 8),
        .timeout_policy_identity_sha256 = sha(seed + 9),
    };
}

const FixtureFoldProjection = struct {
    role: registry.CircuitRoleV1,
    geometry: *const registry.AuthenticatedGeometryV1,

    pub fn validateAgainst(
        self: FixtureFoldProjection,
        registry_authority: *const registry.RecursiveCircuitRegistryV1,
    ) !void {
        try registry_authority.validate();
        try self.geometry.validate();
        const entry = try registry_authority.entry(self.role);
        const expected = try registry.RegistryEntryV1.fromGeometry(
            self.geometry,
        );
        if (!std.meta.eql(entry.*, expected))
            return error.FixtureCampaignLeaseMismatch;
    }
};

fn FixtureCampaignLease(comptime role: registry.CircuitRoleV1) type {
    return struct {
        pub const ROLE = role;

        authority: *const campaign_final.CampaignFinalRemintAuthorityV2,
        geometry: *const registry.AuthenticatedGeometryV1,

        pub fn validateForCampaign(
            self: *const @This(),
            authority: *const campaign_final.CampaignFinalRemintAuthorityV2,
        ) !void {
            if (self.authority != authority or
                self.geometry != try authority.geometryForRole(role))
            {
                return error.FixtureCampaignLeaseMismatch;
            }
        }

        pub fn foldProjection(
            self: *const @This(),
            registry_authority: *const registry.RecursiveCircuitRegistryV1,
        ) !FixtureFoldProjection {
            if (registry_authority != try self.authority.registryAuthority())
                return error.FixtureCampaignLeaseMismatch;
            return .{ .role = role, .geometry = self.geometry };
        }
    };
}

const FixtureRealLease = FixtureCampaignLease(
    .ethereum_incremental_leaf_wrapper_v4,
);
const FixtureEmptyLease = FixtureCampaignLease(
    .canonical_empty_field_v2,
);
const FixtureCommonLease = FixtureCampaignLease(
    .common_fold_field_v2,
);
const FixtureTypedLease = campaign_fold_lease.TypedCampaignFoldLeaseV2(
    FixtureFoldProjection,
    FixtureRealLease,
    FixtureEmptyLease,
    FixtureCommonLease,
);

fn PermissiveCampaignLease(comptime role: registry.CircuitRoleV1) type {
    return struct {
        pub const ROLE = role;

        authority: *const campaign_final.CampaignFinalRemintAuthorityV2,
        geometry: *const registry.AuthenticatedGeometryV1,

        pub fn validateForCampaign(
            self: *const @This(),
            authority: *const campaign_final.CampaignFinalRemintAuthorityV2,
        ) !void {
            if (self.authority != authority)
                return error.FixtureCampaignLeaseMismatch;
        }

        pub fn foldProjection(
            self: *const @This(),
            registry_authority: *const registry.RecursiveCircuitRegistryV1,
        ) !FixtureFoldProjection {
            if (registry_authority != try self.authority.registryAuthority())
                return error.FixtureCampaignLeaseMismatch;
            return .{ .role = role, .geometry = self.geometry };
        }
    };
}

const PermissiveRealLease = PermissiveCampaignLease(
    .ethereum_incremental_leaf_wrapper_v4,
);
const PermissiveEmptyLease = PermissiveCampaignLease(
    .canonical_empty_field_v2,
);
const PermissiveCommonLease = PermissiveCampaignLease(
    .common_fold_field_v2,
);
const PointerClosureTypedLease = campaign_fold_lease.TypedCampaignFoldLeaseV2(
    FixtureFoldProjection,
    PermissiveRealLease,
    PermissiveEmptyLease,
    PermissiveCommonLease,
);

pub const Fixture = struct {
    active_real: RealSource,
    active_empty: EmptySource,
    active_common: CommonSource,
    final_real: RealSource,
    final_empty: EmptySource,
    final_common: CommonSource,
    original_active_empty: registry.AuthenticatedGeometryV1,

    pub fn init() !Fixture {
        const role0_logs = activeLogs(8);
        const other_logs = activeLogs(7);
        const active_real = RealSource{ .geometry_value = try fixtureGeometry(
            .ethereum_incremental_leaf_wrapper_v4,
            role0_logs,
            role0_logs,
            sha(10),
            100,
        ) };
        const active_empty = EmptySource{ .geometry_value = try fixtureGeometry(
            .canonical_empty_field_v2,
            other_logs,
            other_logs,
            sha(20),
            200,
        ) };
        const active_common = CommonSource{ .geometry_value = try fixtureGeometry(
            .common_fold_field_v2,
            other_logs,
            other_logs,
            sha(30),
            300,
        ) };
        return .{
            .active_real = active_real,
            .active_empty = active_empty,
            .active_common = active_common,
            .final_real = undefined,
            .final_empty = undefined,
            .final_common = undefined,
            .original_active_empty = active_empty.geometry_value,
        };
    }

    pub fn activeSources(self: *Fixture) struct {
        *const RealSource,
        *const EmptySource,
        *const CommonSource,
    } {
        return .{ &self.active_real, &self.active_empty, &self.active_common };
    }

    pub fn finalSources(self: *Fixture) struct {
        *const RealSource,
        *const EmptySource,
        *const CommonSource,
    } {
        return .{ &self.final_real, &self.final_empty, &self.final_common };
    }

    pub fn remintForTarget(
        self: *Fixture,
        target: *const subject.PaddingTargetV2,
    ) void {
        self.final_real = .{ .geometry_value = fixtureGeometry(
            .ethereum_incremental_leaf_wrapper_v4,
            self.active_real.geometry_value.active_component_log_sizes,
            target.target_padded_log_sizes,
            target.padding_table_layout_identity_sha256,
            400,
        ) catch unreachable };
        self.final_empty = .{ .geometry_value = fixtureGeometry(
            .canonical_empty_field_v2,
            self.active_empty.geometry_value.active_component_log_sizes,
            target.target_padded_log_sizes,
            target.padding_table_layout_identity_sha256,
            500,
        ) catch unreachable };
        self.final_common = .{ .geometry_value = fixtureGeometry(
            .common_fold_field_v2,
            self.active_common.geometry_value.active_component_log_sizes,
            target.target_padded_log_sizes,
            target.padding_table_layout_identity_sha256,
            600,
        ) catch unreachable };
    }
};

fn FixtureSource(comptime role_value: subject.Role) type {
    return struct {
        pub const ROLE = role_value;

        geometry_value: registry.AuthenticatedGeometryV1,
        valid: bool = true,
        target_bound: bool = true,

        pub fn validateColdGeometry(self: *const @This()) !void {
            if (!self.valid) return error.RejectedFixtureColdGeometry;
            try self.geometry_value.validate();
            if (self.geometry_value.role != ROLE)
                return error.RejectedFixtureColdGeometry;
        }

        pub fn geometryForPaddingTarget(
            self: *const @This(),
        ) *const registry.AuthenticatedGeometryV1 {
            return &self.geometry_value;
        }

        pub fn validateForPaddingTarget(
            self: *const @This(),
            target: *const campaign_target.CampaignPaddingTargetV2,
        ) !void {
            if (!self.target_bound)
                return error.RejectedFixturePaddingTarget;
            try self.validateColdGeometry();
            try target.validateRemintedGeometry(ROLE, &self.geometry_value);
        }
    };
}

fn fixtureGeometry(
    role: subject.Role,
    active: subject.LogVectorV2,
    padded: subject.LogVectorV2,
    layout_identity: [32]u8,
    seed: u32,
) !registry.AuthenticatedGeometryV1 {
    const manifest = try manifestFor(padded);
    const shape = try fixtureShape(&manifest, layout_identity);
    var preprocessed = [_]u8{0} ** registry.MAX_PREPROCESSED_COLUMN_COUNT;
    for (std.enums.values(roster.Component)) |component| {
        const placement = try manifest.placement(component);
        const start: usize = @intCast(placement.preprocessed_offset);
        const end = start + @as(usize, placement.geometry.preprocessed_columns);
        @memset(preprocessed[start..end], @intCast(placement.geometry.log_size));
    }
    var root: [8]u32 = undefined;
    for (&root, 0..) |*word, index| word.* = seed + @as(u32, @intCast(index));
    return registry.AuthenticatedGeometryV1.seal(.{
        .role = role,
        .authenticated_padding = true,
        .component_count = subject.COMPONENT_COUNT,
        .preprocessed_column_count = @intCast(
            manifest.total_preprocessed_columns,
        ),
        .trace_log_size = maximumLog(padded),
        .active_component_log_sizes = active,
        .padded_component_log_sizes = padded,
        .preprocessed_column_log_sizes = preprocessed,
        .circuit_identity_sha256 = sha(seed + 1),
        .program_identity_sha256 = sha(seed + 2),
        .profile_identity_sha256 = sha(seed + 3),
        .padding_layout_identity_sha256 = layout_identity,
        .preprocessed_root = root,
        .pcs = registry.PcsConfigV1.secureTemporalParent(),
        .output_abi = registry.OutputAbiV1.fieldNodePublicV2(),
        .proof_shape = shape,
        .authority_identity_sha256 = undefined,
    });
}

fn fixtureShape(
    manifest: *const Manifest,
    layout_identity: [32]u8,
) !registry.FixedProofShapeV3 {
    const query_count: u16 = 193;
    const blowup: u8 = 1;
    var counts = [_]u16{0} ** registry.FIXED_PROOF_TREE_COUNT;
    counts[0] = @intCast(manifest.total_preprocessed_columns);
    counts[1] = @intCast(manifest.total_main_columns);
    counts[2] = @intCast(manifest.total_interaction_columns);
    counts[3] = 4;
    var logs = [_][registry.MAX_TREE_COLUMN_COUNT]u8{
        [_]u8{0} ** registry.MAX_TREE_COLUMN_COUNT,
    } ** registry.FIXED_PROOF_TREE_COUNT;
    var samples = [_][registry.MAX_TREE_COLUMN_COUNT]u8{
        [_]u8{0} ** registry.MAX_TREE_COLUMN_COUNT,
    } ** registry.FIXED_PROOF_TREE_COUNT;
    for (std.enums.values(roster.Component)) |component| {
        const placement = try manifest.placement(component);
        const extended: u8 = @intCast(placement.geometry.log_size + blowup);
        const column_counts = [_]u16{
            placement.geometry.preprocessed_columns,
            placement.geometry.main_columns,
            placement.geometry.interaction_columns,
        };
        const offsets = [_]u32{
            placement.preprocessed_offset,
            placement.main_offset,
            placement.interaction_offset,
        };
        for (column_counts, offsets, 0..) |column_count, offset, tree| {
            const start: usize = @intCast(offset);
            const end = start + @as(usize, column_count);
            @memset(logs[tree][start..end], extended);
            @memset(samples[tree][start..end], 1);
        }
    }
    const column_log_degree = maximumTreeLog(&logs, counts) - blowup;
    @memset(logs[3][0..counts[3]], column_log_degree + blowup);
    @memset(samples[3][0..counts[3]], 1);
    var total_columns: u32 = 0;
    var total_samples: u32 = 0;
    var total_trace_siblings: u32 = 0;
    for (counts, &logs, &samples) |count, *tree_logs, *tree_samples| {
        total_columns += @as(u32, count);
        for (tree_samples[0..count]) |sample_count|
            total_samples += sample_count;
        total_trace_siblings +=
            @as(u32, maximumLogSlice(tree_logs[0..count])) *
            @as(u32, query_count);
    }
    var fri_widths = [_]u8{0} ** registry.MAX_FRI_LAYER_COUNT;
    var fri_depths = [_]u8{0} ** registry.MAX_FRI_LAYER_COUNT;
    fri_widths[0..4].* = .{ 16, 16, 16, 16 };
    fri_depths[0..4].* = .{ 13, 9, 5, 1 };
    return registry.FixedProofShapeV3.seal(.{
        .maximum_merkle_depth = maximumTreeLog(&logs, counts),
        .claimed_sum_count = subject.COMPONENT_COUNT,
        .fri_layer_count = 4,
        .query_count = query_count,
        .maximum_fold_width = 16,
        .column_log_degree = column_log_degree,
        .sampled_value_count = total_samples,
        .queried_value_count = total_columns * @as(u32, query_count),
        .trace_path_count = registry.FIXED_PROOF_TREE_COUNT *
            @as(u32, query_count),
        .trace_sibling_count = total_trace_siblings,
        .fri_value_count = 4 * 16 * @as(u32, query_count),
        .fri_sibling_count = (13 + 9 + 5 + 1) * @as(u32, query_count),
        .last_layer_coefficient_count = 1,
        .tree_column_counts = counts,
        .tree_column_log_sizes = logs,
        .tree_column_sample_counts = samples,
        .fri_layer_fold_widths = fri_widths,
        .fri_layer_path_depths = fri_depths,
        .table_layout_identity_sha256 = layout_identity,
        .identity_sha256 = undefined,
    });
}

fn manifestFor(logs: subject.LogVectorV2) !Manifest {
    var exact: universal_manifest.LogSizes = undefined;
    for (&exact, logs[0..subject.COMPONENT_COUNT]) |*out, value| out.* = value;
    return universal_manifest.build(exact);
}

fn activeLogs(provider_log: u8) subject.LogVectorV2 {
    var result = [_]u8{4} ** registry.MAX_COMPONENT_COUNT;
    @memset(result[subject.COMPONENT_COUNT..], 0);
    result[@intFromEnum(roster.Component.poseidon2)] = provider_log;
    result[@intFromEnum(roster.Component.range_check_8_8)] = 16;
    return result;
}

fn maximumLog(logs: subject.LogVectorV2) u8 {
    return maximumLogSlice(logs[0..subject.COMPONENT_COUNT]);
}

fn maximumTreeLog(
    logs: *const [registry.FIXED_PROOF_TREE_COUNT][registry.MAX_TREE_COLUMN_COUNT]u8,
    counts: [registry.FIXED_PROOF_TREE_COUNT]u16,
) u8 {
    var result: u8 = 0;
    for (logs, counts) |tree, count|
        result = @max(result, maximumLogSlice(tree[0..count]));
    return result;
}

fn maximumLogSlice(logs: []const u8) u8 {
    var result: u8 = 0;
    for (logs) |log_size| result = @max(result, log_size);
    return result;
}

fn sha(seed: u32) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = @truncate(seed + @as(u32, @intCast(index)));
    return result;
}

fn campaignJob(
    segment_count: u32,
) !frontend.recursion.span_statement.JobContext {
    const initial = try frontend.recursion.span_statement.MachineState.init(
        0x1000,
        [_]u32{0} ** 32,
        poseidonDigest(801),
        poseidonDigest(802),
    );
    const final = try frontend.recursion.span_statement.MachineState.init(
        0x2000,
        [_]u32{0} ** 32,
        poseidonDigest(803),
        poseidonDigest(804),
    );
    return frontend.recursion.span_statement.JobContext.init(
        try frontend.recursion.span_statement.CompleteExecution.init(
            frontend.recursion.protocol.PROTOCOL_ID_WORDS,
            poseidonDigest(805),
            initial,
            final,
            poseidonDigest(806),
            poseidonDigest(807),
            88_000,
        ),
        segment_count,
    );
}

fn poseidonDigest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn fixtureArtifactRef(
    kind: u32,
    seed: u32,
) campaign_artifact.ArtifactRef {
    return .{
        .kind = kind,
        .format_version = 1,
        .schema_version = 1,
        .byte_count = 17,
        .sha256 = sha(seed),
    };
}

fn fieldPublicAbi() [32]u8 {
    return @import("recursive_field_node_public_v2.zig").abiIdentitySha256();
}
