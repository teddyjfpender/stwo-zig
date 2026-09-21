//! Gate-only Stage-102 lifecycle joining authenticated Stage-101 custody to
//! the genuine campaign tree.
//!
//! The Stage-102 worker needs its semantic key before its proof exists.  This
//! owner derives that key from the exact verifier-owned Stage-101 input, the
//! campaign-wide provider geometry, and the final role-0 geometry.  It then
//! cold-opens the already-published Stage-101 proof into the same Worker,
//! consumes that live lease in a Stage-102 build, independently cold-opens the
//! resulting wrapper, and lets the mutable inventory deep-adopt the seal-last
//! publication.  Only after every runtime row is present does it quiesce the
//! Worker, seal the inventory, and install the immutable Session consumed by
//! the existing three-leaf tree gate.
//!
//! No request JSON, lease selector, verifier capability, or filesystem path
//! survives as a durable authority.  All release flags remain false; the
//! entry points here exercise the exact production bodies for a coordinated
//! genuine gate only.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const support = @import("recursive_pipeline_worker_support_v1.zig");
const storage = @import("recursive_pipeline_worker_storage_v1.zig");
const native_worker = @import("recursive_pipeline_worker_native_leaf_v4.zig");
const real_worker = @import("recursive_pipeline_worker_campaign_real_leaf_v4.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_store = @import("recursive_campaign_node_artifact_store_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const role0_authority = @import("recursive_pipeline_worker_campaign_real_leaf_authority_v4.zig");
const role_io = @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
const field_public = @import("recursive_common_ethereum_incremental_leaf_field_public_v4_schema3.zig");
const table_mod = @import("recursive_pipeline_incremental_campaign_table_v4.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const GENUINE_Q193_GATE_GREEN = false;
pub const GENUINE_GATE_ONLY = true;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const SERIALIZABLE_LIVE_LEASE_SELECTOR = false;
pub const AUTHENTICATED_STAGE101_REQUIRED = true;
pub const BUILD_THEN_INDEPENDENT_COLD_OPEN_REQUIRED = true;
pub const QUIESCE_BEFORE_IMMUTABLE_INSTALL_REQUIRED = true;
pub const EXECUTION_POLICY_HAS_NO_SERIAL_FALLBACK = true;
pub const RUNTIME_CAMPAIGN_CARDINALITY_REQUIRED = true;

const PLAN_IDENTITY_DOMAIN =
    "stwo-zig/recursive-pipeline-campaign-genuine-stage102-plan/v4\x00";

pub const Error = error{
    GenuineStage102TreeLifecycleCampaignMismatchV4,
    GenuineStage102TreeLifecycleIdentityMismatchV4,
    GenuineStage102TreeLifecyclePathMismatchV4,
    GenuineStage102TreeLifecyclePublicationMismatchV4,
    GenuineStage102TreeLifecycleResponseMismatchV4,
};

/// Caller-selected, create-only paths for one worker build. The owner below
/// copies every byte before issuing a request. The caller owns cleanup of
/// these diagnostic products; CAS custody is digest-derived independently.
pub const BuildPathsV4 = struct {
    output_path: []const u8,
    profile_receipt_path: []const u8,
    candidate_ref_path: []const u8,

    pub fn validate(self: BuildPathsV4) !void {
        try support.validateDistinctPaths(
            self.output_path,
            self.profile_receipt_path,
            self.candidate_ref_path,
        );
    }
};

pub const Stage102PublicationV4 = struct {
    output_ref: artifact_store.BlobRefV1,
    stage_manifest_ref: artifact_store.BlobRefV1,

    pub fn validate(self: Stage102PublicationV4) !void {
        try self.output_ref.validate();
        try self.stage_manifest_ref.validate();
        if (self.output_ref.format_version !=
            artifact_store.types.format_version_v1 or
            self.output_ref.kind != .recursion_node or
            self.output_ref.schema_version != campaign_artifact.SCHEMA_VERSION or
            self.output_ref.byte_count != campaign_artifact.ENCODED_BYTE_COUNT or
            self.stage_manifest_ref.format_version !=
                artifact_store.types.format_version_v1 or
            self.stage_manifest_ref.kind != .stage_manifest or
            self.stage_manifest_ref.schema_version !=
                support.stage_manifest_schema_version)
        {
            return error.GenuineStage102TreeLifecyclePublicationMismatchV4;
        }
    }
};

/// Cheap, proof-free preflight used before any file or CAS mutation. Every
/// row owns three create-only diagnostic paths and no path may be reused by a
/// different row.
pub fn validateBuildPathsV4(paths: []const BuildPathsV4) !void {
    if (paths.len == 0)
        return error.GenuineStage102TreeLifecyclePathMismatchV4;
    try validatePathInventory(paths);
}

pub fn Types(
    comptime Engine: type,
    comptime AuthenticatedStage101: type,
    comptime FinalFixture: type,
    comptime Lifecycle: type,
    comptime TreeGate: type,
) type {
    assertTypes(
        Engine,
        AuthenticatedStage101,
        FinalFixture,
        Lifecycle,
        TreeGate,
    );

    const AuthenticatedOwner = AuthenticatedStage101.OwnedCampaignV4;
    const Stage101Publication = AuthenticatedStage101.PublicationV4;
    const FinalOwner = FinalFixture.OwnedFinalV2;
    const Authority = FinalFixture.Role0AuthorityV4;
    const FinalSessionOwner = Lifecycle.OwnedFinalSessionV4;
    const Building = Lifecycle.OwnedBuildingV4;
    const Quiesced = Lifecycle.OwnedQuiescedV4;
    const Sealed = Lifecycle.OwnedSealedV4;
    const TreeOwner = TreeGate.OwnedTreeV2;

    return struct {
        const Family = @This();

        pub const EngineV4 = Engine;
        pub const AuthenticatedStage101V4 = AuthenticatedStage101;
        pub const FinalFixtureV2 = FinalFixture;
        pub const LifecycleV4 = Lifecycle;
        pub const TreeGateV2 = TreeGate;
        pub const AuthorityV4 = Authority;
        pub const FinalSessionOwnerV4 = FinalSessionOwner;
        pub const TreeOwnerV2 = TreeOwner;
        pub const available = false;

        /// Heap-stable Stage-102 plan. `stage101` is a revalidated borrow from
        /// `authenticated`; every Stage-102 pointer and every output path is
        /// owned by this value's arena.
        pub const OwnedStage102PlanV4 = struct {
            allocator: std.mem.Allocator,
            arena: std.heap.ArenaAllocator,
            final: *const FinalOwner,
            authenticated: *const AuthenticatedOwner,
            policy: *const policy_mod.PolicyV2,
            execution_authorities: protocol.ExecutionAuthorities,
            row_index: usize,
            stage101: Stage101Publication,
            node_public: campaign_artifact.NodePublic,
            planned_semantic: campaign_artifact.CampaignSemanticInputsV2,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            paths: BuildPathsV4,
            identity_sha256: artifact_store.Digest,

            const Self = @This();

            pub fn init(
                allocator: std.mem.Allocator,
                scratch: std.mem.Allocator,
                final: *const FinalOwner,
                authenticated: *const AuthenticatedOwner,
                policy: *const policy_mod.PolicyV2,
                execution_authorities: protocol.ExecutionAuthorities,
                row_index: usize,
                paths: BuildPathsV4,
            ) !*Self {
                try validateCampaignClosure(
                    Engine,
                    scratch,
                    final,
                    authenticated,
                );
                try policy.validate();
                try paths.validate();
                if (row_index >= authenticated.leafCount())
                    return error.GenuineStage102TreeLifecycleCampaignMismatchV4;

                const publication = try authenticated.publicationAt(
                    scratch,
                    row_index,
                );
                const fresh = try authenticated.retainedFreshInputAt(
                    row_index,
                );
                try final.campaign.campaign.validateFreshInputAt(
                    Engine,
                    scratch,
                    row_index,
                    fresh,
                );
                var witness = try role_io.OwnedWitnessV4.initUnfrozenForAudit(
                    scratch,
                    &fresh.stage101.public_data.data,
                    &fresh.stage101.role_aware_public.value,
                    &fresh.stage101.relations.base,
                    final.campaign.campaign.provider_geometry
                        .role_io_tuple_capacity,
                );
                defer witness.deinit();
                const node_public = try field_public.deriveNodePublic(
                    Engine,
                    fresh,
                    &witness,
                );
                const source_ref = try node_store.fromSharedRef(
                    publication.output_ref,
                );
                const final_remint = final.genuine.authority();
                const planned = campaign_artifact.PlannedSemanticNodeV2{
                    .stage_kind = .leaf_wrapper,
                    .node_public = node_public,
                    .child_count = 1,
                    .ordered_children = .{
                        source_ref,
                        campaign_artifact.ArtifactRef.zero(),
                    },
                };
                const projected = try campaign_artifact
                    .semanticInputsForPlannedNode(
                    final_remint.shape,
                    try final_remint.registryAuthority(),
                    try final_remint.geometryForRole(
                        .ethereum_incremental_leaf_wrapper_v4,
                    ),
                    planned,
                );

                const self = try allocator.create(Self);
                self.* = undefined;
                self.allocator = allocator;
                self.arena = std.heap.ArenaAllocator.init(allocator);
                errdefer {
                    self.arena.deinit();
                    allocator.destroy(self);
                }
                const arena = self.arena.allocator();
                const dependencies = try arena.alloc(protocol.Dependency, 1);
                dependencies[0] = .{
                    .node_id = try arena.dupe(u8, publication.node.node_id),
                    .role = @intFromEnum(artifact_store.InputRoleV1.proof),
                    .ordinal = 0,
                };
                const external_inputs = try arena.alloc(
                    artifact_store.InputRefV1,
                    0,
                );
                const ordered_inputs = try arena.alloc(
                    artifact_store.InputRefV1,
                    1,
                );
                ordered_inputs[0] = .{
                    .role = .proof,
                    .ordinal = 0,
                    .blob = publication.output_ref,
                };
                const local_task = try campaign_store.localTaskIdentity(
                    final_remint.shape,
                    &projected,
                );
                const security = node_store.security.ProofSecurityV1
                    .recursiveParentSecure();
                const semantic_options = try real_worker.semanticOptionsValueV4(
                    arena,
                    &projected,
                );
                const node = protocol.Node{
                    .node_id = try std.fmt.allocPrint(
                        arena,
                        "stage102/{d}",
                        .{row_index},
                    ),
                    .stage_kind = .prove,
                    .stage_schema_version = real_worker.STAGE_SCHEMA_VERSION,
                    .adapter = try arena.dupe(u8, real_worker.adapter_name),
                    .dependencies = dependencies,
                    .external_inputs = external_inputs,
                    .local_task_identity_sha256 = local_task,
                    .semantic_authorities = .{
                        .protocol_identity_sha256 = projected.circuit_identity_sha256,
                        .program_identity_sha256 = projected.program_identity_sha256,
                        .profile_identity_sha256 = projected.profile_identity_sha256,
                        .pcs_identity_sha256 = projected.pcs_identity_sha256,
                        .security_identity_sha256 = security.identity,
                        .statement_identity_sha256 = try campaign_store
                            .statementCacheIdentity(
                            final_remint.shape,
                            &projected,
                        ),
                        .provider_identity_sha256 = [_]u8{0} ** 32,
                        .layout_identity_sha256 = projected.padding_layout_identity_sha256,
                        .registry_identity_sha256 = projected.registry_identity_sha256,
                    },
                    .semantic_options = semantic_options,
                    .cpu_tokens = policy.cpu_tokens_per_node,
                    .rss_tokens = policy.rss_bytes_per_node,
                    .output_kind = .recursion_node,
                    .output_schema_version = campaign_artifact.SCHEMA_VERSION,
                };
                const semantic = try support.createSemanticKey(
                    arena,
                    node,
                    ordered_inputs,
                    final_remint.shape.campaign_namespace_sha256,
                );
                const execution = try artifact_store.ExecutionKeyV1.create(
                    execution_authorities.fields(semantic.identity),
                );
                self.final = final;
                self.authenticated = authenticated;
                self.policy = policy;
                self.execution_authorities = execution_authorities;
                self.row_index = row_index;
                self.stage101 = publication;
                self.node_public = node_public;
                self.planned_semantic = projected;
                self.node = node;
                self.semantic = semantic;
                self.execution = execution;
                self.ordered_inputs = ordered_inputs;
                self.paths = .{
                    .output_path = try arena.dupe(u8, paths.output_path),
                    .profile_receipt_path = try arena.dupe(
                        u8,
                        paths.profile_receipt_path,
                    ),
                    .candidate_ref_path = try arena.dupe(
                        u8,
                        paths.candidate_ref_path,
                    ),
                };
                self.identity_sha256 = planIdentity(self);
                try self.validate(scratch);
                return self;
            }

            pub fn validate(
                self: *const Self,
                scratch: std.mem.Allocator,
            ) !void {
                try validateCampaignClosure(
                    Engine,
                    scratch,
                    self.final,
                    self.authenticated,
                );
                try self.policy.validateAgainstExecution(self.execution);
                try self.paths.validate();
                if (self.row_index >= self.authenticated.leafCount())
                    return error.GenuineStage102TreeLifecycleCampaignMismatchV4;
                const observed = try self.authenticated.publicationAt(
                    scratch,
                    self.row_index,
                );
                if (!try publicationBorrowEqual(
                    scratch,
                    self.stage101,
                    observed,
                )) return error.GenuineStage102TreeLifecycleIdentityMismatchV4;
                const fresh = try self.authenticated.retainedFreshInputAt(
                    self.row_index,
                );
                try self.final.campaign.campaign.validateFreshInputAt(
                    Engine,
                    scratch,
                    self.row_index,
                    fresh,
                );
                var witness = try role_io.OwnedWitnessV4.initUnfrozenForAudit(
                    scratch,
                    &fresh.stage101.public_data.data,
                    &fresh.stage101.role_aware_public.value,
                    &fresh.stage101.relations.base,
                    self.final.campaign.campaign.provider_geometry
                        .role_io_tuple_capacity,
                );
                defer witness.deinit();
                const expected_public = try field_public.deriveNodePublic(
                    Engine,
                    fresh,
                    &witness,
                );
                const final_remint = self.final.genuine.authority();
                const expected_semantic = try campaign_artifact
                    .semanticInputsForPlannedNode(
                    final_remint.shape,
                    try final_remint.registryAuthority(),
                    try final_remint.geometryForRole(
                        .ethereum_incremental_leaf_wrapper_v4,
                    ),
                    .{
                        .stage_kind = .leaf_wrapper,
                        .node_public = expected_public,
                        .child_count = 1,
                        .ordered_children = .{
                            try node_store.fromSharedRef(
                                observed.output_ref,
                            ),
                            campaign_artifact.ArtifactRef.zero(),
                        },
                    },
                );
                try support.validateKeys(
                    scratch,
                    self.node,
                    self.ordered_inputs,
                    self.semantic,
                    self.execution,
                );
                try real_worker.validateSemanticProjectionV4(
                    scratch,
                    final_remint.shape,
                    self.node,
                    &self.semantic,
                    self.ordered_inputs,
                    &self.planned_semantic,
                );
                const expected_execution = try artifact_store.ExecutionKeyV1
                    .create(self.execution_authorities.fields(
                    self.semantic.identity,
                ));
                const row_u32 = std.math.cast(u32, self.row_index) orelse
                    return error.GenuineStage102TreeLifecycleCampaignMismatchV4;
                if (self.node.dependencies.len != 1 or
                    self.ordered_inputs.len != 1)
                {
                    return error.GenuineStage102TreeLifecycleIdentityMismatchV4;
                }
                const input = self.ordered_inputs[0];
                const dependency = self.node.dependencies[0];
                if (!std.meta.eql(self.node_public, expected_public) or
                    !std.meta.eql(self.planned_semantic, expected_semantic) or
                    !std.meta.eql(self.execution, expected_execution) or
                    self.node.stage_kind != .prove or
                    self.node.stage_schema_version !=
                        real_worker.STAGE_SCHEMA_VERSION or
                    !std.mem.eql(u8, self.node.adapter, real_worker.adapter_name) or
                    self.node.external_inputs.len != 0 or
                    self.node.output_kind != .recursion_node or
                    self.node.output_schema_version !=
                        campaign_artifact.SCHEMA_VERSION or
                    self.node.cpu_tokens != self.policy.cpu_tokens_per_node or
                    self.node.rss_tokens != self.policy.rss_bytes_per_node or
                    self.planned_semantic.coordinate.height != 0 or
                    self.planned_semantic.coordinate.index != row_u32 or
                    dependency.role !=
                        @intFromEnum(artifact_store.InputRoleV1.proof) or
                    dependency.ordinal != 0 or
                    !std.mem.eql(
                        u8,
                        dependency.node_id,
                        observed.node.node_id,
                    ) or input.role != .proof or input.ordinal != 0 or
                    !artifact_store.BlobRefV1.eql(
                        input.blob,
                        observed.output_ref,
                    ) or !std.mem.eql(
                    u8,
                    &self.identity_sha256,
                    &planIdentity(self),
                )) return error.GenuineStage102TreeLifecycleIdentityMismatchV4;
                try validateFinalStage101ProofRef(
                    self.final,
                    self.row_index,
                    observed.output_ref,
                );
            }

            pub fn deinit(self: *Self) void {
                const allocator = self.allocator;
                self.arena.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }

            /// Executes one exact Stage-101 cold-open -> Stage-102 build ->
            /// Stage-102 cold-open/adoption transaction. Live selectors never
            /// leave this call; the Worker's typed Stage-102 lease remains
            /// retained until lifecycle quiescence.
            pub fn executeForGenuineGate(
                self: *const Self,
                scratch: std.mem.Allocator,
                building: *Building,
                sequence_base: u64,
            ) !Stage102PublicationV4 {
                try self.validate(scratch);
                try publishStage102Keys(scratch, self);

                var arena_state = std.heap.ArenaAllocator.init(scratch);
                defer arena_state.deinit();
                const arena = arena_state.allocator();
                const native_lease_id = try self.coldOpenStage101(
                    arena,
                    building,
                    sequence_base,
                );
                const output_ref = try self.buildStage102(
                    arena,
                    building,
                    sequence_base + 1,
                    native_lease_id,
                );
                const result = try self.coldOpenStage102(
                    arena,
                    building,
                    sequence_base + 2,
                    output_ref,
                );
                try result.validate();
                return result;
            }

            fn coldOpenStage101(
                self: *const Self,
                arena: std.mem.Allocator,
                building: *Building,
                sequence: u64,
            ) ![]const u8 {
                const table = self.authenticated.campaignTable();
                var payload = protocol.jsonObject(arena);
                try protocol.put(
                    &payload,
                    "node",
                    try protocol.nodeValue(arena, self.stage101.node),
                );
                try protocol.put(
                    &payload,
                    "ordered_inputs",
                    try protocol.inputRefsValue(
                        arena,
                        &table.records[self.row_index].stage_inputs,
                    ),
                );
                try protocol.put(
                    &payload,
                    "semantic_key",
                    try protocol.semanticProjection(
                        arena,
                        self.stage101.semantic,
                    ),
                );
                try protocol.put(
                    &payload,
                    "execution_key",
                    try protocol.executionProjection(
                        arena,
                        self.stage101.execution,
                    ),
                );
                try protocol.put(
                    &payload,
                    "output_ref",
                    try protocol.blobRefValue(
                        arena,
                        self.stage101.output_ref,
                    ),
                );
                try protocol.put(
                    &payload,
                    "output_path",
                    protocol.string(try storage.objectPathAlloc(
                        arena,
                        self.authenticated.store,
                        self.stage101.output_ref,
                    )),
                );
                try protocol.put(
                    &payload,
                    "dependency_stage_manifest_refs",
                    try blobRefsValue(arena, &.{}),
                );
                try protocol.put(
                    &payload,
                    "stage_manifest_ref",
                    try protocol.blobRefValue(
                        arena,
                        self.stage101.stage_manifest_ref,
                    ),
                );
                try protocol.put(
                    &payload,
                    "validator_version",
                    protocol.integer(1),
                );
                try protocol.put(&payload, "mode", protocol.string("root"));
                const response = try building.adoptForGenuineGate(arena, .{
                    .sequence = sequence,
                    .action = .cold_open,
                    .payload = payload,
                });
                const object = try protocol.objectValue(response);
                try protocol.exactKeys(object, &.{
                    "validation_receipt",
                    "lease_id",
                    "stage_manifest_ref",
                });
                try validateReceiptSeal(arena, object);
                const lease_id = try protocol.stringField(object, "lease_id");
                const manifest = try protocol.parseBlobRef(
                    object.get("stage_manifest_ref") orelse
                        return error.GenuineStage102TreeLifecycleResponseMismatchV4,
                );
                if (lease_id.len == 0 or !artifact_store.BlobRefV1.eql(
                    manifest,
                    self.stage101.stage_manifest_ref,
                )) return error.GenuineStage102TreeLifecycleResponseMismatchV4;
                try building.workerView().validateRetainedLeaseIdentity(
                    lease_id,
                    self.stage101.node.node_id,
                    self.stage101.output_ref,
                    manifest,
                );
                return lease_id;
            }

            fn buildStage102(
                self: *const Self,
                arena: std.mem.Allocator,
                building: *Building,
                sequence: u64,
                native_lease_id: []const u8,
            ) !artifact_store.BlobRefV1 {
                const lease_ids = [_][]const u8{native_lease_id};
                var input_paths = protocol.array(arena);
                for (self.ordered_inputs) |input| {
                    try protocol.append(
                        &input_paths,
                        protocol.string(try storage.objectPathAlloc(
                            arena,
                            self.authenticated.store,
                            input.blob,
                        )),
                    );
                }
                var payload = protocol.jsonObject(arena);
                try putWorkerKeysAndInputs(arena, &payload, self);
                try protocol.put(
                    &payload,
                    "dependency_lease_ids",
                    try support.stringsValue(arena, &lease_ids),
                );
                try protocol.put(&payload, "input_object_paths", input_paths);
                try protocol.put(
                    &payload,
                    "output_path",
                    protocol.string(self.paths.output_path),
                );
                try protocol.put(
                    &payload,
                    "profile_receipt_path",
                    protocol.string(self.paths.profile_receipt_path),
                );
                try protocol.put(
                    &payload,
                    "candidate_ref_path",
                    protocol.string(self.paths.candidate_ref_path),
                );
                const response = try building.buildForGenuineGate(arena, .{
                    .sequence = sequence,
                    .action = .build,
                    .payload = payload,
                });
                const object = try protocol.objectValue(response);
                try protocol.exactKeys(object, &.{
                    "output_path",
                    "output_ref",
                    "profile_receipt_path",
                    "candidate_ref_path",
                    "consumed_lease_ids",
                });
                try expectString(object, "output_path", self.paths.output_path);
                try expectString(
                    object,
                    "profile_receipt_path",
                    self.paths.profile_receipt_path,
                );
                try expectString(
                    object,
                    "candidate_ref_path",
                    self.paths.candidate_ref_path,
                );
                const consumed = try support.stringArray(
                    arena,
                    object.get("consumed_lease_ids") orelse
                        return error.GenuineStage102TreeLifecycleResponseMismatchV4,
                );
                if (consumed.len != 1 or
                    !std.mem.eql(u8, consumed[0], native_lease_id))
                {
                    return error.GenuineStage102TreeLifecycleResponseMismatchV4;
                }
                const output_ref = try protocol.parseBlobRef(
                    object.get("output_ref") orelse
                        return error.GenuineStage102TreeLifecycleResponseMismatchV4,
                );
                if (output_ref.kind != .recursion_node or
                    output_ref.schema_version != campaign_artifact.SCHEMA_VERSION)
                {
                    return error.GenuineStage102TreeLifecycleResponseMismatchV4;
                }
                try storage.exactOpenRef(
                    arena,
                    self.authenticated.store,
                    output_ref,
                    null,
                );
                return output_ref;
            }

            fn coldOpenStage102(
                self: *const Self,
                arena: std.mem.Allocator,
                building: *Building,
                sequence: u64,
                output_ref: artifact_store.BlobRefV1,
            ) !Stage102PublicationV4 {
                var payload = protocol.jsonObject(arena);
                try putWorkerKeysAndInputs(arena, &payload, self);
                try protocol.put(
                    &payload,
                    "output_ref",
                    try protocol.blobRefValue(arena, output_ref),
                );
                try protocol.put(
                    &payload,
                    "output_path",
                    protocol.string(try storage.objectPathAlloc(
                        arena,
                        self.authenticated.store,
                        output_ref,
                    )),
                );
                const dependency_manifests = [_]artifact_store.BlobRefV1{
                    self.stage101.stage_manifest_ref,
                };
                try protocol.put(
                    &payload,
                    "dependency_stage_manifest_refs",
                    try blobRefsValue(arena, &dependency_manifests),
                );
                try protocol.put(&payload, "stage_manifest_ref", .null);
                try protocol.put(
                    &payload,
                    "validator_version",
                    protocol.integer(1),
                );
                try protocol.put(&payload, "mode", protocol.string("root"));
                const response = try building.adoptForGenuineGate(arena, .{
                    .sequence = sequence,
                    .action = .cold_open,
                    .payload = payload,
                });
                const object = try protocol.objectValue(response);
                try protocol.exactKeys(object, &.{
                    "validation_receipt",
                    "lease_id",
                    "stage_manifest_ref",
                });
                try validateReceiptSeal(arena, object);
                const lease_id = try protocol.stringField(object, "lease_id");
                const manifest = try protocol.parseBlobRef(
                    object.get("stage_manifest_ref") orelse
                        return error.GenuineStage102TreeLifecycleResponseMismatchV4,
                );
                const result = Stage102PublicationV4{
                    .output_ref = output_ref,
                    .stage_manifest_ref = manifest,
                };
                try result.validate();
                if (lease_id.len == 0)
                    return error.GenuineStage102TreeLifecycleResponseMismatchV4;
                try building.workerView().validateRetainedLeaseIdentity(
                    lease_id,
                    self.node.node_id,
                    output_ref,
                    manifest,
                );
                return result;
            }

            comptime {
                rejectCodec(Self);
            }
        };

        /// Owns the complete Stage-102 planning authority, all deep-copied
        /// plans/admissions, and the installed immutable lifecycle. `final`,
        /// `authenticated`, and `policy` are borrowed and must outlive it.
        pub const OwnedInstalledStage102V4 = struct {
            allocator: std.mem.Allocator,
            final: *const FinalOwner,
            authenticated: *const AuthenticatedOwner,
            policy: *const policy_mod.PolicyV2,
            execution_authorities: protocol.ExecutionAuthorities,
            plans: []?*OwnedStage102PlanV4,
            admissions: []role0_authority.Stage101AdmissionV4,
            publications: []Stage102PublicationV4,
            authority: Authority,
            authority_initialized: bool,
            lifecycle: ?*FinalSessionOwner,

            const Self = @This();

            pub fn buildAndInstallForGenuineGate(
                allocator: std.mem.Allocator,
                scratch: std.mem.Allocator,
                final: *const FinalOwner,
                authenticated: *const AuthenticatedOwner,
                store_root: []const u8,
                policy: *const policy_mod.PolicyV2,
                execution_authorities: protocol.ExecutionAuthorities,
                paths: []const BuildPathsV4,
            ) !*Self {
                try validateCampaignClosure(
                    Engine,
                    scratch,
                    final,
                    authenticated,
                );
                try policy.validate();
                const count = authenticated.leafCount();
                if (paths.len != count or count == 0)
                    return error.GenuineStage102TreeLifecycleCampaignMismatchV4;
                if (!std.mem.eql(
                    u8,
                    store_root,
                    authenticated.store.root_path,
                )) return error.GenuineStage102TreeLifecycleIdentityMismatchV4;
                try validateBuildPathsV4(paths);

                const plans = try allocator.alloc(?*OwnedStage102PlanV4, count);
                @memset(plans, null);
                var plans_owned = true;
                errdefer if (plans_owned) allocator.free(plans);
                const admissions = try allocator.alloc(
                    role0_authority.Stage101AdmissionV4,
                    count,
                );
                var admissions_owned = true;
                errdefer if (admissions_owned) allocator.free(admissions);
                const publications = try allocator.alloc(
                    Stage102PublicationV4,
                    count,
                );
                var publications_owned = true;
                errdefer if (publications_owned) allocator.free(publications);
                const self = try allocator.create(Self);
                self.* = .{
                    .allocator = allocator,
                    .final = final,
                    .authenticated = authenticated,
                    .policy = policy,
                    .execution_authorities = execution_authorities,
                    .plans = plans,
                    .admissions = admissions,
                    .publications = publications,
                    .authority = undefined,
                    .authority_initialized = false,
                    .lifecycle = null,
                };
                plans_owned = false;
                admissions_owned = false;
                publications_owned = false;
                errdefer self.deinit();

                const wrapper_identities = try scratch.alloc(
                    artifact_store.Digest,
                    count,
                );
                defer scratch.free(wrapper_identities);
                for (paths, 0..) |row_paths, index| {
                    self.plans[index] = try OwnedStage102PlanV4.init(
                        allocator,
                        scratch,
                        final,
                        authenticated,
                        policy,
                        execution_authorities,
                        index,
                        row_paths,
                    );
                    wrapper_identities[index] = self.plans[index].?
                        .node.local_task_identity_sha256;
                }
                try authenticated.fillStage101Admissions(
                    wrapper_identities,
                    self.admissions,
                );
                self.authority = try final.role0Authority(self.admissions);
                self.authority_initialized = true;

                var building: ?*Building = try Lifecycle.beginForGenuineGate(
                    allocator,
                    scratch,
                    authenticated.store,
                    store_root,
                    &self.authority,
                    policy,
                );
                defer if (building) |value| value.deinit();
                for (self.plans, 0..) |maybe_plan, index| {
                    const plan = maybe_plan orelse
                        return error.GenuineStage102TreeLifecycleCampaignMismatchV4;
                    const base = std.math.mul(u64, @intCast(index), 3) catch
                        return error.GenuineStage102TreeLifecycleCampaignMismatchV4;
                    self.publications[index] = try plan.executeForGenuineGate(
                        scratch,
                        building.?,
                        base,
                    );
                    if (try building.?.builderView().adoptedCount() != index + 1)
                        return error.GenuineStage102TreeLifecyclePublicationMismatchV4;
                }

                var quiesced: ?*Quiesced = try building.?
                    .quiesceForGenuineGate();
                building = null;
                defer if (quiesced) |value| value.deinit();
                var sealed: ?*Sealed = try quiesced.?
                    .sealCompleteForGenuineGate(scratch);
                quiesced = null;
                defer if (sealed) |value| value.deinit();
                self.lifecycle = try sealed.?
                    .installImmutableForGenuineGate(scratch);
                sealed = null;
                try self.validate(scratch);
                return self;
            }

            pub fn validate(
                self: *const Self,
                scratch: std.mem.Allocator,
            ) !void {
                try validateCampaignClosure(
                    Engine,
                    scratch,
                    self.final,
                    self.authenticated,
                );
                try self.policy.validate();
                if (!self.authority_initialized or self.lifecycle == null or
                    self.plans.len != self.authenticated.leafCount() or
                    self.admissions.len != self.plans.len or
                    self.publications.len != self.plans.len)
                {
                    return error.GenuineStage102TreeLifecycleCampaignMismatchV4;
                }
                try self.authority.validate(
                    scratch,
                    self.final.genuine.authority().shape
                        .campaign_namespace_sha256,
                );
                if (self.authority.table != self.final.campaign.table or
                    self.authority.campaign_geometry !=
                        self.final.campaign.campaign or
                    self.authority.padding_target != &self.final.genuine.target or
                    self.authority.final_remint !=
                        self.final.genuine.authority() or
                    self.authority.active_sources != &self.final.active_sources or
                    self.authority.stage101_admissions.ptr !=
                        self.admissions.ptr or
                    self.authority.stage101_admissions.len !=
                        self.admissions.len)
                {
                    return error.GenuineStage102TreeLifecycleIdentityMismatchV4;
                }
                const lifecycle = self.lifecycle.?;
                try lifecycle.validate(scratch);
                const session = try lifecycle.immutableSession();
                try Lifecycle.ReplayProviderV4.requireInstalledSession(session);
                if (session.store != self.authenticated.store or
                    session.authority != &self.authority or
                    session.policy != self.policy or
                    session.entries.len != self.plans.len)
                {
                    return error.GenuineStage102TreeLifecycleIdentityMismatchV4;
                }
                for (
                    self.plans,
                    self.publications,
                    session.entries,
                    0..,
                ) |maybe_plan, publication, entry, index| {
                    const plan = maybe_plan orelse
                        return error.GenuineStage102TreeLifecycleCampaignMismatchV4;
                    try plan.validate(scratch);
                    try publication.validate();
                    const retained = try session.stage102AdmissionForOutput(
                        self.final.genuine.authority().shape
                            .campaign_namespace_sha256,
                        publication.output_ref,
                    );
                    if (retained != &session.entries[index].admission or
                        !artifact_store.BlobRefV1.eql(
                            entry.output_ref,
                            publication.output_ref,
                        ) or !artifact_store.BlobRefV1.eql(
                        entry.admission.stage_manifest_ref,
                        publication.stage_manifest_ref,
                    ) or !artifact_store.BlobRefV1.eql(
                        entry.admission.dependency_stage_manifest_ref,
                        plan.stage101.stage_manifest_ref,
                    ) or !std.mem.eql(
                        u8,
                        &entry.admission.node.local_task_identity_sha256,
                        &plan.node.local_task_identity_sha256,
                    )) return error.GenuineStage102TreeLifecyclePublicationMismatchV4;
                }
            }

            pub fn finalSession(self: *Self) !*FinalSessionOwner {
                return self.lifecycle orelse
                    error.GenuineStage102TreeLifecycleCampaignMismatchV4;
            }

            pub fn deinit(self: *Self) void {
                const allocator = self.allocator;
                if (self.lifecycle) |lifecycle| lifecycle.deinit();
                var index = self.plans.len;
                while (index != 0) {
                    index -= 1;
                    if (self.plans[index]) |plan| plan.deinit();
                }
                allocator.free(self.publications);
                allocator.free(self.admissions);
                allocator.free(self.plans);
                self.* = undefined;
                allocator.destroy(self);
            }

            comptime {
                rejectCodec(Self);
            }
        };

        /// One owner spanning the exact installed Stage-102 Session and the
        /// existing role1/role2 tree. The tree is destroyed first so none of
        /// its role-0 borrows can outlive the lifecycle's cached leases.
        pub const OwnedCompleteTreeV4 = struct {
            allocator: std.mem.Allocator,
            installed_stage102: *OwnedInstalledStage102V4,
            tree: *TreeOwner,

            const Self = @This();

            pub fn proveAndSealForGenuineGate(
                allocator: std.mem.Allocator,
                scratch: std.mem.Allocator,
                final: *const FinalOwner,
                authenticated: *const AuthenticatedOwner,
                store_root: []const u8,
                policy: *const policy_mod.PolicyV2,
                execution_authorities: protocol.ExecutionAuthorities,
                paths: []const BuildPathsV4,
            ) !*Self {
                const installed = try OwnedInstalledStage102V4
                    .buildAndInstallForGenuineGate(
                    allocator,
                    scratch,
                    final,
                    authenticated,
                    store_root,
                    policy,
                    execution_authorities,
                    paths,
                );
                var installed_owned = true;
                errdefer if (installed_owned) installed.deinit();
                const tree = try TreeOwner.proveAndSealForGenuineGate(
                    allocator,
                    scratch,
                    final,
                    try installed.finalSession(),
                    execution_authorities,
                );
                var tree_owned = true;
                errdefer if (tree_owned) tree.deinit();
                const self = try allocator.create(Self);
                self.* = .{
                    .allocator = allocator,
                    .installed_stage102 = installed,
                    .tree = tree,
                };
                installed_owned = false;
                tree_owned = false;
                errdefer self.deinit();
                try self.validate(scratch);
                return self;
            }

            pub fn validate(
                self: *const Self,
                scratch: std.mem.Allocator,
            ) !void {
                try self.installed_stage102.validate(scratch);
                try self.tree.validate(scratch);
                const lifecycle = try self.installed_stage102.finalSession();
                const session = try lifecycle.immutableSession();
                if (self.tree.final != self.installed_stage102.final or
                    self.tree.lifecycle != lifecycle or
                    self.tree.session != session)
                {
                    return error.GenuineStage102TreeLifecycleIdentityMismatchV4;
                }
            }

            pub fn rootOutputRef(
                self: *const Self,
            ) artifact_store.BlobRefV1 {
                return self.tree.rootOutputRef();
            }

            pub fn rootStageManifestRef(
                self: *const Self,
            ) artifact_store.BlobRefV1 {
                return self.tree.rootStageManifestRef();
            }

            pub fn deinit(self: *Self) void {
                const allocator = self.allocator;
                self.tree.deinit();
                self.installed_stage102.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }

            comptime {
                rejectCodec(Self);
            }
        };

        comptime {
            if (Family.AuthorityV4 != Lifecycle.AuthorityV4 or
                Family.FinalSessionOwnerV4 !=
                    TreeGate.FinalSessionOwnerV4 or
                Family.TreeOwnerV2 != TreeGate.OwnedTreeV2)
            {
                @compileError("genuine Stage102/tree lifecycle type drifted");
            }
        }
    };
}

fn validateCampaignClosure(
    comptime Engine: type,
    scratch: std.mem.Allocator,
    final: anytype,
    authenticated: anytype,
) !void {
    try final.validate();
    try authenticated.validate();
    const final_table = final.campaign.table;
    const authenticated_table = authenticated.campaignTable();
    const final_bytes = try table_mod.encodeAlloc(scratch, final_table);
    defer scratch.free(final_bytes);
    const authenticated_bytes = try table_mod.encodeAlloc(
        scratch,
        authenticated_table,
    );
    defer scratch.free(authenticated_bytes);
    const final_remint = final.genuine.authority();
    if (authenticated.leafCount() != final.campaign.artifacts.bytes.len or
        authenticated.leafCount() !=
            @as(usize, @intCast(final_remint.shape.real_leaf_count)) or
        !std.mem.eql(u8, final_bytes, authenticated_bytes) or
        !std.mem.eql(
            u8,
            &authenticated.campaign_namespace_sha256,
            &final_remint.shape.campaign_namespace_sha256,
        ) or !std.mem.eql(
        u8,
        &authenticated_table.content_sha256,
        &final_table.content_sha256,
    )) return error.GenuineStage102TreeLifecycleCampaignMismatchV4;
    for (0..authenticated.leafCount()) |index| {
        const fresh = try authenticated.retainedFreshInputAt(index);
        try final.campaign.campaign.validateFreshInputAt(
            Engine,
            scratch,
            index,
            fresh,
        );
        const publication = try authenticated.publicationAt(scratch, index);
        try validateFinalStage101ProofRef(final, index, publication.output_ref);
    }
}

fn validateFinalStage101ProofRef(
    final: anytype,
    index: usize,
    observed: artifact_store.BlobRefV1,
) !void {
    if (index >= final.campaign.artifacts.bytes.len)
        return error.GenuineStage102TreeLifecycleCampaignMismatchV4;
    const proof_bytes = final.campaign.artifacts.bytes[index];
    const expected = try artifact_store.BlobRefV1.create(
        .proof_artifact,
        native_worker.OUTPUT_SCHEMA_VERSION,
        @intCast(proof_bytes.len),
        artifact_store.digestBytes(proof_bytes),
    );
    if (!artifact_store.BlobRefV1.eql(expected, observed))
        return error.GenuineStage102TreeLifecycleCampaignMismatchV4;
}

fn publicationBorrowEqual(
    scratch: std.mem.Allocator,
    left: anytype,
    right: @TypeOf(left),
) !bool {
    const left_options = try protocol.canonicalDigest(
        scratch,
        left.node.semantic_options,
    );
    const right_options = try protocol.canonicalDigest(
        scratch,
        right.node.semantic_options,
    );
    return left.node.node_id.ptr == right.node.node_id.ptr and
        left.node.node_id.len == right.node.node_id.len and
        left.node.adapter.ptr == right.node.adapter.ptr and
        left.node.adapter.len == right.node.adapter.len and
        left.node.dependencies.ptr == right.node.dependencies.ptr and
        left.node.dependencies.len == right.node.dependencies.len and
        left.node.external_inputs.ptr == right.node.external_inputs.ptr and
        left.node.external_inputs.len == right.node.external_inputs.len and
        std.meta.eql(left.node.stage_kind, right.node.stage_kind) and
        left.node.stage_schema_version == right.node.stage_schema_version and
        std.meta.eql(left.node.local_task_identity_sha256, right.node.local_task_identity_sha256) and
        std.meta.eql(left.node.semantic_authorities, right.node.semantic_authorities) and
        left.node.cpu_tokens == right.node.cpu_tokens and
        left.node.rss_tokens == right.node.rss_tokens and
        left.node.output_kind == right.node.output_kind and
        left.node.output_schema_version == right.node.output_schema_version and
        std.mem.eql(u8, &left_options, &right_options) and
        left.semantic.fields.ordered_inputs.ptr ==
            right.semantic.fields.ordered_inputs.ptr and
        left.semantic.fields.ordered_inputs.len ==
            right.semantic.fields.ordered_inputs.len and
        std.mem.eql(u8, &left.semantic.identity, &right.semantic.identity) and
        std.meta.eql(left.execution, right.execution) and
        artifact_store.BlobRefV1.eql(left.output_ref, right.output_ref) and
        artifact_store.BlobRefV1.eql(
            left.stage_manifest_ref,
            right.stage_manifest_ref,
        );
}

fn publishStage102Keys(
    scratch: std.mem.Allocator,
    plan: anytype,
) !void {
    const semantic_bytes = try plan.semantic.canonicalBytesAlloc(scratch);
    defer scratch.free(semantic_bytes);
    const execution_bytes = try plan.execution.canonicalBytes();
    const semantic_ref = try plan.authenticated.store.putBytes(
        .semantic_key,
        artifact_store.types.format_version_v1,
        semantic_bytes,
    );
    const execution_ref = try plan.authenticated.store.putBytes(
        .execution_key,
        artifact_store.types.format_version_v1,
        &execution_bytes,
    );
    if (!std.mem.eql(u8, &semantic_ref.sha256, &plan.semantic.identity) or
        !std.mem.eql(u8, &execution_ref.sha256, &plan.execution.identity))
    {
        return error.GenuineStage102TreeLifecycleIdentityMismatchV4;
    }
}

fn putWorkerKeysAndInputs(
    allocator: std.mem.Allocator,
    payload: *protocol.Json,
    plan: anytype,
) !void {
    try protocol.put(
        payload,
        "node",
        try protocol.nodeValue(allocator, plan.node),
    );
    try protocol.put(
        payload,
        "ordered_inputs",
        try protocol.inputRefsValue(allocator, plan.ordered_inputs),
    );
    try protocol.put(
        payload,
        "semantic_key",
        try protocol.semanticProjection(allocator, plan.semantic),
    );
    try protocol.put(
        payload,
        "execution_key",
        try protocol.executionProjection(allocator, plan.execution),
    );
}

fn blobRefsValue(
    allocator: std.mem.Allocator,
    refs: []const artifact_store.BlobRefV1,
) !protocol.Json {
    var result = protocol.array(allocator);
    for (refs) |ref|
        try protocol.append(
            &result,
            try protocol.blobRefValue(allocator, ref),
        );
    return result;
}

fn validateReceiptSeal(
    allocator: std.mem.Allocator,
    object: std.json.ObjectMap,
) !void {
    const receipt = try protocol.objectValue(
        object.get("validation_receipt") orelse
            return error.GenuineStage102TreeLifecycleResponseMismatchV4,
    );
    try protocol.validateSeal(allocator, receipt);
}

fn expectString(
    object: std.json.ObjectMap,
    field: []const u8,
    expected: []const u8,
) !void {
    if (!std.mem.eql(
        u8,
        try protocol.stringField(object, field),
        expected,
    )) return error.GenuineStage102TreeLifecycleResponseMismatchV4;
}

fn validatePathInventory(paths: []const BuildPathsV4) !void {
    for (paths, 0..) |paths_for_row, index| {
        try paths_for_row.validate();
        const current = [_][]const u8{
            paths_for_row.output_path,
            paths_for_row.profile_receipt_path,
            paths_for_row.candidate_ref_path,
        };
        for (paths[0..index]) |earlier| {
            const previous = [_][]const u8{
                earlier.output_path,
                earlier.profile_receipt_path,
                earlier.candidate_ref_path,
            };
            for (current) |a| for (previous) |b| {
                if (std.mem.eql(u8, a, b))
                    return error.GenuineStage102TreeLifecyclePathMismatchV4;
            };
        }
    }
}

fn planIdentity(plan: anytype) artifact_store.Digest {
    var hash = Sha256.init(.{});
    hash.update(PLAN_IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u64, @intCast(plan.row_index));
    hash.update(&plan.final.genuine.authority().binding_identity_sha256);
    hash.update(&plan.authenticated.table_ref.sha256);
    hash.update(&plan.stage101.output_ref.sha256);
    hash.update(&plan.stage101.stage_manifest_ref.sha256);
    hash.update(&plan.planned_semantic.identity_sha256);
    hash.update(&plan.semantic.identity);
    hash.update(&plan.execution.identity);
    hashBytes(&hash, plan.node.node_id);
    hashBytes(&hash, plan.paths.output_path);
    hashBytes(&hash, plan.paths.profile_receipt_path);
    hashBytes(&hash, plan.paths.candidate_ref_path);
    return hash.finalResult();
}

fn hashBytes(hash: *Sha256, bytes: []const u8) void {
    hashInt(hash, u64, @intCast(bytes.len));
    hash.update(bytes);
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn assertTypes(
    comptime Engine: type,
    comptime AuthenticatedStage101: type,
    comptime FinalFixture: type,
    comptime Lifecycle: type,
    comptime TreeGate: type,
) void {
    inline for (.{
        "EngineV4",
        "OwnedCampaignV4",
        "PublicationV4",
    }) |name| if (!@hasDecl(AuthenticatedStage101, name))
        @compileError("authenticated Stage101 family missing " ++ name);
    inline for (.{
        "OwnedFinalV2",
        "Role0AuthorityV4",
    }) |name| if (!@hasDecl(FinalFixture, name))
        @compileError("genuine final fixture missing " ++ name);
    inline for (.{
        "AuthorityV4",
        "OwnedBuildingV4",
        "OwnedQuiescedV4",
        "OwnedSealedV4",
        "OwnedFinalSessionV4",
        "ReplayProviderV4",
        "beginForGenuineGate",
    }) |name| if (!@hasDecl(Lifecycle, name))
        @compileError("genuine Stage102 lifecycle missing " ++ name);
    inline for (.{
        "FinalOwnerV2",
        "FinalSessionOwnerV4",
        "OwnedTreeV2",
    }) |name| if (!@hasDecl(TreeGate, name))
        @compileError("genuine three-leaf tree gate missing " ++ name);
    inline for (.{
        "validate",
        "campaignTable",
        "leafCount",
        "publicationAt",
        "retainedFreshInputAt",
        "fillStage101Admissions",
    }) |name| if (!@hasDecl(AuthenticatedStage101.OwnedCampaignV4, name))
        @compileError("authenticated Stage101 owner missing " ++ name);
    inline for (.{
        "buildForGenuineGate",
        "adoptForGenuineGate",
        "workerView",
        "builderView",
        "quiesceForGenuineGate",
    }) |name| if (!@hasDecl(Lifecycle.OwnedBuildingV4, name))
        @compileError("genuine Stage102 build owner missing " ++ name);
    if (!@hasDecl(
        Lifecycle.OwnedQuiescedV4,
        "sealCompleteForGenuineGate",
    ) or !@hasDecl(
        Lifecycle.OwnedSealedV4,
        "installImmutableForGenuineGate",
    ) or !@hasDecl(
        Lifecycle.OwnedFinalSessionV4,
        "immutableSession",
    ) or !@hasDecl(
        Lifecycle.OwnedFinalSessionV4,
        "validate",
    ) or !@hasDecl(
        Lifecycle.BuilderV4,
        "adoptedCount",
    ) or !@hasDecl(
        Lifecycle.BuildWorkerV4,
        "validateRetainedLeaseIdentity",
    )) @compileError("genuine Stage102 lifecycle exact-body API drifted");
    inline for (.{
        "proveAndSealForGenuineGate",
        "validate",
        "rootOutputRef",
        "rootStageManifestRef",
        "deinit",
    }) |name| if (!@hasDecl(TreeGate.OwnedTreeV2, name))
        @compileError("genuine tree owner missing " ++ name);
    if (AuthenticatedStage101.EngineV4 != Engine or
        FinalFixture.EngineV4 != Engine or
        FinalFixture.Role0AuthorityV4 != Lifecycle.AuthorityV4 or
        TreeGate.FinalOwnerV2 != FinalFixture.OwnedFinalV2 or
        TreeGate.FinalSessionOwnerV4 != Lifecycle.OwnedFinalSessionV4)
    {
        @compileError("genuine Stage101/102/tree nominal types drifted");
    }
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("genuine Stage102 lifecycle owner gained a codec");
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        GENUINE_Q193_GATE_GREEN or !GENUINE_GATE_ONLY or
        SERIALIZABLE_FRESH_CAPABILITY or SERIALIZABLE_LIVE_LEASE_SELECTOR or
        !AUTHENTICATED_STAGE101_REQUIRED or
        !BUILD_THEN_INDEPENDENT_COLD_OPEN_REQUIRED or
        !QUIESCE_BEFORE_IMMUTABLE_INSTALL_REQUIRED or
        !EXECUTION_POLICY_HAS_NO_SERIAL_FALLBACK or
        !RUNTIME_CAMPAIGN_CARDINALITY_REQUIRED)
    {
        @compileError("genuine Stage102/tree lifecycle contract drifted");
    }
}
