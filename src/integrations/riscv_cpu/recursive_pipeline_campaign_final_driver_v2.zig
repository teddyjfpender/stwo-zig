//! Seal-last runtime-shape driver for the final campaign frontier.
//!
//! The Stage102 epoch is already sealed and immutable. This driver validates
//! its cold-open receipts, appends the campaign-native Stage103 empty leaves,
//! and then admits Stage104 one complete level at a time. Every receipt is
//! reopened from the shared CAS, checked against its Zig keys and execution
//! policy, and required to carry a complete transitive StageManifest before
//! it may become a parent input. Lease IDs remain process-local strings; no
//! proof capability, lease, or validation token is serialized here.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const support = @import("recursive_pipeline_worker_support_v1.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const campaign_store = @import("recursive_campaign_node_artifact_store_v2.zig");
const campaign_cas = @import("recursive_pipeline_worker_campaign_cas_v2.zig");
const consumers = @import("recursive_pipeline_worker_campaign_consumers_v2.zig");
const real_worker =
    @import("recursive_pipeline_worker_campaign_real_leaf_v4.zig");
const empty_source =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const scheduler = @import("recursive_pipeline_level_scheduler_v2.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const GENUINE_Q193_GATE_GREEN = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const STAGE102_SESSION_IS_IMMUTABLE = true;
pub const MANIFEST_IS_SEAL_LAST = true;
pub const EVERY_PARENT_REQUIRES_TWO_COLD_LEASES = true;
pub const TOPOLOGY_IS_RUNTIME_SHAPE_BOUND = true;
pub const EXECUTION_POLICY_IS_EXACT = true;
pub const BINARY_CHILD_COUNT: u32 = 2;
pub const RUNTIME_PLAN_DESCRIPTION_IS_PATH_FREE = true;
pub const RUNTIME_PLAN_DOES_NOT_PREDICT_OUTPUT_REFS = true;
pub const RUNTIME_PLAN_LEVELS_ARE_INCREMENTAL = true;

pub const Shape = shape_mod.CampaignShapeAuthorityV2;
pub const Policy = policy_mod.PolicyV2;
pub const FinalRemint = final_mod.CampaignFinalRemintAuthorityV2;
pub const Artifact = campaign_artifact.Artifact;
pub const Coordinate = campaign_artifact.TaskCoordinate;
pub const Role = @import("recursive_circuit_registry_v1.zig").CircuitRoleV1;

pub const Error = error{
    CampaignFinalDriverAlias,
    CampaignFinalDriverExecutionMismatch,
    CampaignFinalDriverFrontierMismatch,
    CampaignFinalDriverLeaseMissing,
    CampaignFinalDriverManifestMismatch,
    CampaignFinalDriverSessionMismatch,
    CampaignFinalDriverStageMismatch,
    CampaignFinalDriverTopologyMismatch,
};

/// Complete worker cold-open result. All pointers borrow the immutable plan
/// or sealed Stage102 session and must outlive validation. `lease_id` is only
/// a process-local selector into the active worker's typed lease table.
pub const CommittedStageV2 = struct {
    node: *const protocol.Node,
    semantic: *const artifact_store.SemanticKeyV1,
    execution: *const artifact_store.ExecutionKeyV1,
    ordered_inputs: []const artifact_store.InputRefV1,
    output_ref: artifact_store.BlobRefV1,
    stage_manifest_ref: artifact_store.BlobRefV1,
    dependency_stage_manifest_refs: []const artifact_store.BlobRefV1,
    lease_id: []const u8,
};

pub const ValidatedCommittedStageV2 = struct {
    receipt: *const CommittedStageV2,
    artifact: Artifact,
    role: Role,
};

/// Path-free controller authority for the post-Stage102 campaign.  It binds
/// the exact runtime topology, final registry, and execution-only CPU/RSS
/// policy.  Output and StageManifest refs are intentionally absent: each
/// Stage104 level is described only after its child outputs have sealed.
pub const RuntimePlanDescriptionV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    campaign_namespace_sha256: [32]u8,
    campaign_shape_identity_sha256: [32]u8,
    final_remint_binding_identity_sha256: [32]u8,
    registry_identity_sha256: [32]u8,
    host_execution_identity_sha256: [32]u8,
    worker_policy_identity_sha256: [32]u8,
    memory_policy_identity_sha256: [32]u8,
    real_leaf_count: u32,
    padded_leaf_count: u32,
    empty_leaf_count: u32,
    fold_count: u32,
    root_height: u8,
    topology_reserved: [3]u8 = .{ 0, 0, 0 },
    total_cpu_tokens: u16,
    cpu_tokens_per_node: u16,
    proof_worker_count: u16,
    maximum_parallel_nodes: u16,
    total_rss_bytes: u64,
    rss_bytes_per_node: u64,
    stage103_schema_version: u16 = 103,
    stage104_schema_version: u16 = 104,
    output_kind: artifact_store.ArtifactKindV1 = .recursion_node,
    output_schema_version: u16 = campaign_artifact.SCHEMA_VERSION,
    output_byte_count: u64 = campaign_artifact.ENCODED_BYTE_COUNT,
    identity_sha256: [32]u8,

    pub fn init(
        final_remint: *const FinalRemint,
        policy: *const Policy,
    ) !RuntimePlanDescriptionV2 {
        try final_remint.validateAgainstCampaign(
            final_remint.shape.campaign_namespace_sha256,
        );
        try policy.validate();
        const shape = final_remint.shape;
        const registry = try final_remint.registryAuthority();
        var result = RuntimePlanDescriptionV2{
            .campaign_namespace_sha256 = shape.campaign_namespace_sha256,
            .campaign_shape_identity_sha256 = shape.identity_sha256,
            .final_remint_binding_identity_sha256 = final_remint.binding_identity_sha256,
            .registry_identity_sha256 = registry.identity_sha256,
            .host_execution_identity_sha256 = policy.host.identity_sha256,
            .worker_policy_identity_sha256 = policy.worker_policy_identity,
            .memory_policy_identity_sha256 = policy.memory_policy_identity,
            .real_leaf_count = shape.real_leaf_count,
            .padded_leaf_count = shape.padded_leaf_count,
            .empty_leaf_count = shape.empty_leaf_count,
            .fold_count = shape.fold_count,
            .root_height = shape.root_height,
            .total_cpu_tokens = policy.total_cpu_tokens,
            .cpu_tokens_per_node = policy.cpu_tokens_per_node,
            .proof_worker_count = policy.proof_worker_count,
            .maximum_parallel_nodes = policy.maximum_parallel_nodes,
            .total_rss_bytes = policy.total_rss_bytes,
            .rss_bytes_per_node = policy.rss_bytes_per_node,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = runtimePlanIdentity(&result);
        try result.validate(final_remint, policy);
        return result;
    }

    pub fn validate(
        self: *const RuntimePlanDescriptionV2,
        final_remint: *const FinalRemint,
        policy: *const Policy,
    ) !void {
        try final_remint.validateAgainstCampaign(
            self.campaign_namespace_sha256,
        );
        try policy.validate();
        const shape = final_remint.shape;
        const registry = try final_remint.registryAuthority();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            !std.mem.allEqual(u8, &self.topology_reserved, 0) or
            !std.mem.eql(
                u8,
                &self.campaign_namespace_sha256,
                &shape.campaign_namespace_sha256,
            ) or !std.mem.eql(
            u8,
            &self.campaign_shape_identity_sha256,
            &shape.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.final_remint_binding_identity_sha256,
            &final_remint.binding_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.registry_identity_sha256,
            &registry.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.host_execution_identity_sha256,
            &policy.host.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.worker_policy_identity_sha256,
            &policy.worker_policy_identity,
        ) or !std.mem.eql(
            u8,
            &self.memory_policy_identity_sha256,
            &policy.memory_policy_identity,
        ) or self.real_leaf_count != shape.real_leaf_count or
            self.padded_leaf_count != shape.padded_leaf_count or
            self.empty_leaf_count != shape.empty_leaf_count or
            self.fold_count != shape.fold_count or
            self.root_height != shape.root_height or
            self.total_cpu_tokens != policy.total_cpu_tokens or
            self.cpu_tokens_per_node != policy.cpu_tokens_per_node or
            self.proof_worker_count != policy.proof_worker_count or
            self.maximum_parallel_nodes != policy.maximum_parallel_nodes or
            self.total_rss_bytes != policy.total_rss_bytes or
            self.rss_bytes_per_node != policy.rss_bytes_per_node or
            self.stage103_schema_version != 103 or
            self.stage104_schema_version != 104 or
            self.output_kind != .recursion_node or
            self.output_schema_version != campaign_artifact.SCHEMA_VERSION or
            self.output_byte_count != campaign_artifact.ENCODED_BYTE_COUNT or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &runtimePlanIdentity(self),
            ))
        {
            return error.CampaignFinalDriverTopologyMismatch;
        }
    }
};

pub const TopologyPlanV2 = struct {
    real_leaf_count: u32,
    padded_leaf_count: u32,
    empty_leaf_count: u32,
    fold_count: u32,
    level_count: u16,

    pub fn init(shape: *const Shape) !TopologyPlanV2 {
        try shape.validate();
        const level_count = std.math.add(
            u16,
            shape.root_height,
            1,
        ) catch return error.CampaignFinalDriverTopologyMismatch;
        const result = TopologyPlanV2{
            .real_leaf_count = shape.real_leaf_count,
            .padded_leaf_count = shape.padded_leaf_count,
            .empty_leaf_count = shape.empty_leaf_count,
            .fold_count = shape.fold_count,
            .level_count = level_count,
        };
        try result.validate(shape);
        return result;
    }

    pub fn validate(
        self: TopologyPlanV2,
        shape: *const Shape,
    ) !void {
        try shape.validate();
        if (self.real_leaf_count != shape.real_leaf_count or
            self.padded_leaf_count != shape.padded_leaf_count or
            self.empty_leaf_count != shape.empty_leaf_count or
            self.fold_count != shape.fold_count or
            self.level_count != @as(u16, shape.root_height) + 1)
        {
            return error.CampaignFinalDriverTopologyMismatch;
        }
    }

    pub fn nodeCountAt(
        self: TopologyPlanV2,
        shape: *const Shape,
        height: u8,
    ) !u32 {
        try self.validate(shape);
        return shape.nodeCount(height);
    }
};

/// Deterministic runtime-shape visitation. The caller maps each coordinate to
/// its already-Zig-derived Node/Semantic/Execution objects and sends it to the
/// typed composite worker; this function never derives a semantic key.
pub fn walkRuntimePlan(shape: *const Shape, visitor: anytype) !void {
    try shape.validate();
    var empty_index = shape.real_leaf_count;
    var empty_count: u32 = 0;
    while (empty_index < shape.padded_leaf_count) : (empty_index += 1) {
        try visitor.stage103(try campaign_public.coordinate(
            shape,
            0,
            empty_index,
        ));
        empty_count += 1;
    }
    var fold_count: u32 = 0;
    var height: u8 = 1;
    while (height <= shape.root_height) : (height += 1) {
        const count = try shape.nodeCount(height);
        var index: u32 = 0;
        while (index < count) : (index += 1) {
            const child_height = height - 1;
            const left_index = std.math.mul(
                u32,
                index,
                BINARY_CHILD_COUNT,
            ) catch return error.CampaignFinalDriverTopologyMismatch;
            const right_index = std.math.add(
                u32,
                left_index,
                1,
            ) catch return error.CampaignFinalDriverTopologyMismatch;
            try visitor.stage104(
                try campaign_public.coordinate(shape, height, index),
                try campaign_public.coordinate(
                    shape,
                    child_height,
                    left_index,
                ),
                try campaign_public.coordinate(
                    shape,
                    child_height,
                    right_index,
                ),
            );
            fold_count += 1;
        }
    }
    if (empty_count != shape.empty_leaf_count or
        fold_count != shape.fold_count)
    {
        return error.CampaignFinalDriverTopologyMismatch;
    }
}

/// Validates the path-free authority immediately before visiting its runtime
/// coordinates.  The visitor may emit the next worker request, but must wait
/// for the resulting cold-open output/StageManifest receipt before it can
/// materialize a parent node.
pub fn walkDescribedRuntimePlan(
    description: *const RuntimePlanDescriptionV2,
    final_remint: *const FinalRemint,
    policy: *const Policy,
    visitor: anytype,
) !void {
    try description.validate(final_remint, policy);
    try walkRuntimePlan(final_remint.shape, visitor);
}

/// `Session` is the immutable `SessionFor` view owned by Mill's final
/// lifecycle. `Adapter` is the post-Stage102 typed composite worker adapter.
pub fn DriverFor(comptime Session: type, comptime Adapter: type) type {
    assertSession(Session);
    assertAdapter(Adapter);
    return struct {
        const Self = @This();

        store: *artifact_store.Store,
        session: *const Session,
        final_remint: *const FinalRemint,
        shape: *const Shape,
        policy: *const Policy,

        pub fn init(
            allocator: std.mem.Allocator,
            session: *const Session,
        ) !Self {
            try session.validate(allocator);
            const final_remint = session.authority.final_remint;
            const shape = final_remint.shape;
            try final_remint.validateAgainstCampaign(
                shape.campaign_namespace_sha256,
            );
            try session.policy.validate();
            const result = Self{
                .store = session.store,
                .session = session,
                .final_remint = final_remint,
                .shape = shape,
                .policy = session.policy,
            };
            try result.validateIdentity(allocator);
            return result;
        }

        pub fn validateIdentity(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) !void {
            try self.session.validate(allocator);
            try self.final_remint.validateAgainstCampaign(
                self.shape.campaign_namespace_sha256,
            );
            try self.shape.validate();
            try self.policy.validate();
            if (self.store != self.session.store or
                self.final_remint != self.session.authority.final_remint or
                self.shape != self.final_remint.shape or
                self.policy != self.session.policy)
            {
                return error.CampaignFinalDriverSessionMismatch;
            }
        }

        /// Validates the complete height-zero frontier. Real receipts exact-
        /// match the immutable Stage102 admission row; empty receipts must
        /// cold-open their own per-index 1,892-byte campaign source.
        pub fn validateLeafFrontier(
            self: *const Self,
            allocator: std.mem.Allocator,
            receipts: []const CommittedStageV2,
        ) !void {
            try self.validateIdentity(allocator);
            const expected = try self.shape.nodeCount(0);
            if (receipts.len != @as(usize, @intCast(expected)))
                return error.CampaignFinalDriverFrontierMismatch;
            for (receipts, 0..) |*receipt, index| {
                const validated = try self.validateCommitted(
                    allocator,
                    receipt,
                );
                const coordinate = validated.artifact.coordinate;
                if (coordinate.height != 0 or
                    coordinate.index != @as(u32, @intCast(index)))
                {
                    return error.CampaignFinalDriverTopologyMismatch;
                }
                if (index < @as(
                    usize,
                    @intCast(self.shape.real_leaf_count),
                )) {
                    try self.validateRealLeaf(
                        allocator,
                        receipt,
                        &validated.artifact,
                        index,
                    );
                } else {
                    try self.validateEmptyLeaf(
                        receipt,
                        &validated.artifact,
                    );
                }
            }
            try validateUniqueReceipts(receipts);
        }

        /// Binds Mill's cold-owned ordered role-0 frontier to the receipt
        /// prefix consumed by this driver. `frontier` is intentionally an
        /// exact nominal owner, not a serialized projection or digest cast.
        pub fn validateRole0Frontier(
            self: *const Self,
            allocator: std.mem.Allocator,
            frontier: anytype,
            receipts: []const CommittedStageV2,
        ) !void {
            try self.validateIdentity(allocator);
            try frontier.validate(allocator);
            const rows = frontier.orderedRows();
            if (rows.len != @as(
                usize,
                @intCast(self.shape.real_leaf_count),
            ) or receipts.len != rows.len or frontier.policy != self.policy) {
                return error.CampaignFinalDriverFrontierMismatch;
            }
            for (rows, receipts, 0..) |row, *receipt, index| {
                try row.role0.validate();
                const validated = try self.validateCommitted(
                    allocator,
                    receipt,
                );
                try self.validateRealLeaf(
                    allocator,
                    receipt,
                    &validated.artifact,
                    index,
                );
                if (row.coordinate != @as(u32, @intCast(index)) or
                    validated.role !=
                        .ethereum_incremental_leaf_wrapper_v4 or
                    validated.artifact.coordinate.height != 0 or
                    validated.artifact.coordinate.index != row.coordinate or
                    row.role0.final_remint != self.final_remint or
                    row.role0.admission !=
                        &self.session.entries[index].admission or
                    !artifact_store.BlobRefV1.eql(
                        row.publication.output_ref,
                        receipt.output_ref,
                    ) or !artifact_store.BlobRefV1.eql(
                    row.publication.stage_manifest_ref,
                    receipt.stage_manifest_ref,
                )) return error.CampaignFinalDriverFrontierMismatch;
                const projection = try row.role0.lease
                    .campaignFoldProjection(self.final_remint);
                try projection.validateAgainstFinal(self.final_remint);
                if (projection.node_artifact !=
                    row.role0.lease.nodeArtifact())
                {
                    return error.CampaignFinalDriverFrontierMismatch;
                }
            }
            try validateUniqueReceipts(receipts);
        }

        /// Validates one complete parent level against the exact preceding
        /// level. The shape, rather than a campaign literal, supplies every
        /// coordinate and count.
        pub fn validateLevel(
            self: *const Self,
            allocator: std.mem.Allocator,
            height: u8,
            children: []const CommittedStageV2,
            parents: []const CommittedStageV2,
        ) !void {
            try self.validateIdentity(allocator);
            if (height == 0 or height > self.shape.root_height or
                children.len != @as(
                    usize,
                    @intCast(try self.shape.nodeCount(height - 1)),
                ) or parents.len != @as(
                usize,
                @intCast(try self.shape.nodeCount(height)),
            )) return error.CampaignFinalDriverTopologyMismatch;
            for (parents, 0..) |*parent_receipt, index| {
                const left_receipt = &children[index * 2];
                const right_receipt = &children[index * 2 + 1];
                const left = try self.validateCommitted(
                    allocator,
                    left_receipt,
                );
                const right = try self.validateCommitted(
                    allocator,
                    right_receipt,
                );
                const parent = try self.validateCommitted(
                    allocator,
                    parent_receipt,
                );
                const expected_coordinate = try campaign_public.coordinate(
                    self.shape,
                    height,
                    @intCast(index),
                );
                if (parent.role != .common_fold_field_v2 or
                    !std.meta.eql(
                        parent.artifact.coordinate,
                        expected_coordinate,
                    ) or parent.artifact.child_count != 2 or
                    !artifact_store.BlobRefV1.eql(
                        parent_receipt.ordered_inputs[0].blob,
                        left_receipt.output_ref,
                    ) or !artifact_store.BlobRefV1.eql(
                    parent_receipt.ordered_inputs[1].blob,
                    right_receipt.output_ref,
                ) or !artifact_store.BlobRefV1.eql(
                    parent_receipt.dependency_stage_manifest_refs[0],
                    left_receipt.stage_manifest_ref,
                ) or !artifact_store.BlobRefV1.eql(
                    parent_receipt.dependency_stage_manifest_refs[1],
                    right_receipt.stage_manifest_ref,
                ) or !std.mem.eql(
                    u8,
                    parent_receipt.node.dependencies[0].node_id,
                    left_receipt.node.node_id,
                ) or !std.mem.eql(
                    u8,
                    parent_receipt.node.dependencies[1].node_id,
                    right_receipt.node.node_id,
                )) return error.CampaignFinalDriverTopologyMismatch;
                try campaign_public.validateParentAgainst(
                    self.shape,
                    &parent.artifact.node_public,
                    &left.artifact.node_public,
                    &right.artifact.node_public,
                );
                const expected_stage: campaign_artifact.StageKind =
                    if (height == self.shape.root_height) .root else .fold;
                if (parent.artifact.stage_kind != expected_stage)
                    return error.CampaignFinalDriverStageMismatch;
            }
            try validateUniqueReceipts(parents);
        }

        /// `levels[0]` is the full real+empty frontier. Each subsequent slice
        /// is one complete fold level; the last slice contains the sole root.
        pub fn validateComplete(
            self: *const Self,
            allocator: std.mem.Allocator,
            levels: []const []const CommittedStageV2,
        ) !*const CommittedStageV2 {
            const level_count = std.math.add(
                usize,
                @as(usize, self.shape.root_height),
                1,
            ) catch return error.CampaignFinalDriverTopologyMismatch;
            if (levels.len != level_count)
                return error.CampaignFinalDriverTopologyMismatch;
            try self.validateLeafFrontier(allocator, levels[0]);
            var height: u8 = 1;
            while (height <= self.shape.root_height) : (height += 1) {
                try self.validateLevel(
                    allocator,
                    height,
                    levels[height - 1],
                    levels[height],
                );
            }
            try validateUniqueCampaign(levels);
            const root_level = levels[self.shape.root_height];
            if (root_level.len != 1)
                return error.CampaignFinalDriverTopologyMismatch;
            return &root_level[0];
        }

        pub fn admitHighestReadyLevel(
            self: *const Self,
            ready_by_height: []const u32,
        ) !?scheduler.LevelAdmissionV2 {
            return scheduler.selectHighestReadyLevel(
                self.shape,
                self.policy,
                ready_by_height,
            );
        }

        pub fn validateCommitted(
            self: *const Self,
            allocator: std.mem.Allocator,
            receipt: *const CommittedStageV2,
        ) !ValidatedCommittedStageV2 {
            if (receipt.lease_id.len == 0)
                return error.CampaignFinalDriverLeaseMissing;
            if (!Adapter.acceptsNodeAdapter(receipt.node.adapter))
                return error.CampaignFinalDriverStageMismatch;
            try receipt.semantic.validate(allocator);
            try receipt.execution.validate();
            try self.policy.validateAgainstExecution(receipt.execution.*);
            if (receipt.node.cpu_tokens !=
                @as(u64, self.policy.cpu_tokens_per_node) or
                receipt.node.rss_tokens != self.policy.rss_bytes_per_node or
                !std.mem.eql(
                    u8,
                    &receipt.execution.fields.semantic_key_identity,
                    &receipt.semantic.identity,
                )) return error.CampaignFinalDriverExecutionMismatch;
            try campaign_cas.validate(receipt.output_ref, .recursion_node);
            try campaign_cas.validate(
                receipt.stage_manifest_ref,
                .stage_manifest,
            );
            for (receipt.dependency_stage_manifest_refs) |manifest|
                try campaign_cas.validate(manifest, .stage_manifest);

            const artifact = try campaign_store.coldOpenRecursiveNodeTransport(
                self.store,
                self.shape,
                receipt.output_ref,
            );
            const role = try artifactRole(&artifact);
            const geometry = try self.final_remint.geometryForRole(role);
            try campaign_artifact.admitRegistry(
                try self.final_remint.registryAuthority(),
                self.shape,
                &artifact,
                geometry,
            );
            const projected = try campaign_artifact.semanticInputsForStore(
                self.shape,
                &artifact,
            );
            switch (role) {
                .ethereum_incremental_leaf_wrapper_v4 => try real_worker.validateSemanticProjectionV4(
                    allocator,
                    self.shape,
                    receipt.node.*,
                    receipt.semantic,
                    receipt.ordered_inputs,
                    &projected,
                ),
                .canonical_empty_field_v2, .common_fold_field_v2 => try consumers.validateSemanticProjectionV2(
                    allocator,
                    self.shape,
                    receipt.node.*,
                    receipt.semantic,
                    receipt.ordered_inputs,
                    &projected,
                ),
            }
            const expected_stage_schema = try campaign_store
                .stageSchemaVersion(self.shape, &projected);
            const description = try Adapter.describe(
                receipt.node.stage_kind,
                receipt.node.stage_schema_version,
            );
            if (receipt.node.stage_schema_version != expected_stage_schema or
                description.output_kind != .recursion_node or
                description.output_schema_version !=
                    campaign_artifact.SCHEMA_VERSION or
                receipt.dependency_stage_manifest_refs.len !=
                    receipt.node.dependencies.len)
            {
                return error.CampaignFinalDriverStageMismatch;
            }
            const proof_ref = try node_store.toSharedRef(artifact.proof_ref);
            try campaign_cas.validate(proof_ref, .proof);
            try support.validateExistingStageManifest(
                allocator,
                self.store,
                receipt.stage_manifest_ref,
                receipt.node.*,
                receipt.ordered_inputs,
                receipt.semantic.*,
                receipt.execution.*,
                receipt.output_ref,
                receipt.dependency_stage_manifest_refs,
                "root",
            );
            return .{ .receipt = receipt, .artifact = artifact, .role = role };
        }

        fn validateRealLeaf(
            self: *const Self,
            allocator: std.mem.Allocator,
            receipt: *const CommittedStageV2,
            artifact: *const Artifact,
            index: usize,
        ) !void {
            if (index >= self.session.entries.len or
                artifact.node_kind != .real or
                receipt.node.stage_schema_version != 102)
            {
                return error.CampaignFinalDriverSessionMismatch;
            }
            const entry = &self.session.entries[index];
            try entry.admission.validate(
                allocator,
                self.store,
                self.session.authority,
                self.final_remint,
                entry.output_ref,
                artifact,
            );
            if (!artifact_store.BlobRefV1.eql(
                receipt.output_ref,
                entry.output_ref,
            ) or !artifact_store.BlobRefV1.eql(
                receipt.stage_manifest_ref,
                entry.admission.stage_manifest_ref,
            ) or receipt.node != entry.admission.node or
                receipt.semantic != entry.admission.semantic or
                receipt.execution != entry.admission.execution or
                receipt.ordered_inputs.ptr !=
                    entry.admission.ordered_inputs.ptr or
                receipt.dependency_stage_manifest_refs.len != 1 or
                !artifact_store.BlobRefV1.eql(
                    receipt.dependency_stage_manifest_refs[0],
                    entry.admission.dependency_stage_manifest_ref,
                )) return error.CampaignFinalDriverSessionMismatch;
        }

        fn validateEmptyLeaf(
            self: *const Self,
            receipt: *const CommittedStageV2,
            artifact: *const Artifact,
        ) !void {
            if (artifact.node_kind != .empty or
                receipt.node.stage_schema_version != 103 or
                receipt.dependency_stage_manifest_refs.len != 0 or
                receipt.ordered_inputs.len != 1)
            {
                return error.CampaignFinalDriverStageMismatch;
            }
            const source_ref = receipt.ordered_inputs[0].blob;
            try campaign_cas.validate(source_ref, .stage103_source);
            var source_blob = try self.store.openBlob(
                source_ref,
                .source,
                empty_source.SCHEMA_VERSION,
                empty_source.SOURCE_ENCODED_BYTE_COUNT,
            );
            defer source_blob.deinit(self.store.allocator);
            const source = try empty_source.ColdInputV2.open(
                self.shape,
                source_blob.bytes,
            );
            if (!std.meta.eql(
                try source.coordinate(),
                artifact.coordinate,
            )) return error.CampaignFinalDriverTopologyMismatch;
        }
    };
}

pub fn validateReceiptEnvelope(
    receipt: *const CommittedStageV2,
    policy: *const Policy,
    expected_stage_schema: u16,
    expected_dependency_count: usize,
) !void {
    try policy.validate();
    try receipt.execution.validate();
    if (receipt.lease_id.len == 0 or
        receipt.node.stage_schema_version != expected_stage_schema or
        receipt.node.dependencies.len != expected_dependency_count or
        receipt.dependency_stage_manifest_refs.len !=
            expected_dependency_count or
        receipt.node.cpu_tokens != @as(u64, policy.cpu_tokens_per_node) or
        receipt.node.rss_tokens != policy.rss_bytes_per_node or
        !std.mem.eql(
            u8,
            &receipt.execution.fields.semantic_key_identity,
            &receipt.semantic.identity,
        ))
    {
        return error.CampaignFinalDriverExecutionMismatch;
    }
    try policy.validateAgainstExecution(receipt.execution.*);
    try campaign_cas.validate(receipt.output_ref, .recursion_node);
    try campaign_cas.validate(
        receipt.stage_manifest_ref,
        .stage_manifest,
    );
    for (receipt.dependency_stage_manifest_refs) |manifest|
        try campaign_cas.validate(manifest, .stage_manifest);
}

pub fn validateReceiptSet(receipts: []const CommittedStageV2) !void {
    try validateUniqueReceipts(receipts);
}

fn artifactRole(artifact: *const Artifact) !Role {
    return switch (artifact.stage_kind) {
        .leaf_wrapper => switch (artifact.node_kind) {
            .real => .ethereum_incremental_leaf_wrapper_v4,
            .empty => .canonical_empty_field_v2,
            .mixed => error.CampaignFinalDriverStageMismatch,
        },
        .fold, .root => .common_fold_field_v2,
    };
}

fn validateUniqueReceipts(receipts: []const CommittedStageV2) !void {
    for (receipts, 0..) |receipt, index| {
        for (receipts[0..index]) |earlier| {
            if (artifact_store.BlobRefV1.eql(
                receipt.output_ref,
                earlier.output_ref,
            ) or artifact_store.BlobRefV1.eql(
                receipt.stage_manifest_ref,
                earlier.stage_manifest_ref,
            ) or std.mem.eql(u8, receipt.lease_id, earlier.lease_id)) {
                return error.CampaignFinalDriverAlias;
            }
        }
    }
}

fn validateUniqueCampaign(
    levels: []const []const CommittedStageV2,
) !void {
    for (levels, 0..) |level, level_index| {
        for (level, 0..) |receipt, receipt_index| {
            for (levels[0..level_index]) |earlier_level| {
                for (earlier_level) |earlier| try requireDistinct(
                    receipt,
                    earlier,
                );
            }
            for (level[0..receipt_index]) |earlier| try requireDistinct(
                receipt,
                earlier,
            );
        }
    }
}

fn requireDistinct(
    left: CommittedStageV2,
    right: CommittedStageV2,
) !void {
    if (artifact_store.BlobRefV1.eql(left.output_ref, right.output_ref) or
        artifact_store.BlobRefV1.eql(
            left.stage_manifest_ref,
            right.stage_manifest_ref,
        ) or std.mem.eql(u8, left.lease_id, right.lease_id))
    {
        return error.CampaignFinalDriverAlias;
    }
}

fn runtimePlanIdentity(value: *const RuntimePlanDescriptionV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/recursive-pipeline-campaign-final-plan/v2\x00");
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hash.update(&value.reserved);
    inline for (.{
        value.campaign_namespace_sha256,
        value.campaign_shape_identity_sha256,
        value.final_remint_binding_identity_sha256,
        value.registry_identity_sha256,
        value.host_execution_identity_sha256,
        value.worker_policy_identity_sha256,
        value.memory_policy_identity_sha256,
    }) |identity| hash.update(&identity);
    hashInt(&hash, u32, value.real_leaf_count);
    hashInt(&hash, u32, value.padded_leaf_count);
    hashInt(&hash, u32, value.empty_leaf_count);
    hashInt(&hash, u32, value.fold_count);
    hashInt(&hash, u8, value.root_height);
    hash.update(&value.topology_reserved);
    hashInt(&hash, u16, value.total_cpu_tokens);
    hashInt(&hash, u16, value.cpu_tokens_per_node);
    hashInt(&hash, u16, value.proof_worker_count);
    hashInt(&hash, u16, value.maximum_parallel_nodes);
    hashInt(&hash, u64, value.total_rss_bytes);
    hashInt(&hash, u64, value.rss_bytes_per_node);
    hashInt(&hash, u16, value.stage103_schema_version);
    hashInt(&hash, u16, value.stage104_schema_version);
    hashInt(&hash, u32, @intFromEnum(value.output_kind));
    hashInt(&hash, u16, value.output_schema_version);
    hashInt(&hash, u64, value.output_byte_count);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn assertSession(comptime Session: type) void {
    inline for (.{"validate"}) |name| if (!@hasDecl(Session, name))
        @compileError("campaign final driver session missing " ++ name);
    inline for (.{ "store", "authority", "entries", "policy" }) |name|
        if (!@hasField(Session, name))
            @compileError("campaign final driver session field missing " ++ name);
    rejectCodec(Session);
}

fn assertAdapter(comptime Adapter: type) void {
    inline for (.{
        "available",
        "LeasePayload",
        "acceptsNodeAdapter",
        "describe",
        "buildOutputWithExecutionAndLeases",
        "coldOpenLease",
        "deinitLeasePayload",
    }) |name| if (!@hasDecl(Adapter, name))
        @compileError("campaign final driver adapter missing " ++ name);
    rejectCodec(Adapter.LeasePayload);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign final driver capability gained a codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        GENUINE_Q193_GATE_GREEN or SERIALIZABLE_FRESH_CAPABILITY or
        !STAGE102_SESSION_IS_IMMUTABLE or !MANIFEST_IS_SEAL_LAST or
        !EVERY_PARENT_REQUIRES_TWO_COLD_LEASES or
        !TOPOLOGY_IS_RUNTIME_SHAPE_BOUND or !EXECUTION_POLICY_IS_EXACT or
        BINARY_CHILD_COUNT != 2 or
        !RUNTIME_PLAN_DESCRIPTION_IS_PATH_FREE or
        !RUNTIME_PLAN_DOES_NOT_PREDICT_OUTPUT_REFS or
        !RUNTIME_PLAN_LEVELS_ARE_INCREMENTAL)
    {
        @compileError("campaign final driver contract drifted");
    }
}
