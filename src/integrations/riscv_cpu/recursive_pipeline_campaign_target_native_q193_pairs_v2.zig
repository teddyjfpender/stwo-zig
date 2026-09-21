//! Unrouteable genuine-q193 fixture boundary for campaign Stage103/104.
//!
//! The final controller already owns canonical Stage103/104 descriptions,
//! while the proof families own the verifier capabilities.  This module is
//! the narrow typed bridge used to gate those two layers before routing is
//! enabled: it derives every Stage104 child-role pair from the authenticated
//! runtime campaign shape, checks the exact nominal leases against that plan,
//! and invokes the target-native role-1/role-2 proof cores with the worker
//! count selected by the description's sealed ExecutionKey policy.  RSS is
//! admission authority only and is rechecked on the node; it is never mixed
//! into a proof transcript.
//!
//! The role-2 entrypoints deliberately return the core cold proof rather than
//! a durable node or worker lease.  They exist only to run prove -> encode ->
//! destroy -> fresh-cold-open gates for each nominal pair.  Production still
//! requires the normal Stage104 backend to publish and recursively cold-open
//! the node and both children.  Nothing in this file has a codec or a route.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const worker_support = @import("recursive_pipeline_worker_support_v1.zig");
const consumers = @import("recursive_pipeline_worker_campaign_consumers_v2.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const description_mod = @import("recursive_pipeline_campaign_final_description_v2.zig");
const final_driver = @import("recursive_pipeline_campaign_final_driver_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_cas = @import("recursive_pipeline_worker_campaign_cas_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const role1_source = @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const role1_proof = @import("recursive_common_canonical_empty_campaign_universal_proof_v2.zig");
const role1_child = @import("recursive_common_canonical_empty_campaign_fold_child_v2.zig");
const secure_engine = @import("recursive_temporal_secure_parent_native_engine_v1.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const ROLE1_Q193_GENUINE_GATE_GREEN = false;
pub const ROLE2_NOMINAL_PAIR_Q193_GATES_GREEN = false;
pub const GENUINE_GATE_ONLY = true;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const PAIRS_ARE_RUNTIME_SHAPE_DERIVED = true;
pub const EXECUTION_KEY_WORKER_POLICY_REQUIRED = true;
pub const EXECUTION_KEY_RSS_POLICY_REQUIRED = true;
pub const ROLE2_GATE_OUTPUT_IS_NOT_A_DURABLE_NODE = true;
pub const GATE_PUBLICATION_IS_CREATE_ONLY = true;
pub const GATE_MANIFEST_IS_SEAL_LAST = true;
pub const CHILD_COUNT: usize = 2;

pub const Shape = shape_mod.CampaignShapeAuthorityV2;
pub const FinalRemint = final_mod.CampaignFinalRemintAuthorityV2;
pub const Coordinate = campaign_public.TaskCoordinateV1;
pub const Role = registry_mod.CircuitRoleV1;
pub const Policy = policy_mod.PolicyV2;
pub const StageDescription = description_mod.OwnedStageDescriptionV2;

pub const Error = error{
    CampaignTargetNativeExecutionMismatch,
    CampaignTargetNativeLifecycleMismatch,
    CampaignTargetNativeNominalPairMismatch,
    CampaignTargetNativePublicationMismatch,
    CampaignTargetNativeRole1Mismatch,
    CampaignTargetNativeRole2Mismatch,
};

/// These are the only ordered nominal pairs reachable in a prefix-real,
/// suffix-empty binary campaign.  `empty_real` is intentionally absent.
pub const NominalPairKindV2 = enum(u8) {
    real_real = 0,
    real_empty = 1,
    empty_empty = 2,
    common_common = 3,
};

pub const PairPlanV2 = struct {
    final_remint: *const FinalRemint,
    campaign_shape_identity_sha256: [32]u8,
    final_remint_binding_identity_sha256: [32]u8,
    parent: Coordinate,
    children: [CHILD_COUNT]Coordinate,
    roles: [CHILD_COUNT]Role,
    kind: NominalPairKindV2,

    pub fn init(
        final_remint: *const FinalRemint,
        parent: Coordinate,
    ) !PairPlanV2 {
        try final_remint.validateAgainstCampaign(
            final_remint.shape.campaign_namespace_sha256,
        );
        const shape = final_remint.shape;
        try campaign_public.validateCoordinate(shape, parent);
        if (parent.height == 0)
            return error.CampaignTargetNativeNominalPairMismatch;
        const child_height = parent.height - 1;
        const left_index = std.math.mul(
            u32,
            parent.index,
            CHILD_COUNT,
        ) catch return error.CampaignTargetNativeNominalPairMismatch;
        const right_index = std.math.add(
            u32,
            left_index,
            1,
        ) catch return error.CampaignTargetNativeNominalPairMismatch;
        const children = [CHILD_COUNT]Coordinate{
            try campaign_public.coordinate(shape, child_height, left_index),
            try campaign_public.coordinate(shape, child_height, right_index),
        };
        const roles = [CHILD_COUNT]Role{
            try roleForCoordinate(shape, children[0]),
            try roleForCoordinate(shape, children[1]),
        };
        const result = PairPlanV2{
            .final_remint = final_remint,
            .campaign_shape_identity_sha256 = shape.identity_sha256,
            .final_remint_binding_identity_sha256 = final_remint
                .binding_identity_sha256,
            .parent = parent,
            .children = children,
            .roles = roles,
            .kind = try kindForRoles(roles),
        };
        try result.validate(final_remint);
        return result;
    }

    pub fn validate(
        self: PairPlanV2,
        final_remint: *const FinalRemint,
    ) !void {
        if (self.final_remint != final_remint)
            return error.CampaignTargetNativeNominalPairMismatch;
        try final_remint.validateAgainstCampaign(
            final_remint.shape.campaign_namespace_sha256,
        );
        const shape = final_remint.shape;
        if (!std.mem.eql(
            u8,
            &self.campaign_shape_identity_sha256,
            &shape.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.final_remint_binding_identity_sha256,
            &final_remint.binding_identity_sha256,
        )) return error.CampaignTargetNativeNominalPairMismatch;
        const expected = try initUnchecked(final_remint, self.parent);
        if (!std.meta.eql(self, expected))
            return error.CampaignTargetNativeNominalPairMismatch;
    }

    fn initUnchecked(
        final_remint: *const FinalRemint,
        parent: Coordinate,
    ) !PairPlanV2 {
        const shape = final_remint.shape;
        try campaign_public.validateCoordinate(shape, parent);
        if (parent.height == 0)
            return error.CampaignTargetNativeNominalPairMismatch;
        const child_height = parent.height - 1;
        const left_index = std.math.mul(
            u32,
            parent.index,
            CHILD_COUNT,
        ) catch return error.CampaignTargetNativeNominalPairMismatch;
        const right_index = std.math.add(
            u32,
            left_index,
            1,
        ) catch return error.CampaignTargetNativeNominalPairMismatch;
        const children = [CHILD_COUNT]Coordinate{
            try campaign_public.coordinate(shape, child_height, left_index),
            try campaign_public.coordinate(shape, child_height, right_index),
        };
        const roles = [CHILD_COUNT]Role{
            try roleForCoordinate(shape, children[0]),
            try roleForCoordinate(shape, children[1]),
        };
        return .{
            .final_remint = final_remint,
            .campaign_shape_identity_sha256 = shape.identity_sha256,
            .final_remint_binding_identity_sha256 = final_remint
                .binding_identity_sha256,
            .parent = parent,
            .children = children,
            .roles = roles,
            .kind = try kindForRoles(roles),
        };
    }
};

/// Shape-derived inventory used by the genuine gate harness.  Counts are not
/// required to contain every kind for every campaign; they record exactly
/// which pair proofs this authenticated topology requires.
pub const NominalPairInventoryV2 = struct {
    final_remint: *const FinalRemint,
    counts: [4]u32,
    total: u32,

    pub fn init(final_remint: *const FinalRemint) !NominalPairInventoryV2 {
        try final_remint.validateAgainstCampaign(
            final_remint.shape.campaign_namespace_sha256,
        );
        var result = NominalPairInventoryV2{
            .final_remint = final_remint,
            .counts = @splat(0),
            .total = 0,
        };
        var height: u8 = 1;
        while (height <= final_remint.shape.root_height) : (height += 1) {
            const node_count = try final_remint.shape.nodeCount(height);
            var index: u32 = 0;
            while (index < node_count) : (index += 1) {
                const plan = try PairPlanV2.init(
                    final_remint,
                    try campaign_public.coordinate(
                        final_remint.shape,
                        height,
                        index,
                    ),
                );
                result.counts[@intFromEnum(plan.kind)] += 1;
                result.total += 1;
            }
        }
        try result.validate(final_remint);
        return result;
    }

    pub fn validate(
        self: NominalPairInventoryV2,
        final_remint: *const FinalRemint,
    ) !void {
        try final_remint.validateAgainstCampaign(
            final_remint.shape.campaign_namespace_sha256,
        );
        if (self.final_remint != final_remint or
            self.total != final_remint.shape.fold_count)
        {
            return error.CampaignTargetNativeNominalPairMismatch;
        }
        var counts: [4]u32 = @splat(0);
        var total: u32 = 0;
        var height: u8 = 1;
        while (height <= final_remint.shape.root_height) : (height += 1) {
            const node_count = try final_remint.shape.nodeCount(height);
            var index: u32 = 0;
            while (index < node_count) : (index += 1) {
                const plan = try PairPlanV2.init(
                    final_remint,
                    try campaign_public.coordinate(
                        final_remint.shape,
                        height,
                        index,
                    ),
                );
                counts[@intFromEnum(plan.kind)] += 1;
                total += 1;
            }
        }
        if (total != self.total or !std.meta.eql(counts, self.counts))
            return error.CampaignTargetNativeNominalPairMismatch;
    }

    pub fn count(
        self: NominalPairInventoryV2,
        kind: NominalPairKindV2,
    ) u32 {
        return self.counts[@intFromEnum(kind)];
    }
};

/// Path-free authority shared by the coordinated genuine role-1/role-2 gate.
/// It is rebuilt from the same FinalRemint and Policy consumed by the final
/// driver, so the cryptographic fixture cannot silently select a different
/// campaign topology or execution envelope. It contains no output refs,
/// paths, lease selectors, or verifier capability.
pub const GenuineLifecyclePlanV2 = struct {
    final_remint: *const FinalRemint,
    policy: *const Policy,
    runtime_plan: final_driver.RuntimePlanDescriptionV2,
    pair_inventory: NominalPairInventoryV2,
    role1_proof_count: u32,
    role2_proof_count: u32,
    worker_count: usize,
    cpu_tokens_per_node: u64,
    rss_bytes_per_node: u64,

    pub fn init(
        final_remint: *const FinalRemint,
        policy: *const Policy,
    ) !GenuineLifecyclePlanV2 {
        try final_remint.validateAgainstCampaign(
            final_remint.shape.campaign_namespace_sha256,
        );
        try policy.validate();
        const result = GenuineLifecyclePlanV2{
            .final_remint = final_remint,
            .policy = policy,
            .runtime_plan = try final_driver.RuntimePlanDescriptionV2.init(
                final_remint,
                policy,
            ),
            .pair_inventory = try NominalPairInventoryV2.init(final_remint),
            .role1_proof_count = final_remint.shape.empty_leaf_count,
            .role2_proof_count = final_remint.shape.fold_count,
            .worker_count = try policy.engineWorkerCount(),
            .cpu_tokens_per_node = policy.cpu_tokens_per_node,
            .rss_bytes_per_node = policy.rss_bytes_per_node,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: *const GenuineLifecyclePlanV2) !void {
        try self.final_remint.validateAgainstCampaign(
            self.final_remint.shape.campaign_namespace_sha256,
        );
        try self.policy.validate();
        try self.runtime_plan.validate(self.final_remint, self.policy);
        try self.pair_inventory.validate(self.final_remint);
        const expected = try final_driver.RuntimePlanDescriptionV2.init(
            self.final_remint,
            self.policy,
        );
        if (!std.meta.eql(self.runtime_plan, expected) or
            self.pair_inventory.final_remint != self.final_remint or
            self.role1_proof_count !=
                self.final_remint.shape.empty_leaf_count or
            self.role2_proof_count != self.final_remint.shape.fold_count or
            self.worker_count != try self.policy.engineWorkerCount() or
            self.cpu_tokens_per_node != self.policy.cpu_tokens_per_node or
            self.rss_bytes_per_node != self.policy.rss_bytes_per_node)
        {
            return error.CampaignTargetNativeLifecycleMismatch;
        }
    }

    /// Returns the exact per-node execution binding only after proving that
    /// the canonical description belongs to this runtime plan.
    pub fn bindDescription(
        self: *const GenuineLifecyclePlanV2,
        scratch: std.mem.Allocator,
        description: *const StageDescription,
    ) !ExecutionBindingV2 {
        try self.validate();
        try description.validate(scratch);
        if (description.final_remint != self.final_remint or
            description.policy != self.policy)
        {
            return error.CampaignTargetNativeLifecycleMismatch;
        }
        const coordinate = description.planned_semantic.coordinate;
        try campaign_public.validateCoordinate(
            self.final_remint.shape,
            coordinate,
        );
        const expected_stage: artifact_store.StageKindV1 =
            switch (description.planned_semantic.stage_kind) {
                .leaf_wrapper => .prove,
                .fold, .root => .fold,
            };
        const expected_schema: u16 = switch (description.planned_semantic.stage_kind) {
            .leaf_wrapper => consumers.STAGE103_SCHEMA_VERSION,
            .fold, .root => consumers.STAGE104_SCHEMA_VERSION,
        };
        switch (description.planned_semantic.stage_kind) {
            .leaf_wrapper => {
                if (coordinate.height != 0 or
                    description.planned_semantic.node_kind != .empty or
                    try campaign_public.expectedNodeKind(
                        self.final_remint.shape,
                        coordinate,
                    ) != .empty)
                {
                    return error.CampaignTargetNativeLifecycleMismatch;
                }
            },
            .fold, .root => {
                const pair = try PairPlanV2.init(
                    self.final_remint,
                    coordinate,
                );
                if (pair.parent.height != coordinate.height)
                    return error.CampaignTargetNativeLifecycleMismatch;
                const expected_semantic_stage: campaign_artifact.StageKind =
                    if (coordinate.height ==
                    self.final_remint.shape.root_height)
                        .root
                    else
                        .fold;
                if (description.planned_semantic.stage_kind !=
                    expected_semantic_stage)
                {
                    return error.CampaignTargetNativeLifecycleMismatch;
                }
            },
        }
        const execution = try ExecutionBindingV2.fromDescription(
            scratch,
            description,
            expected_stage,
            expected_schema,
        );
        if (execution.worker_count != self.worker_count or
            execution.cpu_tokens != self.cpu_tokens_per_node or
            execution.rss_bytes != self.rss_bytes_per_node)
        {
            return error.CampaignTargetNativeLifecycleMismatch;
        }
        return execution;
    }

    comptime {
        rejectCodec(GenuineLifecyclePlanV2);
    }
};

/// Borrowed proof bytes plus their exact campaign node transport. This is a
/// genuine-gate publication candidate, not a StageManifest, live lease, or
/// proof capability. The final driver may consume its output ref only after
/// the normal worker has published both blobs and sealed the StageManifest.
pub const GatePublicationV2 = struct {
    description: *const StageDescription,
    final_remint: *const FinalRemint,
    proof_bytes: []const u8,
    artifact: campaign_artifact.Artifact,
    node_bytes: [campaign_artifact.ENCODED_BYTE_COUNT]u8,
    output_ref: artifact_store.BlobRefV1,

    pub fn init(
        scratch: std.mem.Allocator,
        description: *const StageDescription,
        proof_bytes: []const u8,
        artifact: campaign_artifact.Artifact,
    ) !GatePublicationV2 {
        const node_bytes = try campaign_artifact.encodeCanonical(
            description.final_remint.shape,
            &artifact,
        );
        const output_ref = try node_store.toSharedRef(
            try campaign_artifact.artifactRef(
                description.final_remint.shape,
                &artifact,
            ),
        );
        const result = GatePublicationV2{
            .description = description,
            .final_remint = description.final_remint,
            .proof_bytes = proof_bytes,
            .artifact = artifact,
            .node_bytes = node_bytes,
            .output_ref = output_ref,
        };
        try result.validate(scratch);
        return result;
    }

    pub fn validate(
        self: *const GatePublicationV2,
        scratch: std.mem.Allocator,
    ) !void {
        try self.description.validate(scratch);
        if (self.final_remint != self.description.final_remint or
            self.proof_bytes.len == 0)
        {
            return error.CampaignTargetNativePublicationMismatch;
        }
        try self.final_remint.validateAgainstCampaign(
            self.artifact.campaign_namespace_sha256,
        );
        const role = try roleForGateArtifact(&self.artifact);
        const registry = try self.final_remint.registryAuthority();
        const geometry = try self.final_remint.geometryForRole(role);
        try campaign_artifact.admitRegistry(
            registry,
            self.final_remint.shape,
            &self.artifact,
            geometry,
        );
        const semantic = try campaign_artifact.semanticInputsForStore(
            self.final_remint.shape,
            &self.artifact,
        );
        const proof_ref = try node_store.toSharedRef(self.artifact.proof_ref);
        try campaign_cas.validate(proof_ref, .proof);
        var proof_sha256: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(
            self.proof_bytes,
            &proof_sha256,
            .{},
        );
        const proof_byte_count = std.math.cast(
            u64,
            self.proof_bytes.len,
        ) orelse return error.CampaignTargetNativePublicationMismatch;
        const expected_node_bytes = try campaign_artifact.encodeCanonical(
            self.final_remint.shape,
            &self.artifact,
        );
        const expected_output_ref = try node_store.toSharedRef(
            try campaign_artifact.artifactRef(
                self.final_remint.shape,
                &self.artifact,
            ),
        );
        if (!std.meta.eql(
            semantic,
            self.description.planned_semantic,
        ) or !std.meta.eql(
            self.artifact.node_public,
            self.description.planned_node_public,
        ) or proof_ref.byte_count != proof_byte_count or
            !std.mem.eql(u8, &proof_ref.sha256, &proof_sha256) or
            !std.mem.eql(u8, &self.node_bytes, &expected_node_bytes) or
            !artifact_store.BlobRefV1.eql(
                self.output_ref,
                expected_output_ref,
            ))
        {
            return error.CampaignTargetNativePublicationMismatch;
        }
    }

    comptime {
        rejectCodec(GatePublicationV2);
    }
};

/// Process-local receipt for the explicit genuine-gate CAS transaction.
/// Proof and node are published first; only their exact refs may be sealed
/// into the StageManifest. A crash before the last put leaves inert CAS
/// objects and no admitted stage. Repeating the transaction is idempotent
/// because the store is content addressed.
pub const SealedGatePublicationV2 = struct {
    store: *artifact_store.Store,
    candidate: *const GatePublicationV2,
    proof_ref: artifact_store.BlobRefV1,
    node_ref: artifact_store.BlobRefV1,
    dependency_count: u8,
    dependency_stage_manifest_refs: [CHILD_COUNT]artifact_store.BlobRefV1,
    stage_manifest_ref: artifact_store.BlobRefV1,

    pub fn publishSealLast(
        scratch: std.mem.Allocator,
        store: *artifact_store.Store,
        candidate: *const GatePublicationV2,
        dependency_stage_manifest_refs: []const artifact_store.BlobRefV1,
    ) !SealedGatePublicationV2 {
        try candidate.validate(scratch);
        try validateDependencyManifestRefs(
            scratch,
            store,
            candidate.description,
            dependency_stage_manifest_refs,
        );
        const proof_ref = try store.putBytes(
            .proof_artifact,
            campaign_cas.PROOF_SCHEMA_VERSION,
            candidate.proof_bytes,
        );
        const expected_proof_ref = try node_store.toSharedRef(
            candidate.artifact.proof_ref,
        );
        if (!artifact_store.BlobRefV1.eql(
            proof_ref,
            expected_proof_ref,
        )) return error.CampaignTargetNativePublicationMismatch;

        const node_ref = try store.putBytes(
            .recursion_node,
            campaign_artifact.SCHEMA_VERSION,
            &candidate.node_bytes,
        );
        if (!artifact_store.BlobRefV1.eql(
            node_ref,
            candidate.output_ref,
        )) return error.CampaignTargetNativePublicationMismatch;

        // The manifest is deliberately constructed and published only after
        // both durable output refs have exact-matched their verifier-derived
        // authorities.
        var manifest_arena = std.heap.ArenaAllocator.init(scratch);
        defer manifest_arena.deinit();
        const manifest_allocator = manifest_arena.allocator();
        const outputs = [_]artifact_store.BlobRefV1{node_ref};
        const manifest = try worker_support.createStageManifest(
            manifest_allocator,
            candidate.description.node,
            candidate.description.ordered_inputs,
            candidate.description.semantic,
            candidate.description.execution,
            &outputs,
            dependency_stage_manifest_refs,
        );
        const manifest_bytes = try manifest.canonicalBytesAlloc(
            manifest_allocator,
        );
        const stage_manifest_ref = try store.putBytes(
            .stage_manifest,
            worker_support.stage_manifest_schema_version,
            manifest_bytes,
        );
        if (!std.mem.eql(
            u8,
            &stage_manifest_ref.sha256,
            &manifest.identity,
        )) return error.CampaignTargetNativePublicationMismatch;

        var dependencies: [CHILD_COUNT]artifact_store.BlobRefV1 = @splat(
            std.mem.zeroes(artifact_store.BlobRefV1),
        );
        for (dependency_stage_manifest_refs, 0..) |ref, index|
            dependencies[index] = ref;
        const result = SealedGatePublicationV2{
            .store = store,
            .candidate = candidate,
            .proof_ref = proof_ref,
            .node_ref = node_ref,
            .dependency_count = @intCast(
                dependency_stage_manifest_refs.len,
            ),
            .dependency_stage_manifest_refs = dependencies,
            .stage_manifest_ref = stage_manifest_ref,
        };
        try result.validate(scratch);
        return result;
    }

    pub fn validate(
        self: *const SealedGatePublicationV2,
        scratch: std.mem.Allocator,
    ) !void {
        try self.candidate.validate(scratch);
        if (self.dependency_count > CHILD_COUNT)
            return error.CampaignTargetNativePublicationMismatch;
        const dependency_count: usize = @intCast(self.dependency_count);
        const dependencies = self.dependency_stage_manifest_refs[0..dependency_count];
        const zero_ref = std.mem.zeroes(artifact_store.BlobRefV1);
        for (self.dependency_stage_manifest_refs[dependency_count..]) |ref|
            if (!std.meta.eql(ref, zero_ref))
                return error.CampaignTargetNativePublicationMismatch;
        try validateDependencyManifestRefs(
            scratch,
            self.store,
            self.candidate.description,
            dependencies,
        );
        const expected_proof_ref = try node_store.toSharedRef(
            self.candidate.artifact.proof_ref,
        );
        if (!artifact_store.BlobRefV1.eql(
            self.proof_ref,
            expected_proof_ref,
        ) or !artifact_store.BlobRefV1.eql(
            self.node_ref,
            self.candidate.output_ref,
        )) return error.CampaignTargetNativePublicationMismatch;

        var proof = try self.store.openBlob(
            self.proof_ref,
            .proof_artifact,
            campaign_cas.PROOF_SCHEMA_VERSION,
            campaign_cas.MAX_PROOF_BYTE_COUNT,
        );
        defer proof.deinit(self.store.allocator);
        var node = try self.store.openBlob(
            self.node_ref,
            .recursion_node,
            campaign_artifact.SCHEMA_VERSION,
            campaign_artifact.ENCODED_BYTE_COUNT,
        );
        defer node.deinit(self.store.allocator);
        if (!std.mem.eql(u8, proof.bytes, self.candidate.proof_bytes) or
            !std.mem.eql(u8, node.bytes, &self.candidate.node_bytes))
        {
            return error.CampaignTargetNativePublicationMismatch;
        }
        try worker_support.validateExistingStageManifest(
            scratch,
            self.store,
            self.stage_manifest_ref,
            self.candidate.description.node,
            self.candidate.description.ordered_inputs,
            self.candidate.description.semantic,
            self.candidate.description.execution,
            self.node_ref,
            dependencies,
            "root",
        );
    }

    comptime {
        rejectCodec(SealedGatePublicationV2);
    }
};

/// Process-local binding from one canonical controller description to the
/// exact q193 worker and RSS admission chosen for that node.
pub const ExecutionBindingV2 = struct {
    description: ?*const StageDescription,
    policy: *const Policy,
    node: *const protocol.Node,
    semantic: *const artifact_store.SemanticKeyV1,
    execution: *const artifact_store.ExecutionKeyV1,
    stage_kind: artifact_store.StageKindV1,
    stage_schema_version: u16,
    worker_count: usize,
    cpu_tokens: u64,
    rss_bytes: u64,

    pub fn init(
        scratch: std.mem.Allocator,
        policy: *const Policy,
        node: *const protocol.Node,
        semantic: *const artifact_store.SemanticKeyV1,
        execution: *const artifact_store.ExecutionKeyV1,
        stage_kind: artifact_store.StageKindV1,
        stage_schema_version: u16,
    ) !ExecutionBindingV2 {
        try policy.validateAgainstExecution(execution.*);
        try semantic.validate(scratch);
        const result = ExecutionBindingV2{
            .description = null,
            .policy = policy,
            .node = node,
            .semantic = semantic,
            .execution = execution,
            .stage_kind = stage_kind,
            .stage_schema_version = stage_schema_version,
            .worker_count = try policy.engineWorkerCount(),
            .cpu_tokens = policy.cpu_tokens_per_node,
            .rss_bytes = policy.rss_bytes_per_node,
        };
        try result.validate(scratch);
        return result;
    }

    pub fn fromDescription(
        scratch: std.mem.Allocator,
        description: *const StageDescription,
        stage_kind: artifact_store.StageKindV1,
        stage_schema_version: u16,
    ) !ExecutionBindingV2 {
        try description.validate(scratch);
        var result = try init(
            scratch,
            description.policy,
            &description.node,
            &description.semantic,
            &description.execution,
            stage_kind,
            stage_schema_version,
        );
        result.description = description;
        try result.validate(scratch);
        return result;
    }

    pub fn validate(
        self: ExecutionBindingV2,
        scratch: std.mem.Allocator,
    ) !void {
        try self.policy.validateAgainstExecution(self.execution.*);
        try self.semantic.validate(scratch);
        const expected_workers = try self.policy.engineWorkerCount();
        if (self.node.stage_kind != self.stage_kind or
            self.node.stage_schema_version != self.stage_schema_version or
            self.semantic.fields.stage_kind != self.stage_kind or
            self.semantic.fields.stage_schema_version !=
                self.stage_schema_version or
            !std.mem.eql(
                u8,
                &self.execution.fields.semantic_key_identity,
                &self.semantic.identity,
            ) or self.node.cpu_tokens !=
            @as(u64, self.policy.cpu_tokens_per_node) or
            self.node.rss_tokens != self.policy.rss_bytes_per_node or
            self.worker_count != expected_workers or
            self.cpu_tokens != self.policy.cpu_tokens_per_node or
            self.rss_bytes != self.policy.rss_bytes_per_node)
        {
            return error.CampaignTargetNativeExecutionMismatch;
        }
        if (self.description) |description| {
            if (self.policy != description.policy or
                self.node != &description.node or
                self.semantic != &description.semantic or
                self.execution != &description.execution)
            {
                return error.CampaignTargetNativeExecutionMismatch;
            }
            try description.validate(scratch);
        }
    }

    pub fn proofOptions(self: ExecutionBindingV2) secure_engine.ExecutionOptions {
        return .{ .worker_count = self.worker_count };
    }
};

/// Genuine role-1 entrypoint used by a later heavy gate.  The canonical
/// description binds the exact empty source, FinalRemint and execution
/// policy before the proof engine runs.
pub fn proveRole1ForGenuineGate(
    allocator: std.mem.Allocator,
    scratch: std.mem.Allocator,
    description: *const StageDescription,
    source: *const role1_source.ColdInputV2,
) !role1_proof.ProveResultV2 {
    const execution = try validateRole1Description(
        scratch,
        description,
        source,
    );
    const source_bytes = try source.source.encodeCanonical(&source.shape);
    var result = try role1_proof.proveAndColdVerify(
        allocator,
        description.final_remint,
        &source_bytes,
        execution.proofOptions(),
    );
    errdefer result.deinit();
    try result.receipt.validate();
    const expected_worker_count = std.math.cast(
        u32,
        execution.worker_count,
    ) orelse return error.CampaignTargetNativeRole1Mismatch;
    if (result.receipt.worker_count != expected_worker_count) {
        return error.CampaignTargetNativeRole1Mismatch;
    }
    return result;
}

/// Independent retained-byte cold-open for the role-1 genuine gate.  The
/// returned typed lease is the only value admissible to a role-2 pair.
pub fn coldOpenRole1ForGenuineGate(
    allocator: std.mem.Allocator,
    scratch: std.mem.Allocator,
    description: *const StageDescription,
    source: *const role1_source.ColdInputV2,
    proof_bytes: []const u8,
) !role1_child.OwnedLeaseV2 {
    _ = try validateRole1Description(scratch, description, source);
    const source_bytes = try source.source.encodeCanonical(&source.shape);
    var cold = try role1_proof.coldOpen(
        allocator,
        description.final_remint,
        &source_bytes,
        proof_bytes,
    );
    var cold_owned = true;
    defer if (cold_owned) cold.deinit();
    const moved = cold;
    cold = undefined;
    cold_owned = false;
    var result = try role1_child.OwnedLeaseV2.initOwned(
        description.final_remint,
        moved,
    );
    errdefer result.deinit();
    try result.validateForCampaign(description.final_remint);
    if (!std.meta.eql(
        result.nodeArtifact().node_public,
        description.planned_node_public,
    )) return error.CampaignTargetNativeRole1Mismatch;
    return result;
}

/// Reconstructs the exact Stage103 output transport from a verifier-owned
/// role-1 lease and retained proof bytes. It does not publish either blob or
/// mint a StageManifest.
pub fn role1PublicationForGenuineGate(
    scratch: std.mem.Allocator,
    description: *const StageDescription,
    source: *const role1_source.ColdInputV2,
    lease: *const role1_child.OwnedLeaseV2,
    proof_bytes: []const u8,
) !GatePublicationV2 {
    _ = try validateRole1Description(scratch, description, source);
    try lease.validateForCampaign(description.final_remint);
    if (!std.meta.eql(lease.evidence.cold.source_input, source.*))
        return error.CampaignTargetNativeRole1Mismatch;
    return GatePublicationV2.init(
        scratch,
        description,
        proof_bytes,
        lease.nodeArtifact().*,
    );
}

/// Specializes the role-2 gate on the exact all-level nominal lease union.
/// `Role2Types` is `recursive_common_fold_campaign_final_proof_v2.AllLevelTypes`.
pub fn Types(comptime Role2Types: type) type {
    assertRole2Types(Role2Types);
    const DependencyLease = Role2Types.DependencyLease;
    const ProofFamily = Role2Types.ProofFamily;
    const LiveTypes = ProofFamily.LiveTypesV2;
    const CoreProof = ProofFamily.CoreProofV2;

    return struct {
        const SelfTypes = @This();

        pub const DependencyLeaseV2 = DependencyLease;
        pub const CoreProofV2 = CoreProof;
        pub const ProductionLeasePayloadV2 = ProofFamily.LeasePayload;
        pub const ProductionProvedV2 = ProofFamily.ProvedV2;

        /// Heap-stable borrowed pair. The caller owns both child leases and
        /// must retain this owner until every returned core cold proof is
        /// destroyed. No child is consumed or serialized here.
        pub const PreparedRole2PairV2 = struct {
            allocator: std.mem.Allocator,
            description: *const StageDescription,
            final_remint: *const FinalRemint,
            lifecycle_plan: GenuineLifecyclePlanV2,
            execution: ExecutionBindingV2,
            target: target_mod.CampaignPaddingTargetV2,
            plan: PairPlanV2,
            children: [CHILD_COUNT]DependencyLease,
            fold_input: LiveTypes.FoldInputV2,
            live: LiveTypes.LiveV2,

            pub fn init(
                allocator: std.mem.Allocator,
                scratch: std.mem.Allocator,
                description: *const StageDescription,
                left: DependencyLease,
                right: DependencyLease,
            ) !*PreparedRole2PairV2 {
                const owner = try allocator.create(PreparedRole2PairV2);
                errdefer allocator.destroy(owner);
                owner.allocator = allocator;
                owner.description = description;
                owner.final_remint = description.final_remint;
                owner.lifecycle_plan = try GenuineLifecyclePlanV2.init(
                    description.final_remint,
                    description.policy,
                );
                owner.execution = try owner.lifecycle_plan.bindDescription(
                    scratch,
                    description,
                );
                owner.target = try target_mod.CampaignPaddingTargetV2
                    .fromFinal(description.final_remint);
                owner.plan = try PairPlanV2.init(
                    description.final_remint,
                    description.planned_semantic.coordinate,
                );
                owner.children = .{ left, right };
                const projections = try validateChildren(
                    scratch,
                    &owner.plan,
                    &owner.children,
                    description,
                );
                owner.fold_input = try LiveTypes.FoldInputV2.init(
                    &owner.target,
                    projections[0].node_public,
                    projections[1].node_public,
                    owner.plan.parent,
                );
                owner.live = try LiveTypes.LiveV2.init(
                    &owner.fold_input,
                    .{
                        try LiveTypes.FoldChild.init(
                            &owner.target,
                            owner.final_remint,
                            &owner.children[0],
                        ),
                        try LiveTypes.FoldChild.init(
                            &owner.target,
                            owner.final_remint,
                            &owner.children[1],
                        ),
                    },
                );
                try owner.validate(scratch);
                return owner;
            }

            pub fn validate(
                self: *const PreparedRole2PairV2,
                scratch: std.mem.Allocator,
            ) !void {
                try self.execution.validate(scratch);
                try self.lifecycle_plan.validate();
                _ = try self.lifecycle_plan.bindDescription(
                    scratch,
                    self.description,
                );
                try self.target.validateAgainstFinal(self.final_remint);
                try self.plan.validate(self.final_remint);
                const projections = try validateChildren(
                    scratch,
                    &self.plan,
                    &self.children,
                    self.description,
                );
                try self.fold_input.validate();
                try self.live.validate();
                if (self.description.final_remint != self.final_remint or
                    self.lifecycle_plan.final_remint != self.final_remint or
                    self.lifecycle_plan.policy != self.description.policy or
                    self.execution.description != self.description or
                    self.fold_input.padding_target != &self.target or
                    self.live.padding_target != &self.target or
                    self.live.input != &self.fold_input or
                    self.live.children[0].final_remint != self.final_remint or
                    self.live.children[1].final_remint != self.final_remint or
                    self.live.children[0].lease != &self.children[0] or
                    self.live.children[1].lease != &self.children[1] or
                    !std.meta.eql(
                        self.fold_input.parent_node_public,
                        self.description.planned_node_public,
                    ) or !std.meta.eql(
                    self.fold_input.child_node_publics[0],
                    projections[0].node_public.*,
                ) or !std.meta.eql(
                    self.fold_input.child_node_publics[1],
                    projections[1].node_public.*,
                )) return error.CampaignTargetNativeRole2Mismatch;
            }

            pub fn deinit(self: *PreparedRole2PairV2) void {
                const allocator = self.allocator;
                self.* = undefined;
                allocator.destroy(self);
            }

            comptime {
                rejectCodec(PreparedRole2PairV2);
            }
        };

        /// Runs the exact target-native role-2 core while all production and
        /// router gates remain closed. The returned proof borrows `prepared`.
        pub fn proveRole2ForGenuineGate(
            allocator: std.mem.Allocator,
            scratch: std.mem.Allocator,
            prepared: *const PreparedRole2PairV2,
        ) !CoreProof.ProveResultV2 {
            try prepared.validate(scratch);
            var result = try CoreProof.proveAndColdVerify(
                allocator,
                &prepared.target,
                &prepared.live,
                prepared.execution.proofOptions(),
            );
            errdefer result.deinit();
            try result.receipt.validate();
            const expected_worker_count = std.math.cast(
                u32,
                prepared.execution.worker_count,
            ) orelse return error.CampaignTargetNativeRole2Mismatch;
            if (result.receipt.worker_count != expected_worker_count)
                return error.CampaignTargetNativeRole2Mismatch;
            try validateRole2Cold(prepared, &result.proof);
            return result;
        }

        /// Fresh q193/PCS verification of retained role-2 bytes. No receipt,
        /// digest, or prior in-process token can substitute for this call.
        pub fn coldOpenRole2ForGenuineGate(
            allocator: std.mem.Allocator,
            scratch: std.mem.Allocator,
            prepared: *const PreparedRole2PairV2,
            proof_bytes: []const u8,
        ) !CoreProof.OwnedColdProofV2 {
            try prepared.validate(scratch);
            var result = try CoreProof.coldOpen(
                allocator,
                &prepared.target,
                &prepared.live,
                proof_bytes,
            );
            errdefer result.deinit();
            try validateRole2Cold(prepared, &result);
            return result;
        }

        /// Builds the canonical Stage104 node transport only after a fresh
        /// role-2 cold owner validates against the exact prepared pair.
        pub fn role2PublicationForGenuineGate(
            scratch: std.mem.Allocator,
            prepared: *const PreparedRole2PairV2,
            cold: *const CoreProof.OwnedColdProofV2,
        ) !GatePublicationV2 {
            try prepared.validate(scratch);
            try validateRole2Cold(prepared, cold);
            return GatePublicationV2.init(
                scratch,
                prepared.description,
                cold.proofBytes(),
                try buildRole2Artifact(prepared, cold),
            );
        }

        /// Exact production-typed Stage104 transaction for the genuine gate.
        /// The canonical description supplies Node/Semantic/Execution policy;
        /// the proof family borrows its two live nominal children only while
        /// proving, then owns two independent CAS cold-opens in the result.
        pub fn proveRole2TransitiveForGenuineGate(
            allocator: std.mem.Allocator,
            scratch: std.mem.Allocator,
            store: *artifact_store.Store,
            prepared: *const PreparedRole2PairV2,
        ) !ProofFamily.ProvedV2 {
            try prepared.validate(scratch);
            const authorities = try role2Authorities(prepared);
            const dependency_leases = role2DependencyPointers(prepared);
            var result = try ProofFamily
                .proveAndColdVerifyForGenuineGate(
                allocator,
                store,
                authorities,
                prepared.description.node,
                prepared.description.semantic,
                prepared.description.ordered_inputs,
                0,
                &dependency_leases,
                prepared.execution.worker_count,
            );
            errdefer result.deinit();
            try validateProductionRole2Result(
                scratch,
                prepared,
                &result,
                &dependency_leases,
            );
            return result;
        }

        /// Retained-byte/new-process counterpart. It recursively cold-opens
        /// each child from its canonical kind-10 ref, q193-verifies the
        /// parent, and returns the same production `LeasePayload` type.
        pub fn coldOpenRole2TransitiveForGenuineGate(
            allocator: std.mem.Allocator,
            scratch: std.mem.Allocator,
            store: *artifact_store.Store,
            prepared: *const PreparedRole2PairV2,
            proof_bytes: []const u8,
            node_bytes: []const u8,
        ) !ProofFamily.LeasePayload {
            try prepared.validate(scratch);
            const authorities = try role2Authorities(prepared);
            var result = try ProofFamily.coldOpenOwnedForGenuineGate(
                allocator,
                store,
                authorities,
                prepared.description.node,
                prepared.description.semantic,
                prepared.description.ordered_inputs,
                proof_bytes,
                node_bytes,
            );
            errdefer result.deinit();
            const expected = try campaign_artifact.decodeCanonical(
                prepared.final_remint.shape,
                node_bytes,
            );
            if (!std.meta.eql(result.nodeArtifact().*, expected))
                return error.CampaignTargetNativeRole2Mismatch;
            const publication = try GatePublicationV2.init(
                scratch,
                prepared.description,
                result.proofBytes(),
                result.nodeArtifact().*,
            );
            try publication.validate(scratch);
            return result;
        }

        fn role2Authorities(
            prepared: *const PreparedRole2PairV2,
        ) !consumers.AuthoritiesV2 {
            const result = consumers.AuthoritiesV2{
                .final_remint = prepared.final_remint,
                .shape = prepared.final_remint.shape,
                .registry = try prepared.final_remint.registryAuthority(),
                .geometry = try prepared.final_remint.geometryForRole(
                    .common_fold_field_v2,
                ),
            };
            try result.validate(.common_fold_field_v2);
            return result;
        }

        fn role2DependencyPointers(
            prepared: *const PreparedRole2PairV2,
        ) [CHILD_COUNT]*const DependencyLease {
            return .{ &prepared.children[0], &prepared.children[1] };
        }

        fn validateProductionRole2Result(
            scratch: std.mem.Allocator,
            prepared: *const PreparedRole2PairV2,
            result: *const ProofFamily.ProvedV2,
            dependency_leases: *const [CHILD_COUNT]*const DependencyLease,
        ) !void {
            const authorities = try role2Authorities(prepared);
            try result.validate(authorities, dependency_leases);
            const expected_worker_count = std.math.cast(
                u32,
                prepared.execution.worker_count,
            ) orelse return error.CampaignTargetNativeRole2Mismatch;
            if (result.receipt.worker_count != expected_worker_count)
                return error.CampaignTargetNativeRole2Mismatch;
            const publication = try GatePublicationV2.init(
                scratch,
                prepared.description,
                result.proofBytes(),
                result.nodeArtifact().*,
            );
            try publication.validate(scratch);
        }

        fn validateRole2Cold(
            prepared: *const PreparedRole2PairV2,
            cold: *const CoreProof.OwnedColdProofV2,
        ) !void {
            try cold.validateForPaddingTarget(&prepared.target);
            const geometry = try prepared.final_remint.geometryForRole(
                .common_fold_field_v2,
            );
            if (!std.meta.eql(geometry.*, cold.geometry_value) or
                !std.meta.eql(
                    cold.node_public,
                    prepared.description.planned_node_public,
                )) return error.CampaignTargetNativeRole2Mismatch;
        }

        fn buildRole2Artifact(
            prepared: *const PreparedRole2PairV2,
            cold: *const CoreProof.OwnedColdProofV2,
        ) !campaign_artifact.Artifact {
            try validateRole2Cold(prepared, cold);
            const authority = prepared.final_remint;
            const geometry = try authority.geometryForRole(
                .common_fold_field_v2,
            );
            const registry = try authority.registryAuthority();
            const entry = try registry.entry(.common_fold_field_v2);
            const coordinate = cold.node_public.coordinate;
            const stage: campaign_artifact.StageKind =
                if (coordinate.height == authority.shape.root_height)
                    .root
                else
                    .fold;
            const result = try campaign_artifact.seal(authority.shape, .{
                .stage_kind = stage,
                .node_kind = cold.node_public.node_kind,
                .child_count = CHILD_COUNT,
                .coordinate = coordinate,
                .node_public = cold.node_public,
                .campaign_namespace_sha256 = authority.shape
                    .campaign_namespace_sha256,
                .circuit_identity_sha256 = entry.circuit_identity_sha256,
                .program_identity_sha256 = entry.program_identity_sha256,
                .profile_identity_sha256 = entry.profile_identity_sha256,
                .pcs_identity_sha256 = entry.pcs_identity_sha256,
                .padding_layout_identity_sha256 = entry
                    .padding_layout_identity_sha256,
                .registry_identity_sha256 = registry.identity_sha256,
                .node_public_abi_sha256 = geometry.output_abi
                    .node_public_abi_sha256,
                .proof_shape_identity_sha256 = geometry.proof_shape
                    .identity_sha256,
                .ordered_children = .{
                    try node_store.fromSharedRef(
                        prepared.description.ordered_inputs[0].blob,
                    ),
                    try node_store.fromSharedRef(
                        prepared.description.ordered_inputs[1].blob,
                    ),
                },
                .proof_ref = try cold.proofArtifactRef(),
                .preprocessed_root = geometry.preprocessed_root,
                .semantic_inputs_identity_sha256 = undefined,
                .field_public_transport_sha256 = undefined,
                .content_identity_sha256 = undefined,
            });
            try campaign_artifact.admitRegistry(
                registry,
                authority.shape,
                &result,
                geometry,
            );
            return result;
        }

        fn validateChildren(
            scratch: std.mem.Allocator,
            plan: *const PairPlanV2,
            children: *const [CHILD_COUNT]DependencyLease,
            description: *const StageDescription,
        ) ![CHILD_COUNT]@import("recursive_pipeline_campaign_fold_projection_v2.zig").ProjectionV2 {
            try plan.validate(description.final_remint);
            try description.validate(scratch);
            if (description.final_remint != plan.final_remint or
                description.node.stage_kind != .fold or
                description.node.stage_schema_version !=
                    consumers.STAGE104_SCHEMA_VERSION or
                description.ordered_inputs.len != CHILD_COUNT or
                !std.meta.eql(
                    description.planned_semantic.coordinate,
                    plan.parent,
                )) return error.CampaignTargetNativeNominalPairMismatch;
            var projections: [CHILD_COUNT]@import(
                "recursive_pipeline_campaign_fold_projection_v2.zig",
            ).ProjectionV2 = undefined;
            const input_roles = [_]artifact_store.InputRoleV1{
                .child_left,
                .child_right,
            };
            for (children, &projections, description.ordered_inputs, input_roles, 0..) |
                child,
                *projection,
                input,
                input_role,
                index,
            | {
                try child.validateAgainst(plan.final_remint);
                projection.* = try child.foldProjection(plan.final_remint);
                try projection.validateAgainstFinal(plan.final_remint);
                const expected_ref = try node_store.toSharedRef(
                    try campaign_artifact.artifactRef(
                        plan.final_remint.shape,
                        projection.node_artifact,
                    ),
                );
                if (child.role() != plan.roles[index] or
                    projection.role != plan.roles[index] or
                    !std.meta.eql(
                        projection.node_public.coordinate,
                        plan.children[index],
                    ) or input.role != input_role or input.ordinal != 0 or
                    !artifact_store.BlobRefV1.eql(input.blob, expected_ref))
                {
                    return error.CampaignTargetNativeNominalPairMismatch;
                }
            }
            if (projections[0].capture == projections[1].capture or
                projections[0].node_artifact == projections[1].node_artifact)
            {
                return error.CampaignTargetNativeNominalPairMismatch;
            }
            const expected_parent = try campaign_public.initParent(
                plan.final_remint.shape,
                projections[0].node_public,
                projections[1].node_public,
                plan.parent,
            );
            if (!std.meta.eql(
                expected_parent,
                description.planned_node_public,
            )) return error.CampaignTargetNativeNominalPairMismatch;
            return projections;
        }

        comptime {
            rejectCodec(SelfTypes);
            if (ProofFamily.DependencyLeaseV2 != DependencyLease or
                !GENUINE_GATE_ONLY or PRODUCTION_ACTIVATION or
                ROUTER_ACTIVATION)
            {
                @compileError("campaign target-native q193 pair facade drifted");
            }
        }
    };
}

fn validateRole1Description(
    scratch: std.mem.Allocator,
    description: *const StageDescription,
    source: *const role1_source.ColdInputV2,
) !ExecutionBindingV2 {
    const lifecycle = try GenuineLifecyclePlanV2.init(
        description.final_remint,
        description.policy,
    );
    const execution = try lifecycle.bindDescription(
        scratch,
        description,
    );
    const source_bytes = try source.source.encodeCanonical(&source.shape);
    try source.validate(&source_bytes);
    const source_artifact_ref = try source.source.artifactRef(&source.shape);
    const source_ref = try node_store.toSharedRef(source_artifact_ref);
    if (description.planned_semantic.stage_kind != .leaf_wrapper or
        description.planned_semantic.node_kind != .empty or
        description.planned_semantic.child_count != 1 or
        !std.meta.eql(
            description.planned_semantic.ordered_children[0],
            source_artifact_ref,
        ) or
        !description.planned_semantic.ordered_children[1].isZero() or
        description.ordered_inputs.len != 1 or
        description.ordered_inputs[0].role != .direct or
        description.ordered_inputs[0].ordinal != 0 or
        !artifact_store.BlobRefV1.eql(
            description.ordered_inputs[0].blob,
            source_ref,
        ) or
        !std.meta.eql(source.shape, description.final_remint.shape.*) or
        !std.meta.eql(source.node_public, description.planned_node_public) or
        source.node_public.node_kind != .empty)
    {
        return error.CampaignTargetNativeRole1Mismatch;
    }
    return execution;
}

fn roleForCoordinate(shape: *const Shape, coordinate: Coordinate) !Role {
    try campaign_public.validateCoordinate(shape, coordinate);
    if (coordinate.height != 0) return .common_fold_field_v2;
    return switch (try campaign_public.expectedNodeKind(shape, coordinate)) {
        .real => .ethereum_incremental_leaf_wrapper_v4,
        .empty => .canonical_empty_field_v2,
        .mixed => error.CampaignTargetNativeNominalPairMismatch,
    };
}

fn roleForGateArtifact(
    artifact: *const campaign_artifact.Artifact,
) !Role {
    return switch (artifact.stage_kind) {
        .leaf_wrapper => switch (artifact.node_kind) {
            .empty => .canonical_empty_field_v2,
            .real, .mixed => error.CampaignTargetNativePublicationMismatch,
        },
        .fold, .root => .common_fold_field_v2,
    };
}

fn validateDependencyManifestRefs(
    scratch: std.mem.Allocator,
    store: *artifact_store.Store,
    description: *const StageDescription,
    refs: []const artifact_store.BlobRefV1,
) !void {
    if (refs.len > CHILD_COUNT or
        refs.len != description.node.dependencies.len or
        refs.len != description.dependency_stage_manifest_refs.len)
    {
        return error.CampaignTargetNativePublicationMismatch;
    }
    for (refs, description.dependency_stage_manifest_refs) |
        observed,
        expected,
    | {
        try campaign_cas.validate(observed, .stage_manifest);
        if (!artifact_store.BlobRefV1.eql(observed, expected))
            return error.CampaignTargetNativePublicationMismatch;
    }
    try worker_support.validateDependencyManifests(
        scratch,
        store,
        description.node,
        refs,
    );
}

fn kindForRoles(roles: [CHILD_COUNT]Role) !NominalPairKindV2 {
    return if (roles[0] == .ethereum_incremental_leaf_wrapper_v4 and
        roles[1] == .ethereum_incremental_leaf_wrapper_v4)
        .real_real
    else if (roles[0] == .ethereum_incremental_leaf_wrapper_v4 and
        roles[1] == .canonical_empty_field_v2)
        .real_empty
    else if (roles[0] == .canonical_empty_field_v2 and
        roles[1] == .canonical_empty_field_v2)
        .empty_empty
    else if (roles[0] == .common_fold_field_v2 and
        roles[1] == .common_fold_field_v2)
        .common_common
    else
        error.CampaignTargetNativeNominalPairMismatch;
}

fn assertRole2Types(comptime Role2Types: type) void {
    inline for (.{ "DependencyLease", "ProofFamily" }) |name|
        if (!@hasDecl(Role2Types, name))
            @compileError("campaign role2 all-level facade missing " ++ name);
    const Family = Role2Types.ProofFamily;
    inline for (.{
        "DependencyLeaseV2",
        "LiveTypesV2",
        "CoreProofV2",
        "LeasePayload",
        "ProvedV2",
        "proveAndColdVerifyForGenuineGate",
        "coldOpenOwnedForGenuineGate",
    }) |name| if (!@hasDecl(Family, name))
        @compileError("campaign role2 proof family missing " ++ name);
    inline for (.{ "role", "validateAgainst", "foldProjection" }) |name|
        if (!@hasDecl(Role2Types.DependencyLease, name))
            @compileError("campaign role2 dependency missing " ++ name);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign target-native gate capability gained a codec");
}

comptime {
    rejectCodec(PairPlanV2);
    rejectCodec(NominalPairInventoryV2);
    rejectCodec(GenuineLifecyclePlanV2);
    rejectCodec(GatePublicationV2);
    rejectCodec(SealedGatePublicationV2);
    rejectCodec(ExecutionBindingV2);
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        ROLE1_Q193_GENUINE_GATE_GREEN or
        ROLE2_NOMINAL_PAIR_Q193_GATES_GREEN or !GENUINE_GATE_ONLY or
        SERIALIZABLE_FRESH_CAPABILITY or
        !PAIRS_ARE_RUNTIME_SHAPE_DERIVED or
        !EXECUTION_KEY_WORKER_POLICY_REQUIRED or
        !EXECUTION_KEY_RSS_POLICY_REQUIRED or
        !ROLE2_GATE_OUTPUT_IS_NOT_A_DURABLE_NODE or
        !GATE_PUBLICATION_IS_CREATE_ONLY or !GATE_MANIFEST_IS_SEAL_LAST or
        CHILD_COUNT != 2 or
        policy_mod.MAX_PROOF_WORKERS != 32)
    {
        @compileError("campaign target-native q193 pair contract drifted");
    }
}
