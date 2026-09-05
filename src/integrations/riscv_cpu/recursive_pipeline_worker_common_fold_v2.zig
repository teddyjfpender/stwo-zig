//! Unrouteable stage-104 boundary requiring final geometry/parity, typed child
//! cold-open, authenticated campaign shape, and genuine q193 authorities.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const campaign_shape = @import("recursive_pipeline_campaign_shape_v2.zig");
const node_artifact = @import("recursive_node_artifact_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const cohort_mod = @import("recursive_common_fold_universal_cohort_v2.zig");
const manifest_mod = @import("recursive_common_fold_universal_manifest_v2.zig");
const proof_mod = @import("recursive_common_fold_universal_proof_v2.zig");
const common_child = @import("recursive_common_fold_child_v2.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");

pub const adapter_name = "common_fold_v2";
pub const profile_schema = "stwo.recursive-common-fold-profile.v2";
pub const validation_schema = "stwo.recursive-common-fold-validation.v2";

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const STAGE_SCHEMA_VERSION: u16 =
    node_store.COMMON_FOLD_STAGE_SCHEMA_VERSION;
pub const OUTPUT_SCHEMA_VERSION: u16 = node_artifact.SCHEMA_VERSION;
pub const PROOF_SCHEMA_VERSION: u16 = 1;
pub const DEPENDENCY_COUNT: usize = 2;
pub const OUTPUT_BYTE_COUNT: usize = node_artifact.ENCODED_BYTE_COUNT;
pub const MAX_RETAINED_PROOF_BYTES: u64 =
    secure_artifact.MAX_CANONICAL_PROOF_BYTES + 4 * 1024 * 1024;

pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const DEPENDENCIES_BORROWED_DURING_BUILD = true;
pub const BUILD_FAILURE_RETAINS_DEPENDENCIES = true;
pub const COLD_OPEN_OWNS_DEPENDENCY_PAIR = true;
pub const CampaignShapeAuthorityV2 =
    campaign_shape.CampaignShapeAuthorityV2;

pub const Error = error{
    CommonFoldStage104ArtifactMismatch,
    CommonFoldStage104AuthorityUnavailable,
    CommonFoldStage104BackendUnavailable,
    CommonFoldStage104DependencyMismatch,
    CommonFoldStage104InputMismatch,
    CommonFoldStage104OutputMismatch,
    CommonFoldStage104ProjectionMismatch,
    CommonFoldStage104RequiresArtifactStore,
};

pub const StageContractV2 = struct {
    stage_kind: artifact_store.StageKindV1 = .fold,
    stage_schema_version: u16 = STAGE_SCHEMA_VERSION,
    output_kind: artifact_store.ArtifactKindV1 = .recursion_node,
    output_format_version: u16 = artifact_store.types.format_version_v1,
    output_schema_version: u16 = OUTPUT_SCHEMA_VERSION,
    output_byte_count: u64 = OUTPUT_BYTE_COUNT,
    proof_kind: artifact_store.ArtifactKindV1 = .proof_artifact,
    proof_format_version: u16 = artifact_store.types.format_version_v1,
    proof_schema_version: u16 = PROOF_SCHEMA_VERSION,
    dependency_count: u8 = DEPENDENCY_COUNT,
    root_cold_open_transitive: bool = true,
};

pub fn stageContract() StageContractV2 {
    return .{};
}

/// Validates only the durable CAS type allocation. It does not cold-open a
/// proof and cannot mint a live lease.
pub fn validateCasRef(
    ref: artifact_store.BlobRefV1,
    expected: enum { proof, node },
) !void {
    try ref.validate();
    switch (expected) {
        .proof => if (ref.kind != .proof_artifact or
            ref.format_version != artifact_store.types.format_version_v1 or
            ref.schema_version != PROOF_SCHEMA_VERSION or
            ref.byte_count == 0 or ref.byte_count > MAX_RETAINED_PROOF_BYTES)
        {
            return error.CommonFoldStage104ArtifactMismatch;
        },
        .node => if (ref.kind != .recursion_node or
            ref.format_version != artifact_store.types.format_version_v1 or
            ref.schema_version != OUTPUT_SCHEMA_VERSION or
            ref.byte_count != OUTPUT_BYTE_COUNT)
        {
            return error.CommonFoldStage104ArtifactMismatch;
        },
    }
}

/// Error-path ownership guard for a recursively cold-opened pair.
/// `transferValue` plus `commitTransfer` transfers both children atomically
/// to the returned parent lease; without the commit, the opener receives
/// exactly one deinit call.
pub fn OwnedPairGuard(comptime ChildColdOpener: type) type {
    return struct {
        pair: ChildColdOpener.OwnedPair,
        owned: bool = true,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.owned) {
                ChildColdOpener.deinitOwnedPair(&self.pair, allocator);
                self.owned = false;
            }
        }

        pub fn transferValue(self: *const Self) ChildColdOpener.OwnedPair {
            std.debug.assert(self.owned);
            return self.pair;
        }

        pub fn commitTransfer(self: *Self) void {
            std.debug.assert(self.owned);
            self.owned = false;
            self.pair = undefined;
        }
    };
}

/// Exact future route: the provider owns final three-role geometry/parity and
/// campaign shape; the opener borrows or recursively owns two typed children;
/// the backend transfers that pair into a parent only after q193 succeeds.
pub fn AdapterFor(
    comptime AuthorityProvider: type,
    comptime ChildColdOpener: type,
    comptime Backend: type,
) type {
    assertAuthorityProviderContract(AuthorityProvider);
    assertChildColdOpenerContract(ChildColdOpener);
    assertBackendContract(Backend);
    comptime {
        if (AuthorityProvider.Authority != manifest_mod.AuthorityV2 or
            AuthorityProvider.CampaignShape != CampaignShapeAuthorityV2 or
            ChildColdOpener.Authority != manifest_mod.AuthorityV2 or
            Backend.Authority != manifest_mod.AuthorityV2 or
            ChildColdOpener.Child != cohort_mod.FreshFoldChildV2 or
            Backend.Child != cohort_mod.FreshFoldChildV2 or
            Backend.OwnedPair != ChildColdOpener.OwnedPair)
        {
            @compileError("stage104 authority/child contracts are nominally different");
        }
    }

    return struct {
        pub const name = adapter_name;
        pub const production = PRODUCTION_ACTIVATION;
        pub const available = AuthorityProvider.available and
            ChildColdOpener.available and Backend.available and
            proof_mod.Q193_BACKEND_AVAILABLE;
        pub const DependencyLease = ChildColdOpener.DependencyLease;
        pub const LeasePayload = Backend.LeasePayload;

        pub fn acceptsNodeAdapter(value: []const u8) bool {
            return std.mem.eql(u8, value, adapter_name) or
                std.mem.eql(u8, value, "recursive_composite_v2") or
                std.mem.eql(u8, value, "zig-worker-v1");
        }

        pub fn describe(
            stage_kind: artifact_store.StageKindV1,
            stage_schema_version: u16,
        ) !protocol.StageDescription {
            if (stage_kind != .fold or
                stage_schema_version != STAGE_SCHEMA_VERSION)
            {
                return error.UnsupportedRecursivePipelineStage;
            }
            return .{
                .stage_kind = .fold,
                .stage_schema_version = STAGE_SCHEMA_VERSION,
                .output_kind = .recursion_node,
                .output_schema_version = OUTPUT_SCHEMA_VERSION,
                .minimum_cpu_tokens = 1,
                .minimum_rss_tokens = 1,
                .root_cold_open_transitive = true,
            };
        }

        pub fn unavailable() error{CommonFoldStage104BackendUnavailable} {
            return error.CommonFoldStage104BackendUnavailable;
        }

        /// Build leases stay borrowed through durable outer publication.
        pub fn buildOutputWithLeases(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const DependencyLease,
        ) ![]u8 {
            if (comptime !available) return unavailable();
            const authority = try currentAuthority(AuthorityProvider);
            const shape = try currentCampaignShape(
                AuthorityProvider,
                semantic.fields.campaign_namespace,
            );
            try validateStageNode(
                node,
                ordered_inputs,
                shape,
                acceptsNodeAdapter,
            );
            const children = try ChildColdOpener.borrowPair(
                dependency_leases,
                authority,
                shape,
            );
            var proved = try Backend.proveAndColdVerify(
                allocator,
                authority,
                shape,
                node,
                semantic,
                ordered_inputs,
                candidate_ordinal,
                children,
            );
            defer proved.deinit();
            try proved.validate(authority, shape, children);
            const proof_bytes = proved.proofBytes();
            if (proof_bytes.len == 0 or
                proof_bytes.len > MAX_RETAINED_PROOF_BYTES)
            {
                return error.CommonFoldStage104OutputMismatch;
            }
            const proof_ref = try store.putBytes(
                .proof_artifact,
                PROOF_SCHEMA_VERSION,
                proof_bytes,
            );
            try validateCasRef(proof_ref, .proof);
            const artifact = proved.nodeArtifact();
            try validateProjection(
                allocator,
                node,
                semantic,
                ordered_inputs,
                artifact,
                authority,
                shape,
            );
            const expected_proof = try node_store.toSharedRef(
                artifact.proof_ref,
            );
            if (!artifact_store.BlobRefV1.eql(proof_ref, expected_proof))
                return error.CommonFoldStage104OutputMismatch;
            const bytes = try artifact.encodeCanonical();
            return allocator.dupe(u8, &bytes);
        }

        pub fn validateOutput(
            allocator: std.mem.Allocator,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !void {
            if (comptime !available) return unavailable();
            const authority = try currentAuthority(AuthorityProvider);
            const shape = try currentCampaignShape(
                AuthorityProvider,
                semantic.fields.campaign_namespace,
            );
            try validateStageNode(
                node,
                ordered_inputs,
                shape,
                acceptsNodeAdapter,
            );
            const artifact = try node_artifact.RecursiveNodeArtifactV2
                .decodeCanonical(bytes);
            try validateProjection(
                allocator,
                node,
                semantic,
                ordered_inputs,
                &artifact,
                authority,
                shape,
            );
        }

        /// Cold-open owns both children; only q193 success transfers the pair.
        pub fn coldOpenLease(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !LeasePayload {
            if (comptime !available) return unavailable();
            const authority = try currentAuthority(AuthorityProvider);
            const shape = try currentCampaignShape(
                AuthorityProvider,
                semantic.fields.campaign_namespace,
            );
            try validateStageNode(
                node,
                ordered_inputs,
                shape,
                acceptsNodeAdapter,
            );
            const artifact = try node_artifact.RecursiveNodeArtifactV2
                .decodeCanonical(bytes);
            try validateProjection(
                allocator,
                node,
                semantic,
                ordered_inputs,
                &artifact,
                authority,
                shape,
            );
            const proof_ref = try node_store.toSharedRef(artifact.proof_ref);
            try validateCasRef(proof_ref, .proof);
            var proof_blob = try store.openBlob(
                proof_ref,
                .proof_artifact,
                PROOF_SCHEMA_VERSION,
                MAX_RETAINED_PROOF_BYTES,
            );
            defer proof_blob.deinit(store.allocator);

            var pair_guard = OwnedPairGuard(ChildColdOpener){
                .pair = try ChildColdOpener.coldOpenPair(
                    allocator,
                    store,
                    node,
                    semantic,
                    ordered_inputs,
                    authority,
                    shape,
                ),
            };
            defer pair_guard.deinit(allocator);
            const children = try ChildColdOpener.views(
                &pair_guard.pair,
                authority,
                shape,
            );
            var result = try Backend.coldOpenOwned(
                allocator,
                authority,
                shape,
                pair_guard.transferValue(),
                children,
                proof_blob.bytes,
                bytes,
            );
            pair_guard.commitTransfer();
            errdefer result.deinit();
            try result.validate(authority, shape);
            if (!std.meta.eql(result.nodeArtifact().*, artifact))
                return error.CommonFoldStage104OutputMismatch;
            const child = try result.requireFoldChild();
            try child.validateBorrowed();
            return result;
        }

        pub fn deinitLeasePayload(
            payload: *LeasePayload,
            _: std.mem.Allocator,
        ) void {
            payload.deinit();
        }

        pub fn profileValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            _: artifact_store.ExecutionKeyV1,
            candidate_ordinal: u64,
        ) !protocol.Json {
            if (comptime !available) return unavailable();
            var value = protocol.jsonObject(allocator);
            try protocol.put(&value, "schema", protocol.string(profile_schema));
            try protocol.put(&value, "node_id", protocol.string(node.node_id));
            try protocol.putDigest(
                allocator,
                &value,
                "semantic_key_sha256",
                semantic.identity,
            );
            try protocol.put(
                &value,
                "candidate_ordinal",
                try protocol.integerU64(allocator, candidate_ordinal),
            );
            try protocol.put(&value, "performance", .{ .bool = false });
            try protocol.put(&value, "production", .{ .bool = false });
            try protocol.sealObject(allocator, &value);
            return value;
        }

        pub fn validationValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            output_ref: artifact_store.BlobRefV1,
            validator_version: u32,
            mode: []const u8,
        ) !protocol.Json {
            if (comptime !available) return unavailable();
            try validateCasRef(output_ref, .node);
            var value = protocol.jsonObject(allocator);
            try protocol.put(
                &value,
                "schema",
                protocol.string(validation_schema),
            );
            try protocol.put(&value, "node_id", protocol.string(node.node_id));
            try protocol.putDigest(
                allocator,
                &value,
                "semantic_key_sha256",
                semantic.identity,
            );
            try protocol.putDigest(
                allocator,
                &value,
                "output_sha256",
                output_ref.sha256,
            );
            try protocol.put(
                &value,
                "validator_version",
                protocol.integer(validator_version),
            );
            try protocol.put(&value, "mode", protocol.string(mode));
            try protocol.put(&value, "cold_verified", .{ .bool = true });
            try protocol.put(&value, "production", .{ .bool = false });
            try protocol.sealObject(allocator, &value);
            return value;
        }
    };
}

pub const UnavailableDependencyLeaseV2 = struct {};

pub const UnavailableAuthorityProviderV2 = struct {
    pub const Authority = manifest_mod.AuthorityV2;
    pub const CampaignShape = CampaignShapeAuthorityV2;
    pub const available = false;

    pub fn current() error{CommonFoldStage104AuthorityUnavailable}!*const Authority {
        return error.CommonFoldStage104AuthorityUnavailable;
    }

    pub fn shapeForCampaign(
        _: [32]u8,
    ) error{CommonFoldStage104AuthorityUnavailable}!*const CampaignShape {
        return error.CommonFoldStage104AuthorityUnavailable;
    }
};

pub const UnavailableChildColdOpenerV2 = struct {
    pub const Authority = manifest_mod.AuthorityV2;
    pub const Child = cohort_mod.FreshFoldChildV2;
    pub const DependencyLease = UnavailableDependencyLeaseV2;
    pub const OwnedPair = struct {};
    pub const available = false;

    pub fn borrowPair(
        _: []const *const DependencyLease,
        _: *const Authority,
        _: *const CampaignShapeAuthorityV2,
    ) error{CommonFoldStage104DependencyMismatch}![DEPENDENCY_COUNT]Child {
        return error.CommonFoldStage104DependencyMismatch;
    }

    pub fn coldOpenPair(
        _: std.mem.Allocator,
        _: *artifact_store.Store,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: []const artifact_store.InputRefV1,
        _: *const Authority,
        _: *const CampaignShapeAuthorityV2,
    ) error{CommonFoldStage104DependencyMismatch}!OwnedPair {
        return error.CommonFoldStage104DependencyMismatch;
    }

    pub fn views(
        _: *const OwnedPair,
        _: *const Authority,
        _: *const CampaignShapeAuthorityV2,
    ) error{CommonFoldStage104DependencyMismatch}![DEPENDENCY_COUNT]Child {
        return error.CommonFoldStage104DependencyMismatch;
    }

    pub fn deinitOwnedPair(_: *OwnedPair, _: std.mem.Allocator) void {}
};

pub const UnavailableBackendV2 = struct {
    pub const Authority = manifest_mod.AuthorityV2;
    pub const Child = cohort_mod.FreshFoldChildV2;
    pub const OwnedPair = UnavailableChildColdOpenerV2.OwnedPair;
    pub const available = false;

    pub const ProveResult = struct {
        pub fn deinit(_: *ProveResult) void {}

        pub fn validate(
            _: *const ProveResult,
            _: *const Authority,
            _: *const CampaignShapeAuthorityV2,
            _: [DEPENDENCY_COUNT]Child,
        ) error{CommonFoldStage104BackendUnavailable}!void {
            return error.CommonFoldStage104BackendUnavailable;
        }

        pub fn proofBytes(_: *const ProveResult) []const u8 {
            unreachable;
        }

        pub fn nodeArtifact(
            _: *const ProveResult,
        ) *const node_artifact.RecursiveNodeArtifactV2 {
            unreachable;
        }
    };

    pub const LeasePayload = struct {
        pub const FoldChild = common_child.FreshFoldChildV2;

        pub fn validate(
            _: *const LeasePayload,
            _: *const Authority,
            _: *const CampaignShapeAuthorityV2,
        ) error{CommonFoldStage104BackendUnavailable}!void {
            return error.CommonFoldStage104BackendUnavailable;
        }

        pub fn nodeArtifact(
            _: *const LeasePayload,
        ) *const node_artifact.RecursiveNodeArtifactV2 {
            unreachable;
        }

        pub fn requireFoldChild(
            _: *const LeasePayload,
        ) error{CommonFoldStage104BackendUnavailable}!FoldChild {
            return error.CommonFoldStage104BackendUnavailable;
        }

        pub fn deinit(_: *LeasePayload) void {}
    };

    pub fn proveAndColdVerify(
        _: std.mem.Allocator,
        _: *const Authority,
        _: *const CampaignShapeAuthorityV2,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: []const artifact_store.InputRefV1,
        _: u64,
        _: [DEPENDENCY_COUNT]Child,
    ) error{CommonFoldStage104BackendUnavailable}!ProveResult {
        return error.CommonFoldStage104BackendUnavailable;
    }

    pub fn coldOpenOwned(
        _: std.mem.Allocator,
        _: *const Authority,
        _: *const CampaignShapeAuthorityV2,
        _: OwnedPair,
        _: [DEPENDENCY_COUNT]Child,
        _: []const u8,
        _: []const u8,
    ) error{CommonFoldStage104BackendUnavailable}!LeasePayload {
        return error.CommonFoldStage104BackendUnavailable;
    }
};

pub const Adapter = AdapterFor(
    UnavailableAuthorityProviderV2,
    UnavailableChildColdOpenerV2,
    UnavailableBackendV2,
);

fn currentAuthority(comptime Provider: type) !*const manifest_mod.AuthorityV2 {
    if (comptime !Provider.available)
        return error.CommonFoldStage104AuthorityUnavailable;
    const result = try Provider.current();
    try result.validate();
    return result;
}

fn currentCampaignShape(
    comptime Provider: type,
    campaign_namespace_sha256: [32]u8,
) !*const CampaignShapeAuthorityV2 {
    if (comptime !Provider.available)
        return error.CommonFoldStage104AuthorityUnavailable;
    const result = try Provider.shapeForCampaign(
        campaign_namespace_sha256,
    );
    try result.validateAgainstCampaign(campaign_namespace_sha256);
    return result;
}

fn validateStageNode(
    node: protocol.Node,
    ordered_inputs: []const artifact_store.InputRefV1,
    shape: *const CampaignShapeAuthorityV2,
    comptime accepts: fn ([]const u8) bool,
) !void {
    try shape.validate();
    if (node.stage_kind != .fold or
        node.stage_schema_version != STAGE_SCHEMA_VERSION or
        node.dependencies.len != DEPENDENCY_COUNT or
        node.external_inputs.len != 0 or
        node.output_kind != .recursion_node or
        node.output_schema_version != OUTPUT_SCHEMA_VERSION or
        !accepts(node.adapter) or ordered_inputs.len != DEPENDENCY_COUNT)
    {
        return error.CommonFoldStage104InputMismatch;
    }
    const roles = [_]artifact_store.InputRoleV1{ .child_left, .child_right };
    for (node.dependencies, ordered_inputs, roles) |
        dependency,
        input,
        role,
    | {
        if (dependency.role != @intFromEnum(role) or
            dependency.ordinal != 0 or input.role != role or
            input.ordinal != 0)
        {
            return error.CommonFoldStage104DependencyMismatch;
        }
        try validateCasRef(input.blob, .node);
    }
    const options = try protocol.objectValue(node.semantic_options);
    try protocol.exactKeys(options, &.{
        "tree_level",
        "fold_ordinal",
        "campaign_shape_sha256",
        "pipeline_stage",
        "operation",
    });
    const tree_level = try protocol.positiveField(u8, options, "tree_level");
    const fold_ordinal = try protocol.unsignedField(
        u32,
        options,
        "fold_ordinal",
    );
    const expected = shape.parentCoordinate(tree_level, fold_ordinal) catch
        return error.CommonFoldStage104InputMismatch;
    const observed_shape = try protocol.digestField(
        options,
        "campaign_shape_sha256",
        true,
    );
    if (expected.height != tree_level or expected.index != fold_ordinal or
        !std.mem.eql(u8, &observed_shape, &shape.identity_sha256) or
        !std.mem.eql(
            u8,
            try protocol.stringField(options, "operation"),
            "build-common-fold",
        ) or (try protocol.stringField(options, "pipeline_stage")).len == 0)
    {
        return error.CommonFoldStage104InputMismatch;
    }
}

fn validateProjection(
    allocator: std.mem.Allocator,
    node: protocol.Node,
    semantic: artifact_store.SemanticKeyV1,
    ordered_inputs: []const artifact_store.InputRefV1,
    artifact: *const node_artifact.RecursiveNodeArtifactV2,
    authority: *const manifest_mod.AuthorityV2,
    shape: *const CampaignShapeAuthorityV2,
) !void {
    try semantic.validate(allocator);
    try authority.validate();
    try shape.validateAgainstCampaign(semantic.fields.campaign_namespace);
    try artifact.validate();
    if (artifact.stage_kind != .fold and artifact.stage_kind != .root)
        return error.CommonFoldStage104ArtifactMismatch;
    if (artifact.child_count != DEPENDENCY_COUNT)
        return error.CommonFoldStage104ArtifactMismatch;
    for (ordered_inputs, artifact.ordered_children) |input, child| {
        const expected = try node_store.toSharedRef(child);
        if (!artifact_store.BlobRefV1.eql(input.blob, expected))
            return error.CommonFoldStage104ArtifactMismatch;
    }
    try authority.registry.admitV2(
        artifact,
        authority.commonFoldGeometry(),
    );
    const projected = try artifact.semanticInputs();
    const local_task = try node_store.localTaskIdentityV2(&projected);
    const statement = try node_store.statementCacheIdentityV2(&projected);
    const security = node_store.security.ProofSecurityV1
        .recursiveParentSecure();
    const options_identity = try protocol.canonicalDigest(
        allocator,
        node.semantic_options,
    );
    const options = try protocol.objectValue(node.semantic_options);
    const tree_level = try protocol.positiveField(u8, options, "tree_level");
    const fold_ordinal = try protocol.unsignedField(
        u32,
        options,
        "fold_ordinal",
    );
    const expected_coordinate = try shape.parentCoordinate(
        tree_level,
        fold_ordinal,
    );
    const expected_stage = try std.fmt.allocPrint(
        allocator,
        "fold-{d}",
        .{tree_level},
    );
    defer allocator.free(expected_stage);
    const fields = semantic.fields;
    if (expected_coordinate.height != artifact.coordinate.height or
        expected_coordinate.index != artifact.coordinate.index or
        expected_coordinate.global_ordinal !=
            artifact.coordinate.global_ordinal or
        expected_coordinate.node_kind != artifact.node_kind or
        !std.mem.eql(
            u8,
            try protocol.stringField(options, "pipeline_stage"),
            expected_stage,
        ) or fields.stage_kind != .fold or
        fields.stage_schema_version != STAGE_SCHEMA_VERSION or
        !std.mem.eql(u8, &fields.campaign_namespace, &artifact.campaign_namespace_sha256) or
        !std.mem.eql(u8, &fields.local_task_identity, &local_task) or
        !std.mem.eql(u8, &node.local_task_identity_sha256, &local_task) or
        !std.mem.eql(u8, &fields.protocol_identity, &artifact.circuit_identity_sha256) or
        !std.mem.eql(u8, &fields.program_identity, &artifact.program_identity_sha256) or
        !std.mem.eql(u8, &fields.profile_identity, &artifact.profile_identity_sha256) or
        !std.mem.eql(u8, &fields.pcs_identity, &artifact.pcs_identity_sha256) or
        !std.mem.eql(u8, &fields.security_identity, &security.identity) or
        !std.mem.eql(u8, &fields.statement_identity, &statement) or
        !artifact_store.encoding.isZeroDigest(fields.provider_identity) or
        !std.mem.eql(u8, &fields.layout_identity, &artifact.padding_layout_identity_sha256) or
        !std.mem.eql(u8, &fields.registry_identity, &authority.registry.identity_sha256) or
        !std.mem.eql(u8, &fields.semantic_options_identity, &options_identity) or
        fields.ordered_inputs.len != DEPENDENCY_COUNT)
    {
        return error.CommonFoldStage104ProjectionMismatch;
    }
    for (fields.ordered_inputs, ordered_inputs) |actual, expected| {
        if (!std.meta.eql(actual, expected))
            return error.CommonFoldStage104ProjectionMismatch;
    }
}

fn assertAuthorityProviderContract(comptime Provider: type) void {
    inline for (.{
        "Authority",
        "CampaignShape",
        "available",
        "current",
        "shapeForCampaign",
    }) |name| {
        if (!@hasDecl(Provider, name))
            @compileError("stage104 authority provider missing: " ++ name);
    }
}

fn assertChildColdOpenerContract(comptime Opener: type) void {
    inline for (.{
        "Authority",
        "Child",
        "DependencyLease",
        "OwnedPair",
        "available",
        "borrowPair",
        "coldOpenPair",
        "views",
        "deinitOwnedPair",
    }) |name| {
        if (!@hasDecl(Opener, name))
            @compileError("stage104 child cold-opener missing: " ++ name);
    }
}

fn assertBackendContract(comptime Backend: type) void {
    inline for (.{
        "Authority",
        "Child",
        "OwnedPair",
        "ProveResult",
        "LeasePayload",
        "available",
        "proveAndColdVerify",
        "coldOpenOwned",
    }) |name| {
        if (!@hasDecl(Backend, name))
            @compileError("stage104 backend missing: " ++ name);
    }
    const ProveResult = Backend.ProveResult;
    inline for (.{
        "deinit",
        "validate",
        "proofBytes",
        "nodeArtifact",
    }) |name| {
        if (!@hasDecl(ProveResult, name))
            @compileError("stage104 prove result missing: " ++ name);
    }
    const Lease = Backend.LeasePayload;
    inline for (.{
        "deinit",
        "validate",
        "nodeArtifact",
        "requireFoldChild",
    }) |name| {
        if (!@hasDecl(Lease, name))
            @compileError("stage104 lease missing: " ++ name);
    }
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        STAGE_SCHEMA_VERSION != 104 or OUTPUT_SCHEMA_VERSION != 2 or
        PROOF_SCHEMA_VERSION != 1 or DEPENDENCY_COUNT != 2 or
        OUTPUT_BYTE_COUNT != 2380 or PRODUCTION_ACTIVATION or
        ROUTER_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY or
        !DEPENDENCIES_BORROWED_DURING_BUILD or
        !BUILD_FAILURE_RETAINS_DEPENDENCIES or
        !COLD_OPEN_OWNS_DEPENDENCY_PAIR or Adapter.available)
    {
        @compileError("common-fold stage104 worker boundary drifted");
    }
    if (@hasDecl(Adapter.LeasePayload, "encode") or
        @hasDecl(Adapter.LeasePayload, "decode") or
        @hasDecl(Adapter.LeasePayload, "encodeAlloc") or
        @hasDecl(Adapter.LeasePayload, "decodeAlloc"))
    {
        @compileError("stage104 live lease gained a durable codec");
    }
    _ = registry_mod;
}
