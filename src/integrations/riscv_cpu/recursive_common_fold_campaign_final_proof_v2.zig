//! Final-remint-bound, all-level campaign common-fold proof family.
//!
//! Build borrows two nominal child leases only while producing the q193
//! proof. Before returning a parent lease it independently cold-opens an
//! owned child pair from the two durable node refs and cold-opens the parent
//! proof again. The returned lease can therefore outlive worker consumption
//! of the original dependency handles. No lease, graph, query authority, or
//! validation token has a codec.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const frontend = @import("stwo_riscv_frontend");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const final_live_mod =
    @import("recursive_common_fold_campaign_final_live_v2.zig");
const core_proof_mod =
    @import("recursive_common_fold_campaign_prefinal_proof_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const neutral = @import("recursive_pipeline_campaign_fold_projection_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_store =
    @import("recursive_campaign_node_artifact_store_v2.zig");
const campaign_cas = @import("recursive_pipeline_worker_campaign_cas_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const node_artifact = @import("recursive_node_artifact_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

const recursion = frontend.recursion;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const ROLE = registry_mod.CircuitRoleV1.common_fold_field_v2;
pub const CHILD_COUNT: usize = 2;
pub const PROOF_SCHEMA_VERSION: u16 = 1;
pub const CRYPTO_IMPLEMENTED = true;
pub const Q193_GENUINE_GATE_GREEN = false;
pub const ALL_NOMINAL_CHILD_PAIRS_AVAILABLE = false;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const GENUINE_GATE_ONLY = true;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const BUILD_BORROWS_ORIGINAL_CHILDREN = true;
pub const PROVER_OWNER_DESTROYED_BEFORE_COLD_OPEN = true;
pub const OUTPUT_LEASE_OWNS_COLD_OPENED_CHILDREN = true;

pub const Authority = final_mod.CampaignFinalRemintAuthorityV2;
pub const Geometry = registry_mod.AuthenticatedGeometryV1;
pub const Registry = registry_mod.RecursiveCircuitRegistryV1;

pub const Error = error{
    CampaignFinalCommonFoldArtifactMismatch,
    CampaignFinalCommonFoldChildMismatch,
    CampaignFinalCommonFoldGeometryMismatch,
    CampaignFinalCommonFoldOwnershipMismatch,
    CampaignFinalCommonFoldTypeMismatch,
    CampaignFinalCommonFoldUnavailable,
};

/// Self-recursive all-level facade. The common arm is pointer-only, so it can
/// name this exact family's output lease without erasing its nominal type.
/// `ChildColdOpenerFactory.ForDependencyLease` supplies the corresponding
/// recursively owned pair after the worker registry cold-opens both refs.
pub fn AllLevelTypes(
    comptime dimensions: recursion.fixed_wire.Dimensions,
    comptime RealLease: type,
    comptime EmptyLease: type,
    comptime ChildColdOpenerFactory: type,
) type {
    assertFinalRoleLease(RealLease, .ethereum_incremental_leaf_wrapper_v4);
    assertFinalRoleLease(EmptyLease, .canonical_empty_field_v2);
    if (!@hasDecl(ChildColdOpenerFactory, "ForDependencyLease"))
        @compileError("campaign child cold-opener factory is incomplete");

    return struct {
        const SelfTypes = @This();

        /// Process-local indirection that breaks the nominal recursive type
        /// cycle without erasing validation. The bridge is private to this
        /// exact `AllLevelTypes` instantiation; every method first checks its
        /// vtable pointer, then the typed owner reruns its normal campaign
        /// validation. Neither the handle nor its vtable has a codec.
        pub const CommonLeaseHandleV2 = struct {
            pub const ROLE = registry_mod.CircuitRoleV1
                .common_fold_field_v2;

            const VTableV2 = struct {
                deinit: *const fn (*anyopaque, std.mem.Allocator) void,
                validate_for_campaign: *const fn (
                    *const anyopaque,
                    *const Authority,
                ) anyerror!void,
                campaign_fold_projection: *const fn (
                    *const anyopaque,
                    *const Authority,
                ) anyerror!neutral.ProjectionV2,
                node_artifact: *const fn (
                    *const anyopaque,
                ) *const campaign_artifact.Artifact,
            };

            owner: *anyopaque,
            allocator: std.mem.Allocator,
            vtable: *const VTableV2,
            owns_owner: bool,

            pub fn deinit(self: *CommonLeaseHandleV2) void {
                // A handle can only be minted by `CommonBridgeV2.open`.
                // Treat an in-process forged/mutated bridge as a programmer
                // error rather than casting through an unauthenticated type.
                std.debug.assert(self.vtable == &CommonBridgeV2.vtable);
                if (self.owns_owner)
                    self.vtable.deinit(self.owner, self.allocator);
                self.* = undefined;
            }

            /// Short-lived bridge for a common-fold lease already owned by
            /// the same persistent worker. The caller must keep `value`
            /// alive for the complete parent build and deinitialize this
            /// bridge before allowing the worker to consume that lease.
            pub fn borrow(
                value: *const ProofFamily.LeasePayload,
            ) !CommonLeaseHandleV2 {
                try value.validate();
                return .{
                    .owner = @ptrCast(@constCast(value)),
                    .allocator = undefined,
                    .vtable = &CommonBridgeV2.vtable,
                    .owns_owner = false,
                };
            }

            pub fn validateForCampaign(
                self: *const CommonLeaseHandleV2,
                authority: *const Authority,
            ) !void {
                const vtable = try self.validatedVTable();
                try vtable.validate_for_campaign(self.owner, authority);
            }

            pub fn campaignFoldProjection(
                self: *const CommonLeaseHandleV2,
                authority: *const Authority,
            ) !neutral.ProjectionV2 {
                const vtable = try self.validatedVTable();
                const result = try vtable.campaign_fold_projection(
                    self.owner,
                    authority,
                );
                try result.validateAgainstFinal(authority);
                if (result.role != CommonLeaseHandleV2.ROLE)
                    return error.CampaignFinalCommonFoldTypeMismatch;
                return result;
            }

            pub fn nodeArtifact(
                self: *const CommonLeaseHandleV2,
            ) *const campaign_artifact.Artifact {
                // All callers first invoke `validateForCampaign`; keep the
                // uniform role-lease accessor infallible without accepting a
                // foreign vtable.
                std.debug.assert(self.vtable == &CommonBridgeV2.vtable);
                return self.vtable.node_artifact(self.owner);
            }

            fn validatedVTable(
                self: *const CommonLeaseHandleV2,
            ) !*const VTableV2 {
                if (self.vtable != &CommonBridgeV2.vtable)
                    return error.CampaignFinalCommonFoldTypeMismatch;
                return self.vtable;
            }
        };

        pub const DependencyLease = union(registry_mod.CircuitRoleV1) {
            ethereum_incremental_leaf_wrapper_v4: *const RealLease,
            canonical_empty_field_v2: *const EmptyLease,
            common_fold_field_v2: *const CommonLeaseHandleV2,

            const Self = @This();

            pub fn fromReal(value: *const RealLease) Self {
                return .{ .ethereum_incremental_leaf_wrapper_v4 = value };
            }

            pub fn fromEmpty(value: *const EmptyLease) Self {
                return .{ .canonical_empty_field_v2 = value };
            }

            pub fn fromCommon(
                value: *const CommonLeaseHandleV2,
            ) Self {
                return .{ .common_fold_field_v2 = value };
            }

            /// The concrete child opener calls this only after authenticating
            /// the durable kind-10/schema-2 node. The returned handle owns a
            /// fresh recursive cold proof and can outlive the caller's lease.
            pub fn coldOpenCommonNode(
                allocator: std.mem.Allocator,
                store: *artifact_store.Store,
                authority: *const Authority,
                node_ref: artifact_store.BlobRefV1,
            ) !CommonLeaseHandleV2 {
                return CommonBridgeV2.open(
                    allocator,
                    store,
                    authority,
                    node_ref,
                );
            }

            /// Same production lease type and recursive custody as
            /// `coldOpenCommonNode`, exposed only to the genuine q193 gate
            /// while release flags remain false.
            pub fn coldOpenCommonNodeForGenuineGate(
                allocator: std.mem.Allocator,
                store: *artifact_store.Store,
                authority: *const Authority,
                node_ref: artifact_store.BlobRefV1,
            ) anyerror!CommonLeaseHandleV2 {
                return CommonBridgeV2.openForGenuineGate(
                    allocator,
                    store,
                    authority,
                    node_ref,
                );
            }

            pub fn role(self: *const Self) registry_mod.CircuitRoleV1 {
                return std.meta.activeTag(self.*);
            }

            pub fn validateAgainst(
                self: *const Self,
                authority: *const Authority,
            ) !void {
                _ = try self.foldProjection(authority);
            }

            pub fn foldProjection(
                self: *const Self,
                authority: *const Authority,
            ) !neutral.ProjectionV2 {
                const result = switch (self.*) {
                    .ethereum_incremental_leaf_wrapper_v4 => |lease| blk: {
                        try lease.validateForCampaign(authority);
                        break :blk try lease.campaignFoldProjection(authority);
                    },
                    .canonical_empty_field_v2 => |lease| blk: {
                        try lease.validateForCampaign(authority);
                        break :blk try lease.campaignFoldProjection(authority);
                    },
                    .common_fold_field_v2 => |lease| blk: {
                        try lease.validateForCampaign(authority);
                        break :blk try lease.campaignFoldProjection(authority);
                    },
                };
                try result.validateAgainstFinal(authority);
                if (result.role != self.role())
                    return error.CampaignFinalCommonFoldChildMismatch;
                return result;
            }
        };

        const CommonBridgeV2 = struct {
            const vtable = CommonLeaseHandleV2.VTableV2{
                .deinit = deinitOwner,
                .validate_for_campaign = validateOwner,
                .campaign_fold_projection = projectOwner,
                .node_artifact = nodeArtifactOwner,
            };

            fn open(
                allocator: std.mem.Allocator,
                store: *artifact_store.Store,
                authority: *const Authority,
                node_ref: artifact_store.BlobRefV1,
            ) !CommonLeaseHandleV2 {
                const owner = try allocator.create(ProofFamily.LeasePayload);
                errdefer allocator.destroy(owner);
                owner.* = try ProofFamily.LeasePayload.coldOpenFromNodeRef(
                    allocator,
                    store,
                    authority,
                    node_ref,
                );
                errdefer owner.deinit();
                return .{
                    .owner = owner,
                    .allocator = allocator,
                    .vtable = &vtable,
                    .owns_owner = true,
                };
            }

            fn openForGenuineGate(
                allocator: std.mem.Allocator,
                store: *artifact_store.Store,
                authority: *const Authority,
                node_ref: artifact_store.BlobRefV1,
            ) !CommonLeaseHandleV2 {
                const owner = try allocator.create(ProofFamily.LeasePayload);
                errdefer allocator.destroy(owner);
                owner.* = try ProofFamily.LeasePayload
                    .coldOpenFromNodeRefForGenuineGate(
                    allocator,
                    store,
                    authority,
                    node_ref,
                );
                errdefer owner.deinit();
                return .{
                    .owner = owner,
                    .allocator = allocator,
                    .vtable = &vtable,
                    .owns_owner = true,
                };
            }

            fn deinitOwner(
                erased: *anyopaque,
                allocator: std.mem.Allocator,
            ) void {
                const owner: *ProofFamily.LeasePayload = @ptrCast(
                    @alignCast(erased),
                );
                owner.deinit();
                allocator.destroy(owner);
            }

            fn validateOwner(
                erased: *const anyopaque,
                authority: *const Authority,
            ) !void {
                const owner: *const ProofFamily.LeasePayload = @ptrCast(
                    @alignCast(erased),
                );
                try owner.validateForCampaign(authority);
            }

            fn projectOwner(
                erased: *const anyopaque,
                authority: *const Authority,
            ) !neutral.ProjectionV2 {
                const owner: *const ProofFamily.LeasePayload = @ptrCast(
                    @alignCast(erased),
                );
                return owner.campaignFoldProjection(authority);
            }

            fn nodeArtifactOwner(
                erased: *const anyopaque,
            ) *const campaign_artifact.Artifact {
                const owner: *const ProofFamily.LeasePayload = @ptrCast(
                    @alignCast(erased),
                );
                return owner.nodeArtifact();
            }
        };

        pub const ChildColdOpener = ChildColdOpenerFactory
            .ForDependencyLease(DependencyLease);
        pub const ProofFamily = Types(
            dimensions,
            DependencyLease,
            ChildColdOpener,
        );

        comptime {
            rejectCodec(DependencyLease);
            rejectCodec(CommonLeaseHandleV2);
            if (ProofFamily.DependencyLeaseV2 != DependencyLease or
                ProofFamily.ChildColdOpenerV2 != ChildColdOpener)
            {
                @compileError("campaign all-level fold family lost nominal custody");
            }
            _ = SelfTypes;
        }
    };
}

/// `DependencyLease` is the role-neutral tagged lease. `ChildColdOpener`
/// recursively cold-opens the exact two kind-10/schema-2 refs and owns the
/// role-specific verifier leases behind two new tagged values.
pub fn Types(
    comptime dimensions: recursion.fixed_wire.Dimensions,
    comptime DependencyLease: type,
    comptime ChildColdOpener: type,
) type {
    dimensions.validate();
    assertDependencyLease(DependencyLease);
    assertChildColdOpener(ChildColdOpener, DependencyLease);

    const LiveTypes = final_live_mod.Types(DependencyLease);
    const CoreProof = core_proof_mod.TypesForLive(dimensions, LiveTypes);

    return struct {
        const SelfTypes = @This();

        pub const available = CRYPTO_IMPLEMENTED and
            Q193_GENUINE_GATE_GREEN and
            ALL_NOMINAL_CHILD_PAIRS_AVAILABLE and
            ChildColdOpener.available;
        pub const q193_genuine_gate_green = Q193_GENUINE_GATE_GREEN;
        pub const DependencyLeaseV2 = DependencyLease;
        pub const ChildColdOpenerV2 = ChildColdOpener;
        pub const LiveTypesV2 = LiveTypes;
        pub const CoreProofV2 = CoreProof;

        pub const FoldProjectionV2 = struct {
            role: registry_mod.CircuitRoleV1,
            geometry: *const Geometry,
            campaign: neutral.ProjectionV2,

            pub fn validateAgainst(
                self: FoldProjectionV2,
                registry: *const Registry,
            ) !void {
                const expected = try self.campaign.authority
                    .registryAuthority();
                if (registry != expected or self.role != ROLE or
                    self.geometry != self.campaign.geometry)
                {
                    return error.CampaignFinalCommonFoldGeometryMismatch;
                }
                try self.campaign.validateAgainstFinal(
                    self.campaign.authority,
                );
            }
        };

        pub const FreshFoldChildV2 = struct {
            owner: *const LeasePayload,

            pub fn validateBorrowed(self: FreshFoldChildV2) !void {
                try self.owner.validate();
            }

            pub fn campaignFoldProjection(
                self: FreshFoldChildV2,
                authority: *const Authority,
            ) !neutral.ProjectionV2 {
                try self.validateBorrowed();
                return self.owner.campaignFoldProjection(authority);
            }
        };

        const StorageV2 = struct {
            allocator: std.mem.Allocator,
            authority: *const Authority,
            target: target_mod.CampaignPaddingTargetV2,
            owned_children: ChildColdOpener.OwnedPair,
            dependency_leases: [CHILD_COUNT]DependencyLease,
            fold_input: LiveTypes.FoldInputV2,
            live: LiveTypes.LiveV2,
            cold: CoreProof.OwnedColdProofV2,
            node_artifact: campaign_artifact.Artifact,
        };

        /// Small movable handle around heap-stable proof/child custody.
        pub const LeasePayload = struct {
            pub const ROLE = registry_mod.CircuitRoleV1
                .common_fold_field_v2;
            pub const FoldChild = FreshFoldChildV2;

            storage: *StorageV2,

            pub fn deinit(self: *LeasePayload) void {
                const storage = self.storage;
                const allocator = storage.allocator;
                storage.cold.deinit();
                ChildColdOpener.deinitOwnedPair(
                    &storage.owned_children,
                    allocator,
                );
                storage.* = undefined;
                allocator.destroy(storage);
                self.* = undefined;
            }

            pub fn validate(self: *const LeasePayload) !void {
                try self.validateForCampaign(self.storage.authority);
            }

            pub fn validateForCampaign(
                self: *const LeasePayload,
                authority: *const Authority,
            ) !void {
                const storage = self.storage;
                if (storage.authority != authority or
                    storage.cold.live != &storage.live or
                    storage.cold.padding_target != &storage.target)
                {
                    return error.CampaignFinalCommonFoldOwnershipMismatch;
                }
                try storage.target.validateAgainstFinal(authority);
                const reopened = try ChildColdOpener.views(
                    &storage.owned_children,
                    authority,
                );
                inline for (0..CHILD_COUNT) |index| {
                    try reopened[index].validateAgainst(authority);
                    if (!std.meta.eql(
                        reopened[index],
                        storage.dependency_leases[index],
                    )) return error.CampaignFinalCommonFoldOwnershipMismatch;
                }
                try storage.fold_input.validate();
                try storage.live.validate();
                try storage.cold.validateForPaddingTarget(&storage.target);
                const geometry = try authority.geometryForRole(
                    LeasePayload.ROLE,
                );
                if (!std.meta.eql(
                    geometry.*,
                    storage.cold.geometry_value,
                )) return error.CampaignFinalCommonFoldGeometryMismatch;
                const expected = try buildNodeArtifact(
                    authority,
                    &storage.cold,
                    storage.node_artifact.ordered_children,
                );
                if (!std.meta.eql(expected, storage.node_artifact))
                    return error.CampaignFinalCommonFoldArtifactMismatch;
            }

            pub fn validateColdGeometry(self: *const LeasePayload) !void {
                try self.validate();
            }

            pub fn geometryForPaddingTarget(
                self: *const LeasePayload,
            ) *const Geometry {
                return &self.storage.cold.geometry_value;
            }

            pub fn proofBytes(self: *const LeasePayload) []const u8 {
                return self.storage.cold.proofBytes();
            }

            pub fn nodeArtifact(
                self: *const LeasePayload,
            ) *const campaign_artifact.Artifact {
                return &self.storage.node_artifact;
            }

            pub fn requireFoldChild(
                self: *const LeasePayload,
            ) !FreshFoldChildV2 {
                try self.validate();
                return .{ .owner = self };
            }

            /// Transitive cold-open used only by the composite child opener.
            /// It authenticates the node/ref and proof CAS bytes, recursively
            /// owns both children, and then performs a new q193 cold verify.
            pub fn coldOpenFromNodeRef(
                allocator: std.mem.Allocator,
                store: *artifact_store.Store,
                authority: *const Authority,
                node_ref: artifact_store.BlobRefV1,
            ) !LeasePayload {
                if (!available)
                    return error.CampaignFinalCommonFoldUnavailable;
                return coldOpenFromNodeRefImpl(
                    allocator,
                    store,
                    authority,
                    node_ref,
                    false,
                );
            }

            /// Exact recursive production custody for the genuine q193 gate.
            /// It returns this same `LeasePayload` type, never a fixture or
            /// digest-promoted substitute, and bypasses only release flags.
            pub fn coldOpenFromNodeRefForGenuineGate(
                allocator: std.mem.Allocator,
                store: *artifact_store.Store,
                authority: *const Authority,
                node_ref: artifact_store.BlobRefV1,
            ) !LeasePayload {
                return coldOpenFromNodeRefImpl(
                    allocator,
                    store,
                    authority,
                    node_ref,
                    true,
                );
            }

            fn coldOpenFromNodeRefImpl(
                allocator: std.mem.Allocator,
                store: *artifact_store.Store,
                authority: *const Authority,
                node_ref: artifact_store.BlobRefV1,
                comptime genuine_gate: bool,
            ) !LeasePayload {
                const artifact = try campaign_store
                    .coldOpenRecursiveNodeTransport(
                    store,
                    authority.shape,
                    node_ref,
                );
                if (artifact.stage_kind != .fold and
                    artifact.stage_kind != .root)
                {
                    return error.CampaignFinalCommonFoldArtifactMismatch;
                }
                const geometry = try authority.geometryForRole(
                    LeasePayload.ROLE,
                );
                try campaign_artifact.admitRegistry(
                    try authority.registryAuthority(),
                    authority.shape,
                    &artifact,
                    geometry,
                );
                const proof_ref = try node_store.toSharedRef(
                    artifact.proof_ref,
                );
                try campaign_cas.validate(proof_ref, .proof);
                var proof = try store.openBlob(
                    proof_ref,
                    .proof_artifact,
                    campaign_cas.PROOF_SCHEMA_VERSION,
                    campaign_cas.MAX_PROOF_BYTE_COUNT,
                );
                defer proof.deinit(store.allocator);
                const ordered_inputs = try orderedInputsFromArtifact(
                    &artifact,
                );
                const pair = if (comptime genuine_gate)
                    try ChildColdOpener.coldOpenPairForGenuineGate(
                        allocator,
                        store,
                        authority,
                        &ordered_inputs,
                    )
                else
                    try ChildColdOpener.coldOpenPairFromInputs(
                        allocator,
                        store,
                        authority,
                        &ordered_inputs,
                    );
                var result = try LeasePayload.initConsumingOwnedPair(
                    allocator,
                    authority,
                    pair,
                    &ordered_inputs,
                    proof.bytes,
                );
                errdefer result.deinit();
                if (!std.meta.eql(result.nodeArtifact().*, artifact))
                    return error.CampaignFinalCommonFoldArtifactMismatch;
                try result.validateForCampaign(authority);
                return result;
            }

            pub fn campaignFoldProjection(
                self: *const LeasePayload,
                authority: *const Authority,
            ) !neutral.ProjectionV2 {
                try self.validateForCampaign(authority);
                const storage = self.storage;
                const source = try storage.cold.preFinalFoldProjection(
                    &storage.target,
                );
                const geometry = try authority.geometryForRole(
                    LeasePayload.ROLE,
                );
                const result = neutral.ProjectionV2{
                    .role = LeasePayload.ROLE,
                    .authority = authority,
                    .geometry = geometry,
                    .node_artifact = &storage.node_artifact,
                    .node_public = &storage.node_artifact.node_public,
                    .claimed_sums = source.claimed_sums,
                    .claims_seal = source.claims_seal,
                    .session = source.session,
                    .statement = source.statement,
                    .capture = source.capture,
                    .query_words = source.query_words,
                    .query_log_size = source.query_log_size,
                    .final_transcript_digest = source
                        .final_transcript_digest,
                    .final_transcript_draw_count = source
                        .final_transcript_draw_count,
                    .query_words_identity_sha256 = source
                        .query_words_identity_sha256,
                    .graph = .{
                        .capture_identity_sha256 = source.graph
                            .capture_identity_sha256,
                        .layout_identity_sha256 = source.graph
                            .layout_identity_sha256,
                        .query_words = source.graph.query_words,
                        .query_log_size = source.graph.query_log_size,
                        .final_transcript_digest = source.graph
                            .final_transcript_digest,
                        .final_transcript_draw_count = source.graph
                            .final_transcript_draw_count,
                        .query_words_identity_sha256 = source.graph
                            .query_words_identity_sha256,
                        .lane = source.graph.lane,
                        .evaluation = source.graph.evaluation,
                    },
                };
                try result.validateAgainstFinal(authority);
                return result;
            }

            pub fn foldProjection(
                self: *const LeasePayload,
                registry: *const Registry,
            ) !FoldProjectionV2 {
                const campaign = try self.campaignFoldProjection(
                    self.storage.authority,
                );
                const result = FoldProjectionV2{
                    .role = LeasePayload.ROLE,
                    .geometry = campaign.geometry,
                    .campaign = campaign,
                };
                try result.validateAgainst(registry);
                return result;
            }

            /// Consumes `owned_pair` on both success and error. The caller
            /// must relinquish its guard before invoking this function.
            fn initConsumingOwnedPair(
                allocator: std.mem.Allocator,
                authority: *const Authority,
                owned_pair: ChildColdOpener.OwnedPair,
                ordered_inputs: []const artifact_store.InputRefV1,
                proof_bytes: []const u8,
            ) !LeasePayload {
                var pair = owned_pair;
                var pair_owned = true;
                errdefer if (pair_owned) ChildColdOpener.deinitOwnedPair(
                    &pair,
                    allocator,
                );
                const storage = try allocator.create(StorageV2);
                errdefer allocator.destroy(storage);
                storage.allocator = allocator;
                storage.authority = authority;
                storage.target = try target_mod.CampaignPaddingTargetV2
                    .fromFinal(authority);
                storage.owned_children = pair;
                pair = undefined;
                pair_owned = false;
                var storage_pair_owned = true;
                errdefer if (storage_pair_owned)
                    ChildColdOpener.deinitOwnedPair(
                        &storage.owned_children,
                        allocator,
                    );
                storage.dependency_leases = try ChildColdOpener.views(
                    &storage.owned_children,
                    authority,
                );
                const projections = try validateChildrenAndInputs(
                    authority,
                    &storage.dependency_leases,
                    ordered_inputs,
                );
                const parent_coordinate = try parentCoordinate(
                    authority.shape,
                    projections[0].node_public,
                    projections[1].node_public,
                );
                storage.fold_input = try LiveTypes.FoldInputV2.init(
                    &storage.target,
                    projections[0].node_public,
                    projections[1].node_public,
                    parent_coordinate,
                );
                storage.live = try LiveTypes.LiveV2.init(
                    &storage.fold_input,
                    .{
                        try LiveTypes.FoldChild.init(
                            &storage.target,
                            authority,
                            &storage.dependency_leases[0],
                        ),
                        try LiveTypes.FoldChild.init(
                            &storage.target,
                            authority,
                            &storage.dependency_leases[1],
                        ),
                    },
                );
                storage.cold = try CoreProof.coldOpen(
                    allocator,
                    &storage.target,
                    &storage.live,
                    proof_bytes,
                );
                var cold_owned = true;
                errdefer if (cold_owned) storage.cold.deinit();
                const children = try childArtifactRefs(
                    authority,
                    &storage.dependency_leases,
                    ordered_inputs,
                );
                storage.node_artifact = try buildNodeArtifact(
                    authority,
                    &storage.cold,
                    children,
                );
                const result = LeasePayload{ .storage = storage };
                try result.validateForCampaign(authority);
                cold_owned = false;
                storage_pair_owned = false;
                return result;
            }
        };

        pub const ProvedV2 = struct {
            lease: LeasePayload,
            receipt: secure_engine.ReceiptV1,

            pub fn deinit(self: *ProvedV2) void {
                self.lease.deinit();
                self.* = undefined;
            }

            pub fn validate(
                self: *const ProvedV2,
                authorities: anytype,
                dependency_leases: []const *const DependencyLease,
            ) !void {
                try self.receipt.validate();
                try self.lease.validateForCampaign(
                    authorities.final_remint,
                );
                try SelfTypes.validateBorrowedChildren(
                    dependency_leases,
                    authorities,
                    &.{
                        .{
                            .role = .child_left,
                            .ordinal = 0,
                            .blob = try node_store.toSharedRef(
                                self.lease.storage.node_artifact
                                    .ordered_children[0],
                            ),
                        },
                        .{
                            .role = .child_right,
                            .ordinal = 0,
                            .blob = try node_store.toSharedRef(
                                self.lease.storage.node_artifact
                                    .ordered_children[1],
                            ),
                        },
                    },
                );
            }

            pub fn proofBytes(self: *const ProvedV2) []const u8 {
                return self.lease.proofBytes();
            }

            pub fn nodeArtifact(
                self: *const ProvedV2,
            ) *const campaign_artifact.Artifact {
                return self.lease.nodeArtifact();
            }
        };

        pub fn validateBorrowedChildren(
            dependency_leases: []const *const DependencyLease,
            authorities: anytype,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !void {
            if (dependency_leases.len != CHILD_COUNT)
                return error.CampaignFinalCommonFoldChildMismatch;
            const children: [CHILD_COUNT]DependencyLease = .{
                dependency_leases[0].*,
                dependency_leases[1].*,
            };
            _ = try validateChildrenAndInputs(
                authorities.final_remint,
                &children,
                ordered_inputs,
            );
        }

        pub fn proveAndColdVerify(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            authorities: anytype,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const DependencyLease,
            worker_count: usize,
        ) !ProvedV2 {
            if (!available) return error.CampaignFinalCommonFoldUnavailable;
            return proveAndColdVerifyImpl(
                allocator,
                store,
                authorities,
                node,
                semantic,
                ordered_inputs,
                candidate_ordinal,
                dependency_leases,
                worker_count,
                false,
            );
        }

        /// Full production-typed transaction for the coordinated genuine
        /// gate. Original children are borrowed only during proving; the
        /// returned lease owns two independently cold-opened CAS children.
        pub fn proveAndColdVerifyForGenuineGate(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            authorities: anytype,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const DependencyLease,
            worker_count: usize,
        ) !ProvedV2 {
            return proveAndColdVerifyImpl(
                allocator,
                store,
                authorities,
                node,
                semantic,
                ordered_inputs,
                candidate_ordinal,
                dependency_leases,
                worker_count,
                true,
            );
        }

        fn proveAndColdVerifyImpl(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            authorities: anytype,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const DependencyLease,
            worker_count: usize,
            comptime genuine_gate: bool,
        ) !ProvedV2 {
            _ = candidate_ordinal;
            try validateBorrowedChildren(
                dependency_leases,
                authorities,
                ordered_inputs,
            );
            const borrowed: [CHILD_COUNT]DependencyLease = .{
                dependency_leases[0].*,
                dependency_leases[1].*,
            };
            const target = try target_mod.CampaignPaddingTargetV2.fromFinal(
                authorities.final_remint,
            );
            const projections = try validateChildrenAndInputs(
                authorities.final_remint,
                &borrowed,
                ordered_inputs,
            );
            const coordinate = try parentCoordinate(
                authorities.shape,
                projections[0].node_public,
                projections[1].node_public,
            );
            const fold_input = try LiveTypes.FoldInputV2.init(
                &target,
                projections[0].node_public,
                projections[1].node_public,
                coordinate,
            );
            const live = try LiveTypes.LiveV2.init(&fold_input, .{
                try LiveTypes.FoldChild.init(
                    &target,
                    authorities.final_remint,
                    &borrowed[0],
                ),
                try LiveTypes.FoldChild.init(
                    &target,
                    authorities.final_remint,
                    &borrowed[1],
                ),
            });
            // Retain only canonical bytes and the value-only receipt. The
            // prover-owned cold proof is destroyed before any child or parent
            // cold-open, so the returned production lease cannot borrow it.
            const retained = blk: {
                var proved = try CoreProof.proveAndColdVerify(
                    allocator,
                    &target,
                    &live,
                    .{ .worker_count = worker_count },
                );
                defer proved.deinit();
                const proof_bytes = try allocator.dupe(
                    u8,
                    proved.proof.proofBytes(),
                );
                errdefer allocator.free(proof_bytes);
                break :blk .{
                    .proof_bytes = proof_bytes,
                    .receipt = proved.receipt,
                };
            };
            defer allocator.free(retained.proof_bytes);

            _ = node;
            _ = semantic;
            const pair = if (comptime genuine_gate)
                try ChildColdOpener.coldOpenPairForGenuineGate(
                    allocator,
                    store,
                    authorities.final_remint,
                    ordered_inputs,
                )
            else
                try ChildColdOpener.coldOpenPairFromInputs(
                    allocator,
                    store,
                    authorities.final_remint,
                    ordered_inputs,
                );
            var lease = try LeasePayload.initConsumingOwnedPair(
                allocator,
                authorities.final_remint,
                pair,
                ordered_inputs,
                retained.proof_bytes,
            );
            errdefer lease.deinit();
            const result = ProvedV2{
                .lease = lease,
                .receipt = retained.receipt,
            };
            try result.validate(authorities, dependency_leases);
            return result;
        }

        pub fn coldOpenOwned(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            authorities: anytype,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            proof_bytes: []const u8,
            node_bytes: []const u8,
        ) !LeasePayload {
            if (!available) return error.CampaignFinalCommonFoldUnavailable;
            return coldOpenOwnedImpl(
                allocator,
                store,
                authorities,
                node,
                semantic,
                ordered_inputs,
                proof_bytes,
                node_bytes,
                false,
            );
        }

        /// Independent cold-open counterpart to the genuine prove gate. It
        /// reopens both child nodes recursively and q193-verifies this parent
        /// into the exact production `LeasePayload` owner.
        pub fn coldOpenOwnedForGenuineGate(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            authorities: anytype,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            proof_bytes: []const u8,
            node_bytes: []const u8,
        ) !LeasePayload {
            return coldOpenOwnedImpl(
                allocator,
                store,
                authorities,
                node,
                semantic,
                ordered_inputs,
                proof_bytes,
                node_bytes,
                true,
            );
        }

        fn coldOpenOwnedImpl(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            authorities: anytype,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            proof_bytes: []const u8,
            node_bytes: []const u8,
            comptime genuine_gate: bool,
        ) !LeasePayload {
            const expected = try campaign_artifact.decodeCanonical(
                authorities.shape,
                node_bytes,
            );
            _ = node;
            _ = semantic;
            const pair = if (comptime genuine_gate)
                try ChildColdOpener.coldOpenPairForGenuineGate(
                    allocator,
                    store,
                    authorities.final_remint,
                    ordered_inputs,
                )
            else
                try ChildColdOpener.coldOpenPairFromInputs(
                    allocator,
                    store,
                    authorities.final_remint,
                    ordered_inputs,
                );
            var result = try LeasePayload.initConsumingOwnedPair(
                allocator,
                authorities.final_remint,
                pair,
                ordered_inputs,
                proof_bytes,
            );
            errdefer result.deinit();
            if (!std.meta.eql(result.nodeArtifact().*, expected))
                return error.CampaignFinalCommonFoldArtifactMismatch;
            try result.validateForCampaign(authorities.final_remint);
            return result;
        }

        pub fn validateLease(
            value: *const LeasePayload,
            authorities: anytype,
            artifact: *const campaign_artifact.Artifact,
        ) !void {
            try value.validateForCampaign(authorities.final_remint);
            if (!std.meta.eql(value.nodeArtifact().*, artifact.*))
                return error.CampaignFinalCommonFoldArtifactMismatch;
        }

        pub fn deinitLeasePayload(value: *LeasePayload) void {
            value.deinit();
        }

        fn validateChildrenAndInputs(
            authority: *const Authority,
            children: *const [CHILD_COUNT]DependencyLease,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) ![CHILD_COUNT]neutral.ProjectionV2 {
            if (ordered_inputs.len != CHILD_COUNT)
                return error.CampaignFinalCommonFoldChildMismatch;
            var result: [CHILD_COUNT]neutral.ProjectionV2 = undefined;
            const roles = [_]artifact_store.InputRoleV1{
                .child_left,
                .child_right,
            };
            for (children, ordered_inputs, roles, &result) |
                child,
                input,
                input_role,
                *destination,
            | {
                try child.validateAgainst(authority);
                destination.* = try child.foldProjection(authority);
                try destination.validateAgainstFinal(authority);
                const expected = try campaign_artifact.artifactRef(
                    authority.shape,
                    destination.node_artifact,
                );
                if (input.role != input_role or input.ordinal != 0 or
                    !std.meta.eql(
                        expected,
                        try node_store.fromSharedRef(input.blob),
                    )) return error.CampaignFinalCommonFoldChildMismatch;
            }
            if (result[0].capture == result[1].capture or
                result[0].node_artifact == result[1].node_artifact)
            {
                return error.CampaignFinalCommonFoldChildMismatch;
            }
            return result;
        }

        fn childArtifactRefs(
            authority: *const Authority,
            children: *const [CHILD_COUNT]DependencyLease,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) ![CHILD_COUNT]node_artifact.ArtifactRefV1 {
            _ = try validateChildrenAndInputs(
                authority,
                children,
                ordered_inputs,
            );
            return .{
                try node_store.fromSharedRef(ordered_inputs[0].blob),
                try node_store.fromSharedRef(ordered_inputs[1].blob),
            };
        }

        fn orderedInputsFromArtifact(
            artifact: *const campaign_artifact.Artifact,
        ) ![CHILD_COUNT]artifact_store.InputRefV1 {
            if (artifact.child_count != CHILD_COUNT)
                return error.CampaignFinalCommonFoldArtifactMismatch;
            return .{
                .{
                    .role = .child_left,
                    .ordinal = 0,
                    .blob = try node_store.toSharedRef(
                        artifact.ordered_children[0],
                    ),
                },
                .{
                    .role = .child_right,
                    .ordinal = 0,
                    .blob = try node_store.toSharedRef(
                        artifact.ordered_children[1],
                    ),
                },
            };
        }

        fn buildNodeArtifact(
            authority: *const Authority,
            cold: *const CoreProof.OwnedColdProofV2,
            children: [CHILD_COUNT]node_artifact.ArtifactRefV1,
        ) !campaign_artifact.Artifact {
            try cold.validateForPaddingTarget(cold.padding_target);
            const geometry = try authority.geometryForRole(ROLE);
            if (!std.meta.eql(geometry.*, cold.geometry_value))
                return error.CampaignFinalCommonFoldGeometryMismatch;
            const registry = try authority.registryAuthority();
            const entry = try registry.entry(ROLE);
            const coordinate = cold.node_public.coordinate;
            const stage: node_artifact.StageKindV1 =
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
                .ordered_children = children,
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

        fn parentCoordinate(
            shape: *const target_mod.Shape,
            left: *const campaign_public.NodePublicV2,
            right: *const campaign_public.NodePublicV2,
        ) !campaign_public.TaskCoordinateV1 {
            try campaign_public.validate(shape, left);
            try campaign_public.validate(shape, right);
            const height = std.math.add(
                u8,
                left.coordinate.height,
                1,
            ) catch return error.CampaignFinalCommonFoldChildMismatch;
            const coordinate = try campaign_public.coordinate(
                shape,
                height,
                left.coordinate.index / @as(u32, CHILD_COUNT),
            );
            _ = try campaign_public.initParent(
                shape,
                left,
                right,
                coordinate,
            );
            return coordinate;
        }
    };
}

fn assertDependencyLease(comptime Lease: type) void {
    inline for (.{ "role", "validateAgainst", "foldProjection" }) |name|
        if (!@hasDecl(Lease, name))
            @compileError("campaign final common child missing " ++ name);
    rejectCodec(Lease);
}

fn assertFinalRoleLease(
    comptime Lease: type,
    comptime role: registry_mod.CircuitRoleV1,
) void {
    if (!@hasDecl(Lease, "ROLE") or Lease.ROLE != role)
        @compileError("campaign final role lease has wrong nominal role");
    inline for (.{ "validateForCampaign", "campaignFoldProjection" }) |name|
        if (!@hasDecl(Lease, name))
            @compileError("campaign final role lease missing " ++ name);
    rejectCodec(Lease);
}

fn assertChildColdOpener(comptime Opener: type, comptime Lease: type) void {
    inline for (.{
        "available",
        "DependencyLease",
        "OwnedPair",
        "coldOpenPairFromInputs",
        "coldOpenPairForGenuineGate",
        "views",
        "deinitOwnedPair",
    }) |name| if (!@hasDecl(Opener, name))
        @compileError("campaign child cold-opener missing " ++ name);
    if (Opener.DependencyLease != Lease)
        @compileError("campaign child cold-opener lease type mismatch");
    rejectCodec(Opener.OwnedPair);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign final common capability gained a codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        @intFromEnum(ROLE) != 2 or CHILD_COUNT != 2 or
        PROOF_SCHEMA_VERSION != 1 or !CRYPTO_IMPLEMENTED or
        Q193_GENUINE_GATE_GREEN or ALL_NOMINAL_CHILD_PAIRS_AVAILABLE or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or !GENUINE_GATE_ONLY or
        SERIALIZABLE_FRESH_CAPABILITY or
        !BUILD_BORROWS_ORIGINAL_CHILDREN or
        !PROVER_OWNER_DESTROYED_BEFORE_COLD_OPEN or
        !OUTPUT_LEASE_OWNS_COLD_OPENED_CHILDREN)
    {
        @compileError("campaign final common proof contract drifted");
    }
}
