//! Final campaign role-0 fold child owned by one cold q193 verifier.
//!
//! The proof owner borrows its Stage-102 materialization, so this lease owns
//! that materialization at a stable heap address and destroys it only after
//! the cold proof.  The campaign node is sealed against the authenticated
//! runtime shape and the exact FinalRemint registry.  No legacy 210 -> 256
//! coordinate rule, durable digest, or transport receipt can mint this value.

const std = @import("std");

const materializer_mod =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const proof_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const artifact_v1 = @import("recursive_node_artifact_v1.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const projection_mod =
    @import("recursive_pipeline_campaign_fold_projection_v2.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const ROLE = registry_mod.CircuitRoleV4
    .ethereum_incremental_leaf_wrapper_v4;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const LEGACY_TOPOLOGY_ADMISSION = false;

pub const Authority = final_mod.CampaignFinalRemintAuthorityV2;
pub const PaddingTarget = target_mod.CampaignPaddingTargetV2;
pub const Registry = registry_mod.RecursiveCircuitRegistryV1;
pub const Geometry = registry_mod.AuthenticatedGeometryV1;
pub const Artifact = campaign_artifact.Artifact;
pub const CampaignProjectionV2 = projection_mod.ProjectionV2;

pub const Error = campaign_artifact.Error || registry_mod.Error || error{
    EthereumIncrementalCampaignFoldChildMismatchV4,
};

pub fn Types(comptime Engine: type) type {
    const Proof = proof_mod.Types(Engine);
    const ColdProof = Proof.OwnedColdProofV4;
    const Materialized =
        materializer_mod.PreparedOwnedCampaignCaptureV4(Engine);

    return struct {
        pub const ColdProofV4 = ColdProof;
        pub const MaterializedV4 = Materialized;

        /// Compatibility view for callers that still pass the registry as a
        /// separate argument.  The actual authority remains in `campaign`.
        pub const ProjectionV4 = struct {
            role: registry_mod.CircuitRoleV4,
            geometry: *const Geometry,
            campaign: CampaignProjectionV2,

            pub fn validateAgainst(
                self: ProjectionV4,
                registry: *const Registry,
            ) !void {
                const expected = try self.campaign.authority.registryAuthority();
                if (registry != expected or self.role != ROLE or
                    self.geometry != self.campaign.geometry)
                {
                    return error.EthereumIncrementalCampaignFoldChildMismatchV4;
                }
                try self.campaign.validateAgainstFinal(
                    self.campaign.authority,
                );
            }
        };

        /// Borrowed role-specific child. It has no codec and is valid only
        /// while the enclosing worker lease remains at the same address.
        pub const FreshFoldChildV4 = struct {
            owner: *const OwnedLeaseV4,

            pub fn validateBorrowed(self: FreshFoldChildV4) !void {
                try self.owner.validate();
            }

            pub fn campaignFoldProjection(
                self: FreshFoldChildV4,
                authority: *const Authority,
            ) !CampaignProjectionV2 {
                try self.validateBorrowed();
                return self.owner.campaignFoldProjection(authority);
            }
        };

        /// Heap-stable Stage-102 lease. `materialized` is owned even though
        /// it is typed const here: ColdProof sealed this exact address before
        /// the lease was constructed.
        pub const OwnedLeaseV4 = struct {
            pub const ROLE = registry_mod.CircuitRoleV4
                .ethereum_incremental_leaf_wrapper_v4;
            pub const FoldChild = FreshFoldChildV4;

            allocator: std.mem.Allocator,
            padding_target: *const PaddingTarget,
            final_remint: *const Authority,
            materialized: *Materialized,
            cold: ColdProof,
            node_artifact: Artifact,

            const Self = @This();

            /// Takes ownership of both arguments. The cold value must already
            /// borrow `materialized`; no move of the pointee is permitted.
            pub fn initOwned(
                allocator: std.mem.Allocator,
                padding_target: *const PaddingTarget,
                final_remint: *const Authority,
                materialized: *Materialized,
                cold: ColdProof,
            ) !Self {
                var owned_cold = cold;
                var cold_owned = true;
                errdefer if (cold_owned) owned_cold.deinit();
                var materialized_owned = true;
                errdefer if (materialized_owned) {
                    materialized.deinit();
                    allocator.destroy(materialized);
                };
                const node = try buildNodeArtifact(
                    &owned_cold,
                    final_remint,
                );
                var result = Self{
                    .allocator = allocator,
                    .padding_target = padding_target,
                    .final_remint = final_remint,
                    .materialized = materialized,
                    .cold = owned_cold,
                    .node_artifact = node,
                };
                owned_cold = undefined;
                cold_owned = false;
                materialized_owned = false;
                errdefer result.deinit();
                try result.validateForCampaign(final_remint);
                return result;
            }

            pub fn deinit(self: *Self) void {
                const allocator = self.allocator;
                self.cold.deinit();
                self.materialized.deinit();
                allocator.destroy(self.materialized);
                self.* = undefined;
            }

            pub fn validate(self: *const Self) !void {
                try self.validateForCampaign(self.final_remint);
            }

            pub fn validateForCampaign(
                self: *const Self,
                authority: *const Authority,
            ) !void {
                if (self.final_remint != authority or
                    self.cold.materialized != self.materialized)
                {
                    return error.EthereumIncrementalCampaignFoldChildMismatchV4;
                }
                try authority.validateAgainstCampaign(
                    self.node_artifact.campaign_namespace_sha256,
                );
                try self.padding_target.validateAgainstFinal(authority);
                try self.materialized.validate();
                try self.cold.validateForPaddingTarget(self.padding_target);
                const geometry = try authority.geometryForRole(
                    .ethereum_incremental_leaf_wrapper_v4,
                );
                if (!std.meta.eql(geometry.*, self.cold.geometry_value))
                    return error.EthereumIncrementalCampaignFoldChildMismatchV4;
                const expected = try buildNodeArtifact(&self.cold, authority);
                if (!std.meta.eql(expected, self.node_artifact))
                    return error.EthereumIncrementalCampaignFoldChildMismatchV4;
                const projection = try projectionFromLease(self, authority);
                try projection.validateAgainstFinal(authority);
            }

            pub fn validateColdGeometry(self: *const Self) !void {
                try self.validate();
            }

            pub fn geometryForPaddingTarget(self: *const Self) *const Geometry {
                return &self.final_remint.final_remint.final_geometries[
                    @intFromEnum(
                        registry_mod.CircuitRoleV4
                            .ethereum_incremental_leaf_wrapper_v4,
                    )
                ];
            }

            pub fn nodeArtifact(self: *const Self) *const Artifact {
                return &self.node_artifact;
            }

            pub fn proofBytes(self: *const Self) []const u8 {
                return self.cold.artifact_bytes;
            }

            pub fn requireFoldChild(self: *const Self) !FreshFoldChildV4 {
                try self.validate();
                return .{ .owner = self };
            }

            pub fn campaignFoldProjection(
                self: *const Self,
                authority: *const Authority,
            ) !CampaignProjectionV2 {
                try self.validateForCampaign(authority);
                return projectionFromLease(self, authority);
            }

            pub fn foldProjection(
                self: *const Self,
                registry: *const Registry,
            ) !ProjectionV4 {
                const expected = try self.final_remint.registryAuthority();
                if (registry != expected)
                    return error.EthereumIncrementalCampaignFoldChildMismatchV4;
                const campaign = try self.campaignFoldProjection(
                    self.final_remint,
                );
                const result = ProjectionV4{
                    .role = .ethereum_incremental_leaf_wrapper_v4,
                    .geometry = campaign.geometry,
                    .campaign = campaign,
                };
                try result.validateAgainst(registry);
                return result;
            }
        };

        fn projectionFromLease(
            lease: *const OwnedLeaseV4,
            authority: *const Authority,
        ) !CampaignProjectionV2 {
            const ingress = try lease.cold.ingressView();
            const graph = try lease.cold.foldGraphView();
            const geometry = try authority.geometryForRole(
                .ethereum_incremental_leaf_wrapper_v4,
            );
            return .{
                .role = ROLE,
                .authority = authority,
                .geometry = geometry,
                .node_artifact = &lease.node_artifact,
                .node_public = &lease.node_artifact.node_public,
                .claimed_sums = &lease.cold.claims.values,
                .claims_seal = &lease.cold.claims.seal,
                .session = ingress.session,
                .statement = ingress.statement,
                .capture = ingress.capture,
                .query_words = ingress.query_words,
                .query_log_size = ingress.query_log_size,
                .final_transcript_digest = ingress.final_transcript_digest,
                .final_transcript_draw_count = ingress.final_transcript_draw_count,
                .query_words_identity_sha256 = ingress.query_words_identity_sha256,
                .graph = .{
                    .capture_identity_sha256 = graph.capture_identity_sha256,
                    .layout_identity_sha256 = graph.layout_identity_sha256,
                    .query_words = graph.query_words,
                    .query_log_size = graph.query_log_size,
                    .final_transcript_digest = graph.final_transcript_digest,
                    .final_transcript_draw_count = graph.final_transcript_draw_count,
                    .query_words_identity_sha256 = graph.query_words_identity_sha256,
                    .lane = graph.lane,
                    .evaluation = graph.evaluation,
                },
            };
        }

        fn buildNodeArtifact(
            cold: *const ColdProof,
            authority: *const Authority,
        ) !Artifact {
            try cold.validateBorrowed();
            try authority.validateAgainstCampaign(
                authority.shape.campaign_namespace_sha256,
            );
            const registry = try authority.registryAuthority();
            const geometry = try authority.geometryForRole(ROLE);
            if (!std.meta.eql(geometry.*, cold.geometry_value))
                return error.EthereumIncrementalCampaignFoldChildMismatchV4;
            const entry = try registry.entry(
                .ethereum_incremental_leaf_wrapper_v4,
            );
            const source = stage101ArtifactRef(cold.materialized);
            const result = try campaign_artifact.seal(authority.shape, .{
                .stage_kind = .leaf_wrapper,
                .node_kind = .real,
                .child_count = 1,
                .coordinate = cold.materialized.base.input.coordinate,
                .node_public = cold.node_public,
                .campaign_namespace_sha256 = authority.shape.campaign_namespace_sha256,
                .circuit_identity_sha256 = entry.circuit_identity_sha256,
                .program_identity_sha256 = entry.program_identity_sha256,
                .profile_identity_sha256 = entry.profile_identity_sha256,
                .pcs_identity_sha256 = entry.pcs_identity_sha256,
                .padding_layout_identity_sha256 = entry.padding_layout_identity_sha256,
                .registry_identity_sha256 = registry.identity_sha256,
                .node_public_abi_sha256 = geometry.output_abi.node_public_abi_sha256,
                .proof_shape_identity_sha256 = geometry.proof_shape.identity_sha256,
                .ordered_children = .{
                    source,
                    artifact_v1.ArtifactRefV1.zero(),
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

        fn stage101ArtifactRef(materialized: *const Materialized) artifact_v1.ArtifactRefV1 {
            const input = &materialized.base.input;
            return .{
                .kind = 8,
                .format_version = artifact_v1.ARTIFACT_REF_FORMAT_VERSION,
                .schema_version = 1,
                .byte_count = input.artifact_byte_count,
                .sha256 = input.artifact_sha256,
            };
        }
    };
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        @intFromEnum(ROLE) != 0 or PRODUCTION_ACTIVATION or
        ROUTER_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY or
        LEGACY_TOPOLOGY_ADMISSION)
    {
        @compileError("campaign role-0 final fold child drifted");
    }
}
