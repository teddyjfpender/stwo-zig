//! Registry-admitted role-0 wrapper evidence.
//!
//! This layer adds the durable schema-2 recursive-node envelope only after
//! the role-0 proof core has completed canonical decode, q193 cold verify,
//! geometry remint, and composition-graph rerecording.  The registry is
//! checked as a value; no digest can mint the retained fresh capability.

const std = @import("std");

const capture_view =
    @import("recursive_common_ethereum_incremental_leaf_composition_capture_v4.zig");
const core_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4_core.zig");
const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const artifact_mod = @import("recursive_node_artifact_v2.zig");
const artifact_v1 = @import("recursive_node_artifact_v1.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const ROLE = registry_mod.CircuitRoleV4
    .ethereum_incremental_leaf_wrapper_v4;
pub const SOURCE_PROOF_ARTIFACT_KIND: u32 = 8;
pub const SOURCE_PROOF_ARTIFACT_SCHEMA_VERSION: u16 = 1;
pub const OUTPUT_ARTIFACT_KIND: u32 =
    artifact_mod.RECURSIVE_NODE_ARTIFACT_KIND;
pub const OUTPUT_ARTIFACT_SCHEMA_VERSION: u16 = artifact_mod.SCHEMA_VERSION;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const Error = artifact_mod.Error || registry_mod.Error || error{
    EthereumIncrementalUniversalEvidenceMismatchV4,
};

pub fn Types(comptime Engine: type) type {
    const Core = core_mod.Types(Engine);
    const ColdProof = Core.OwnedColdProofV4;
    const GraphView = Core.Graph;
    const IngressView = Core.Ingress;

    return struct {
        pub const CoreTypesV4 = Core;

        /// Complete current-process role-0 capability. `cold` is heap-stable
        /// so every pointer exported through the fold-child view remains
        /// valid until `deinit`.
        pub const EvidenceV4 = struct {
            allocator: std.mem.Allocator,
            cold: *ColdProof,
            node_artifact: artifact_mod.RecursiveNodeArtifactV2,
            registry_value: registry_mod.RecursiveCircuitRegistryV1,
            // Legacy wrapper interface; mutable nested capture slices remain
            // protected by explicit validateFresh/validateBorrowed admission.
            cached_capture: *const common_authority.ProofCapture,

            pub const ROLE = registry_mod.CircuitRoleV4
                .ethereum_incremental_leaf_wrapper_v4;
            pub const Ingress = Core.Ingress;
            pub const Graph = Core.Graph;
            pub const BorrowedViews = struct {
                wrapper: common_authority.FreshWrapperViewV2,
                ingress: Ingress,
                graph: Graph,
            };

            pub fn initOwned(
                cold_value: ColdProof,
                registry: registry_mod.RecursiveCircuitRegistryV1,
                campaign_namespace_sha256: [32]u8,
            ) !EvidenceV4 {
                var owned = cold_value;
                var owned_live = true;
                errdefer if (owned_live) owned.deinit();
                try registry.validate();
                const cold_views = try owned.borrowedViews();
                if (std.mem.allEqual(u8, &campaign_namespace_sha256, 0))
                    return error.EthereumIncrementalUniversalEvidenceMismatchV4;
                const allocator = owned.backingAllocator();
                const cold = try allocator.create(ColdProof);
                cold.* = owned;
                owned = undefined;
                owned_live = false;
                errdefer {
                    cold.deinit();
                    allocator.destroy(cold);
                }
                const node_artifact = try buildNodeArtifact(
                    cold,
                    &registry,
                    campaign_namespace_sha256,
                );
                var result = EvidenceV4{
                    .allocator = allocator,
                    .cold = cold,
                    .node_artifact = node_artifact,
                    .registry_value = registry,
                    .cached_capture = cold_views.ingress.capture,
                };
                _ = try result.projectBorrowedViews(cold_views);
                return result;
            }

            pub fn deinit(self: *EvidenceV4) void {
                self.cold.deinit();
                self.allocator.destroy(self.cold);
                self.* = undefined;
            }

            pub fn validateBorrowed(self: *const EvidenceV4) !void {
                _ = try self.borrowedViews();
            }

            /// Every acquisition rechecks the current cold proof and external
            /// sources. Only private synchronous callers can reuse that local
            /// result to assemble the wrapper projection.
            pub fn borrowedViews(self: *const EvidenceV4) !BorrowedViews {
                const cold_views = try self.cold.borrowedViews();
                return self.projectBorrowedViews(cold_views);
            }

            fn projectBorrowedViews(
                self: *const EvidenceV4,
                cold_views: ColdProof.BorrowedViews,
            ) !BorrowedViews {
                try self.registry_value.validate();
                try self.cold.validateCaptureAlias(self.cached_capture);
                try self.node_artifact.validate();
                try self.registry_value.admitV2(
                    &self.node_artifact,
                    self.cold.geometryForPaddingTarget(),
                );
                const expected = try buildNodeArtifact(
                    self.cold,
                    &self.registry_value,
                    self.node_artifact.campaign_namespace_sha256,
                );
                if (!std.meta.eql(expected, self.node_artifact)) {
                    return error.EthereumIncrementalUniversalEvidenceMismatchV4;
                }
                var ingress = cold_views.ingress;
                if (!std.meta.eql(ingress.node_public.*, self.node_artifact.node_public))
                    return error.EthereumIncrementalUniversalEvidenceMismatchV4;
                ingress.node_public = &self.node_artifact.node_public;
                try ingress.validate();
                const wrapper = common_authority.FreshWrapperViewV2{
                    .artifact = &self.node_artifact,
                    .geometry = ingress.geometry,
                    .capture = self.cached_capture,
                };
                try wrapper.validateAgainst(&self.registry_value);
                return .{ .wrapper = wrapper, .ingress = ingress, .graph = cold_views.graph };
            }

            pub fn validateFresh(
                self: *const EvidenceV4,
                registry: *const registry_mod.RecursiveCircuitRegistryV1,
            ) !void {
                try self.validateBorrowed();
                if (!std.meta.eql(registry.*, self.registry_value))
                    return error.EthereumIncrementalUniversalEvidenceMismatchV4;
            }

            pub fn validateColdGeometry(self: *const EvidenceV4) !void {
                try self.validateBorrowed();
            }

            pub fn geometryForPaddingTarget(
                self: *const EvidenceV4,
            ) *const registry_mod.AuthenticatedGeometryV1 {
                return self.cold.geometryForPaddingTarget();
            }

            pub fn artifact(
                self: *const EvidenceV4,
            ) *const artifact_mod.RecursiveNodeArtifactV2 {
                return &self.node_artifact;
            }

            pub fn geometry(
                self: *const EvidenceV4,
            ) *const registry_mod.AuthenticatedGeometryV1 {
                return self.cold.geometryForPaddingTarget();
            }

            pub fn proofCapture(
                self: *const EvidenceV4,
            ) *const common_authority.ProofCapture {
                return self.cached_capture;
            }

            pub fn wrapperView(
                self: *const EvidenceV4,
            ) !common_authority.FreshWrapperViewV2 {
                return (try self.borrowedViews()).wrapper;
            }

            pub fn ingressView(self: *const EvidenceV4) !IngressView {
                return (try self.borrowedViews()).ingress;
            }

            pub fn foldGraphView(self: *const EvidenceV4) !GraphView {
                return (try self.borrowedViews()).graph;
            }
        };

        pub const ColdCompositionCaptureV4 =
            capture_view.ColdCompositionCaptureV4(EvidenceV4);
        pub const FreshAdmissionV4 =
            common_authority.OwnedFreshWrapperAdmissionV2(EvidenceV4);
    };
}

fn buildNodeArtifact(
    cold: anytype,
    registry: *const registry_mod.RecursiveCircuitRegistryV1,
    campaign_namespace_sha256: [32]u8,
) !artifact_mod.RecursiveNodeArtifactV2 {
    // Both callers just validated cold and registry at their acceptance
    // boundary. This private projection only reads admitted metadata.
    const geometry = cold.geometryForPaddingTarget();
    const entry = try registry.entry(ROLE);
    const expected_entry = try registry_mod.RegistryEntryV1.fromGeometry(
        geometry,
    );
    if (!std.meta.eql(entry.*, expected_entry))
        return error.CircuitNotRegistered;
    const source = stage101ArtifactRef(cold.materializedOwner());
    try source.validate();
    const result = try artifact_mod.RecursiveNodeArtifactV2.seal(.{
        .stage_kind = .leaf_wrapper,
        .node_kind = .real,
        .child_count = 1,
        .coordinate = cold.materializedOwner().base.input.coordinate,
        .node_public = cold.nodePublic().*,
        .campaign_namespace_sha256 = campaign_namespace_sha256,
        .circuit_identity_sha256 = entry.circuit_identity_sha256,
        .program_identity_sha256 = entry.program_identity_sha256,
        .profile_identity_sha256 = entry.profile_identity_sha256,
        .pcs_identity_sha256 = entry.pcs_identity_sha256,
        .padding_layout_identity_sha256 = entry.padding_layout_identity_sha256,
        .registry_identity_sha256 = registry.identity_sha256,
        .node_public_abi_sha256 = geometry.output_abi.node_public_abi_sha256,
        .proof_shape_identity_sha256 = geometry.proof_shape.identity_sha256,
        .ordered_children = .{ source, artifact_mod.ArtifactRefV1.zero() },
        .proof_ref = try cold.proofArtifactRef(),
        .preprocessed_root = geometry.preprocessed_root,
        .semantic_inputs_identity_sha256 = undefined,
        .field_public_transport_sha256 = undefined,
        .content_identity_sha256 = undefined,
    });
    try registry.admitV2(&result, geometry);
    return result;
}

fn stage101ArtifactRef(materialized: anytype) artifact_mod.ArtifactRefV1 {
    const source = &materialized.base.input;
    return .{
        .kind = SOURCE_PROOF_ARTIFACT_KIND,
        .format_version = artifact_v1.ARTIFACT_REF_FORMAT_VERSION,
        .schema_version = SOURCE_PROOF_ARTIFACT_SCHEMA_VERSION,
        .byte_count = source.artifact_byte_count,
        .sha256 = source.artifact_sha256,
    };
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        @intFromEnum(ROLE) != 0 or SOURCE_PROOF_ARTIFACT_KIND != 8 or
        SOURCE_PROOF_ARTIFACT_SCHEMA_VERSION != 1 or
        OUTPUT_ARTIFACT_KIND != 10 or OUTPUT_ARTIFACT_SCHEMA_VERSION != 2 or
        PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("role-0 universal evidence V4 drifted");
    }
}
