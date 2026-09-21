//! Explicit campaign-aware registry/store/worker validation boundary.
//!
//! This facade prevents new worker routes from accidentally falling back to
//! legacy topology validation. It owns only copied transport authorities; a
//! role-specific verifier-owned proof lease remains mandatory and cannot be
//! represented by either admission below.

const std = @import("std");

const artifact_mod = @import("recursive_campaign_node_artifact_v2.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

const STORE_VIEW_DOMAIN =
    "stwo-zig/recursive-campaign-node-store-view/v2\x00";
const REGISTRY_WORKER_DOMAIN =
    "stwo-zig/recursive-campaign-node-registry-worker/v2\x00";

pub const Error = artifact_mod.Error || error{
    CampaignNodePipelineMismatch,
};

/// Cold transport/store projection. Every new process repeats canonical
/// decode and hash closure; this receipt is evidence, never proof freshness.
pub const CampaignStoreViewV2 = struct {
    shape: shape_mod.CampaignShapeAuthorityV2,
    artifact: artifact_mod.Artifact,
    semantic: artifact_mod.CampaignSemanticInputsV2,
    artifact_ref: artifact_mod.ArtifactRef,
    identity_sha256: [32]u8,

    pub fn coldOpen(
        shape: *const shape_mod.CampaignShapeAuthorityV2,
        bytes: []const u8,
    ) Error!CampaignStoreViewV2 {
        const artifact = try artifact_mod.coldDecodeForStore(shape, bytes);
        const semantic = try artifact_mod.semanticInputsForStore(
            shape,
            &artifact,
        );
        const ref = try artifact_mod.artifactRef(shape, &artifact);
        var result = CampaignStoreViewV2{
            .shape = shape.*,
            .artifact = artifact,
            .semantic = semantic,
            .artifact_ref = ref,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = storeViewIdentity(&result);
        try result.validate(bytes);
        return result;
    }

    pub fn validate(
        self: *const CampaignStoreViewV2,
        bytes: []const u8,
    ) Error!void {
        try self.shape.validate();
        try artifact_mod.validate(&self.shape, &self.artifact);
        const canonical = try artifact_mod.encodeCanonical(
            &self.shape,
            &self.artifact,
        );
        const semantic = try artifact_mod.semanticInputsForStore(
            &self.shape,
            &self.artifact,
        );
        const ref = try artifact_mod.artifactRef(
            &self.shape,
            &self.artifact,
        );
        if (!std.mem.eql(u8, bytes, &canonical) or
            !std.meta.eql(self.semantic, semantic) or
            !std.meta.eql(self.artifact_ref, ref) or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &storeViewIdentity(self),
            )) return error.CampaignNodePipelineMismatch;
    }
};

/// Registry/store/worker output closure. It is process-local and still has no
/// verifier capture, transcript, query words, or graph capability.
pub const RegistryWorkerAdmissionV2 = struct {
    store_view_identity_sha256: [32]u8,
    campaign_shape_identity_sha256: [32]u8,
    artifact_ref: artifact_mod.ArtifactRef,
    semantic_identity_sha256: [32]u8,
    registry_identity_sha256: [32]u8,
    geometry_authority_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn mint(
        view: *const CampaignStoreViewV2,
        registry: *const registry_mod.RecursiveCircuitRegistryV1,
        geometry: *const registry_mod.AuthenticatedGeometryV1,
    ) Error!RegistryWorkerAdmissionV2 {
        try artifact_mod.admitRegistry(
            registry,
            &view.shape,
            &view.artifact,
            geometry,
        );
        var result = RegistryWorkerAdmissionV2{
            .store_view_identity_sha256 = view.identity_sha256,
            .campaign_shape_identity_sha256 = view.shape.identity_sha256,
            .artifact_ref = view.artifact_ref,
            .semantic_identity_sha256 = view.semantic.identity_sha256,
            .registry_identity_sha256 = registry.identity_sha256,
            .geometry_authority_identity_sha256 = geometry.authority_identity_sha256,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = registryWorkerIdentity(&result);
        try result.validate(view, registry, geometry);
        return result;
    }

    pub fn validate(
        self: *const RegistryWorkerAdmissionV2,
        view: *const CampaignStoreViewV2,
        registry: *const registry_mod.RecursiveCircuitRegistryV1,
        geometry: *const registry_mod.AuthenticatedGeometryV1,
    ) Error!void {
        try artifact_mod.validateWorkerOutput(
            &view.shape,
            &view.artifact,
            &view.semantic,
        );
        try artifact_mod.admitRegistry(
            registry,
            &view.shape,
            &view.artifact,
            geometry,
        );
        if (!std.mem.eql(
            u8,
            &self.store_view_identity_sha256,
            &view.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.campaign_shape_identity_sha256,
            &view.shape.identity_sha256,
        ) or !std.meta.eql(self.artifact_ref, view.artifact_ref) or
            !std.mem.eql(
                u8,
                &self.semantic_identity_sha256,
                &view.semantic.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &self.registry_identity_sha256,
            &registry.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.geometry_authority_identity_sha256,
            &geometry.authority_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &registryWorkerIdentity(self),
        )) return error.CampaignNodePipelineMismatch;
    }
};

fn storeViewIdentity(value: *const CampaignStoreViewV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(STORE_VIEW_DOMAIN);
    hash.update(&value.shape.identity_sha256);
    hash.update(&value.artifact_ref.sha256);
    hash.update(&value.semantic.identity_sha256);
    return hash.finalResult();
}

fn registryWorkerIdentity(value: *const RegistryWorkerAdmissionV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(REGISTRY_WORKER_DOMAIN);
    hash.update(&value.store_view_identity_sha256);
    hash.update(&value.campaign_shape_identity_sha256);
    hash.update(&value.artifact_ref.sha256);
    hash.update(&value.semantic_identity_sha256);
    hash.update(&value.registry_identity_sha256);
    hash.update(&value.geometry_authority_identity_sha256);
    return hash.finalResult();
}

comptime {
    if (PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY)
        @compileError("campaign registry/store/worker facade drifted");
}
