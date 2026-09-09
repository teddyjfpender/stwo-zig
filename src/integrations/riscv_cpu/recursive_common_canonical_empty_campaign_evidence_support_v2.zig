//! Campaign-aware evidence closure for one cold role-1 proof.
//!
//! Durable node bytes remain kind-10/schema-2. Topology, source and registry
//! checks use only the runtime campaign shape and its one FinalRemint owner.

const std = @import("std");

const artifact_mod = @import("recursive_node_artifact_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

pub fn buildNodeArtifact(
    cold: anytype,
    final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
) !artifact_mod.RecursiveNodeArtifactV2 {
    try cold.validateToken();
    try cold.validateAgainstFinal(final_remint);
    const registry = try final_remint.registryAuthority();
    const geometry = try final_remint.geometryForRole(
        .canonical_empty_field_v2,
    );
    if (!std.meta.eql(geometry.*, cold.geometry_value))
        return error.CanonicalEmptyUniversalEvidenceMismatch;
    const entry = try registry.entry(.canonical_empty_field_v2);
    const expected_entry = try registry_mod.RegistryEntryV1.fromGeometry(
        geometry,
    );
    if (!std.meta.eql(entry.*, expected_entry))
        return error.CircuitNotRegistered;
    const source_ref = try cold.source_input.source.artifactRef(
        &cold.source_input.shape,
    );
    const result = try campaign_artifact.seal(
        &cold.source_input.shape,
        .{
            .stage_kind = .leaf_wrapper,
            .node_kind = .empty,
            .child_count = 1,
            .coordinate = try cold.source_input.coordinate(),
            .node_public = cold.node_public,
            .campaign_namespace_sha256 = cold.source_input.shape.campaign_namespace_sha256,
            .circuit_identity_sha256 = entry.circuit_identity_sha256,
            .program_identity_sha256 = entry.program_identity_sha256,
            .profile_identity_sha256 = entry.profile_identity_sha256,
            .pcs_identity_sha256 = entry.pcs_identity_sha256,
            .padding_layout_identity_sha256 = entry.padding_layout_identity_sha256,
            .registry_identity_sha256 = registry.identity_sha256,
            .node_public_abi_sha256 = geometry.output_abi.node_public_abi_sha256,
            .proof_shape_identity_sha256 = geometry.proof_shape.identity_sha256,
            .ordered_children = .{
                source_ref,
                artifact_mod.ArtifactRefV1.zero(),
            },
            .proof_ref = try cold.proofArtifactRef(),
            .preprocessed_root = geometry.preprocessed_root,
            .semantic_inputs_identity_sha256 = undefined,
            .field_public_transport_sha256 = undefined,
            .content_identity_sha256 = undefined,
        },
    );
    try campaign_artifact.admitRegistry(
        registry,
        &cold.source_input.shape,
        &result,
        geometry,
    );
    return result;
}

pub fn validateFresh(
    cold: anytype,
    final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
    node_artifact: *const artifact_mod.RecursiveNodeArtifactV2,
    cached_graph: anytype,
) !void {
    try cold.validateToken();
    try cold.validateAgainstFinal(final_remint);
    try validateCachedGraph(cold, cached_graph);
    const registry = try final_remint.registryAuthority();
    const geometry = try final_remint.geometryForRole(
        .canonical_empty_field_v2,
    );
    try campaign_artifact.validate(&cold.source_input.shape, node_artifact);
    const expected = try buildNodeArtifact(cold, final_remint);
    if (!std.meta.eql(node_artifact.*, expected))
        return error.CanonicalEmptyUniversalEvidenceMismatch;
    try campaign_artifact.admitRegistry(
        registry,
        &cold.source_input.shape,
        node_artifact,
        geometry,
    );
}

pub fn validateCachedGraph(cold: anytype, cached_graph: anytype) !void {
    const live_graph = try cold.foldGraphView();
    if (!std.meta.eql(cached_graph, live_graph))
        return error.CanonicalEmptyUniversalEvidenceMismatch;
}

pub fn rebaseIngressToArtifact(
    node_artifact: *const artifact_mod.RecursiveNodeArtifactV2,
    ingress: anytype,
) !@TypeOf(ingress) {
    var result = ingress;
    if (!std.meta.eql(node_artifact.node_public, result.node_public.*))
        return error.CanonicalEmptyUniversalEvidenceMismatch;
    result.node_public = &node_artifact.node_public;
    try result.validate();
    return result;
}
