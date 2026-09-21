//! Cheap process-local evidence closure for a cold canonical-empty proof.
//!
//! Every durable field is checked against the verifier-owned cold result and
//! registry, while the expensive q193 replay and composition rerecord remain
//! exactly once per cold boundary in the owning proof module.

const std = @import("std");

const input_mod =
    @import("recursive_common_canonical_empty_wrapper_input_v1.zig");
const artifact_mod = @import("recursive_node_artifact_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

pub fn buildNodeArtifact(
    cold: anytype,
    registry: *const registry_mod.RecursiveCircuitRegistryV1,
    campaign_namespace_sha256: [32]u8,
) !artifact_mod.RecursiveNodeArtifactV2 {
    try cold.validateToken();
    try registry.validate();
    if (std.mem.allEqual(u8, &campaign_namespace_sha256, 0))
        return error.CanonicalEmptyUniversalEvidenceMismatch;
    const entry = try registry.entry(.canonical_empty_field_v2);
    const expected_entry = try registry_mod.RegistryEntryV1.fromGeometry(
        &cold.geometry_value,
    );
    if (!std.meta.eql(entry.*, expected_entry))
        return error.CircuitNotRegistered;
    const source = try input_mod.ColdInputV1.open(&cold.source_bytes);
    const result = try artifact_mod.RecursiveNodeArtifactV2.seal(.{
        .stage_kind = .leaf_wrapper,
        .node_kind = .empty,
        .child_count = 1,
        .coordinate = try source.coordinate(),
        .node_public = cold.node_public,
        .campaign_namespace_sha256 = campaign_namespace_sha256,
        .circuit_identity_sha256 = entry.circuit_identity_sha256,
        .program_identity_sha256 = entry.program_identity_sha256,
        .profile_identity_sha256 = entry.profile_identity_sha256,
        .pcs_identity_sha256 = entry.pcs_identity_sha256,
        .padding_layout_identity_sha256 = entry.padding_layout_identity_sha256,
        .registry_identity_sha256 = registry.identity_sha256,
        .node_public_abi_sha256 = cold.geometry_value.output_abi.node_public_abi_sha256,
        .proof_shape_identity_sha256 = cold.geometry_value.proof_shape.identity_sha256,
        .ordered_children = .{
            try source.sourceRef(),
            artifact_mod.ArtifactRefV1.zero(),
        },
        .proof_ref = try cold.proofArtifactRef(),
        .preprocessed_root = cold.geometry_value.preprocessed_root,
        .semantic_inputs_identity_sha256 = undefined,
        .field_public_transport_sha256 = undefined,
        .content_identity_sha256 = undefined,
    });
    try registry.admitV2(&result, &cold.geometry_value);
    return result;
}

pub fn validateFresh(
    cold: anytype,
    node_artifact: *const artifact_mod.RecursiveNodeArtifactV2,
    cached_graph: anytype,
    registry: *const registry_mod.RecursiveCircuitRegistryV1,
) !void {
    try cold.validateToken();
    try node_artifact.validate();
    try validateCachedGraph(cold, cached_graph);
    const source = try input_mod.ColdInputV1.open(&cold.source_bytes);
    if (node_artifact.stage_kind != .leaf_wrapper or
        node_artifact.node_kind != .empty or
        node_artifact.child_count != 1 or
        !std.meta.eql(node_artifact.coordinate, try source.coordinate()) or
        !std.meta.eql(node_artifact.node_public, cold.node_public) or
        !std.meta.eql(
            node_artifact.ordered_children[0],
            try source.sourceRef(),
        ) or !std.meta.eql(
        node_artifact.ordered_children[1],
        artifact_mod.ArtifactRefV1.zero(),
    ) or !std.meta.eql(
        node_artifact.preprocessed_root,
        cold.geometry_value.preprocessed_root,
    )) return error.CanonicalEmptyUniversalEvidenceMismatch;
    try registry.admitV2(node_artifact, &cold.geometry_value);
}

pub fn validateCachedGraph(cold: anytype, cached_graph: anytype) !void {
    const live_graph = try cold.foldGraphView();
    if (!std.meta.eql(cached_graph, live_graph))
        return error.CanonicalEmptyUniversalEvidenceMismatch;
}

/// Rebinds a cold ingress to the registry-admitted artifact only after the
/// independently retained NodePublic values agree exactly.
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
