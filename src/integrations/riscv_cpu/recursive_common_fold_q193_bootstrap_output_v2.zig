//! Unrouteable kind-10/schema-2 output for the q193 common-fold bootstrap.

const std = @import("std");

const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const node_mod = @import("recursive_node_artifact_v2.zig");
const node_v1 = @import("recursive_node_artifact_v1.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const OUTPUT_REGISTRY_DOMAIN =
    "stwo-zig/recursive-common-fold-q193-bootstrap-output/v2\x00";

pub fn buildNodeArtifact(
    live: anytype,
    geometry: *const registry_mod.AuthenticatedGeometryV1,
    proof_bytes: []const u8,
) !node_mod.RecursiveNodeArtifactV2 {
    try live.validate();
    try geometry.validate();
    if (geometry.role != .common_fold_field_v2 or proof_bytes.len == 0)
        return error.BootstrapCommonOutputMismatch;
    var proof_sha: [32]u8 = undefined;
    Sha256.hash(proof_bytes, &proof_sha, .{});
    const proof_ref = node_mod.ArtifactRefV1{
        .kind = common_authority.PROOF_ARTIFACT_KIND,
        .format_version = node_v1.ARTIFACT_REF_FORMAT_VERSION,
        .schema_version = 1,
        .byte_count = @intCast(proof_bytes.len),
        .sha256 = proof_sha,
    };
    try proof_ref.validate();
    const stage_kind: node_mod.StageKindV1 =
        if (live.input.parent_coordinate.height == node_v1.ROOT_HEIGHT)
            .root
        else
            .fold;
    const result = try node_mod.RecursiveNodeArtifactV2.seal(.{
        .stage_kind = stage_kind,
        .node_kind = live.public_schedule.parent.node_kind,
        .child_count = 2,
        .coordinate = live.input.parent_coordinate,
        .node_public = live.public_schedule.parent,
        .campaign_namespace_sha256 = live.input.campaign_namespace_sha256,
        .circuit_identity_sha256 = geometry.circuit_identity_sha256,
        .program_identity_sha256 = geometry.program_identity_sha256,
        .profile_identity_sha256 = geometry.profile_identity_sha256,
        .pcs_identity_sha256 = geometry.pcs.identity_sha256,
        .padding_layout_identity_sha256 = geometry.padding_layout_identity_sha256,
        .registry_identity_sha256 = outputRegistryIdentity(live, geometry),
        .node_public_abi_sha256 = geometry.output_abi.node_public_abi_sha256,
        .proof_shape_identity_sha256 = geometry.proof_shape.identity_sha256,
        .ordered_children = live.input.child_refs,
        .proof_ref = proof_ref,
        .preprocessed_root = geometry.preprocessed_root,
        .semantic_inputs_identity_sha256 = undefined,
        .field_public_transport_sha256 = undefined,
        .content_identity_sha256 = undefined,
    });
    try validateUnrouteable(live, &result);
    return result;
}

pub fn validateUnrouteable(
    live: anytype,
    node: *const node_mod.RecursiveNodeArtifactV2,
) !void {
    try node.validate();
    if (std.mem.eql(
        u8,
        &node.registry_identity_sha256,
        &live.registry_value.identity_sha256,
    ) or node.stage_kind == .leaf_wrapper or node.child_count != 2) {
        return error.BootstrapCommonOutputMismatch;
    }
}

fn outputRegistryIdentity(
    live: anytype,
    geometry: *const registry_mod.AuthenticatedGeometryV1,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(OUTPUT_REGISTRY_DOMAIN);
    hash.update(&live.identity_sha256);
    hash.update(&geometry.authority_identity_sha256);
    hash.update(&geometry.proof_shape.identity_sha256);
    return hash.finalResult();
}
