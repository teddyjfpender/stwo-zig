//! Standalone parent STARK verification from an independently admitted key,
//! expected canonical root statement, claims, and proof bytes only.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const postcard = @import("interop_postcard");
const transcript = @import("recursive_segment_v2_detached_parent_protocol.zig");
const components = @import("recursive_segment_v2_detached_parent_cohort.zig");
const support = @import("recursive_binary_outer_support.zig");
const manifest_mod = components.manifest_mod;
pub const KeyV1 = transcript.KeyV1;
pub const ClaimsV1 = transcript.ClaimsV1;
pub const ExpectedV1 = transcript.ExpectedV1;
pub const MAX_PROOF_BYTES = @import("recursive_temporal_secure_parent_artifact_v1.zig").MAX_CANONICAL_PROOF_BYTES;

pub fn proofPreflightShape(allocator: std.mem.Allocator, key: *const KeyV1) !postcard.proof_preflight.Shape {
    try key.validate();
    const dummy_relations = components.Relations.dummy();
    const dummy_claims = ClaimsV1{ .values = @splat(core.fields.qm31.QM31.zero()), .poseidon_partials = @splat(core.fields.qm31.QM31.zero()) };
    const owner = try components.OwnedComponentsV1.init(allocator, &key.manifest, key.parameters, &dummy_relations, dummy_claims);
    defer owner.deinit();
    const admitted = core.air.components.Components{
        .components = try owner.verifierComponents(),
        .n_preprocessed_columns = key.manifest.total_preprocessed_columns,
    };
    return @import("recursive_detached_proof_preflight.zig").shape(allocator, admitted, key.pcs_config, MAX_PROOF_BYTES);
}

pub fn verify(allocator: std.mem.Allocator, key: *const KeyV1, expected: *const ExpectedV1, claims: ClaimsV1, proof_bytes: []const u8) !recursion.poseidon2_channel.Digest {
    var native_channel = recursion.poseidon2_channel.Channel{};
    const channel = &native_channel;
    try key.validate();
    try transcript.validateExpected(expected);
    _ = try claims.vector(&key.manifest);
    if (proof_bytes.len == 0 or proof_bytes.len > MAX_PROOF_BYTES)
        return error.SegmentDetachedProofSizeMismatch;
    try postcard.proof_preflight.validate(proof_bytes, try proofPreflightShape(allocator, key));
    var stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(recursion.engine.Hasher, allocator, stream.reader());
    var proof_owned = true;
    defer if (proof_owned) proof.deinit(allocator);
    if (stream.pos != proof_bytes.len) return error.SegmentDetachedProofTrailingBytes;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, key.pcs_config))
        return error.SegmentDetachedProofConfigMismatch;
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != manifest_mod.TREE_COUNT + 1 or !std.meta.eql(commitments[0], key.preprocessed_root))
        return error.SegmentDetachedPreprocessedCommitmentMismatch;
    const Scheme = core.pcs.verifier.CommitmentSchemeVerifier(recursion.engine.Hasher, recursion.engine.MerkleChannel);
    var scheme = try Scheme.init(allocator, key.pcs_config);
    defer scheme.deinit(allocator);
    for (0..2) |tree| try support.commitVerifierTreeForManifest(manifest_mod, allocator, &scheme, &key.manifest, tree, commitments[tree], channel);
    try transcript.mixAdmission(channel, key, expected);
    const relations = try components.Relations.draw(allocator, channel);
    try transcript.mixClaimsAndBoundary(channel, key, expected, claims, &relations);
    try support.commitVerifierTreeForManifest(manifest_mod, allocator, &scheme, &key.manifest, 2, commitments[2], channel);
    const owned_components = try components.OwnedComponentsV1.init(allocator, &key.manifest, key.parameters, &relations, claims);
    defer owned_components.deinit();
    const moved = support.moveOwnedForVerifier(recursion.engine.Proof, &proof, &proof_owned);
    try core.verifier.verify(recursion.engine.Hasher, recursion.engine.MerkleChannel, allocator, try owned_components.verifierComponents(), channel, &scheme, moved);
    return recursion.protocol.transcriptId(channel.digestWords(), channel.n_draws);
}
