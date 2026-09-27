//! Standalone parent STARK verification from an independently admitted key,
//! expected canonical root statement, claims, and proof bytes only.
const std = @import("std");
const core = @import("stwo_core");
const recursion = struct {
    const poseidon2_channel = @import("poseidon2_channel.zig");
    const span_continuation_v1 = @import("span_continuation_v1.zig");
    const verifier_tree = @import("verifier_tree.zig");
    const protocol = @import("protocol.zig");
};
const postcard = @import("interop_postcard");
const transcript = @import("detached_parent_protocol_v1.zig");
const components = @import("detached_parent_verifier_components_v1.zig");
const manifest_mod = components.manifest_mod;
const Hasher = recursion.poseidon2_channel.MerkleHasher;
const Proof = core.proof.StarkProof(Hasher);
pub const ProofCapture = core.pcs.verifier.VerifiedProofCapture(Hasher);
pub const KeyV1 = transcript.KeyV1;
pub const ClaimsV1 = transcript.ClaimsV1;
pub const ExpectedV1 = transcript.ExpectedV1;
pub const MAX_PROOF_BYTES = @import("artifact_limits.zig").MAX_CANONICAL_PROOF_BYTES;

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
    return @import("detached_proof_preflight.zig").shape(allocator, admitted, key.pcs_config, MAX_PROOF_BYTES);
}

pub fn verify(allocator: std.mem.Allocator, key: *const KeyV1, expected: *const ExpectedV1, claims: ClaimsV1, proof_bytes: []const u8) !recursion.poseidon2_channel.Digest {
    var native_channel = recursion.poseidon2_channel.Channel{};
    return (try verifyWithChannel(recursion.poseidon2_channel.MerkleChannel, allocator, key, expected, claims, proof_bytes, &native_channel, null)).terminal;
}

pub const RecordingResultV1 = struct { terminal: recursion.poseidon2_channel.Digest, relations: components.Relations };

/// Shared verification for native and recording channels. Recording custody
/// and freshness belong to the caller; proof admission is identical here.
pub fn verifyWithChannel(comptime MerkleChannel: type, allocator: std.mem.Allocator, key: *const KeyV1, expected: *const ExpectedV1, claims: ClaimsV1, proof_bytes: []const u8, channel: anytype, capture: ?*ProofCapture) !RecordingResultV1 {
    try key.validate();
    try recursion.span_continuation_v1.validate(expected, key.publication_mode);
    _ = try claims.vector(&key.manifest);
    if (proof_bytes.len == 0 or proof_bytes.len > MAX_PROOF_BYTES)
        return error.SegmentDetachedProofSizeMismatch;
    try postcard.proof_preflight.validate(proof_bytes, try proofPreflightShape(allocator, key));
    var stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(Hasher, allocator, stream.reader());
    var proof_owned = true;
    defer if (proof_owned) proof.deinit(allocator);
    if (stream.pos != proof_bytes.len) return error.SegmentDetachedProofTrailingBytes;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, key.pcs_config))
        return error.SegmentDetachedProofConfigMismatch;
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != manifest_mod.TREE_COUNT + 1 or !std.meta.eql(commitments[0], key.preprocessed_root))
        return error.SegmentDetachedPreprocessedCommitmentMismatch;
    const Scheme = core.pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);
    var scheme = try Scheme.init(allocator, key.pcs_config);
    defer scheme.deinit(allocator);
    for (0..2) |tree| try recursion.verifier_tree.commitVerifierTreeForManifest(manifest_mod, allocator, &scheme, &key.manifest, tree, commitments[tree], channel);
    try transcript.mixAdmission(channel, key, expected);
    try transcript.mixInteractionPow(channel, key, claims.interaction_pow);
    const relations = try components.Relations.draw(allocator, channel);
    try transcript.mixClaimsAndBoundary(channel, key, expected, claims, &relations);
    try recursion.verifier_tree.commitVerifierTreeForManifest(manifest_mod, allocator, &scheme, &key.manifest, 2, commitments[2], channel);
    const owned_components = try components.OwnedComponentsV1.init(allocator, &key.manifest, key.parameters, &relations, claims);
    defer owned_components.deinit();
    const moved = recursion.verifier_tree.moveOwnedForVerifier(Proof, &proof, &proof_owned);
    if (capture) |output|
        try core.verifier.verifyWithProofCapture(Hasher, MerkleChannel, allocator, try owned_components.verifierComponents(), channel, &scheme, moved, output)
    else
        try core.verifier.verify(Hasher, MerkleChannel, allocator, try owned_components.verifierComponents(), channel, &scheme, moved);
    const draws = channel.drawCount();
    return .{ .terminal = recursion.protocol.transcriptId(channel.digestWords(), draws), .relations = relations };
}
