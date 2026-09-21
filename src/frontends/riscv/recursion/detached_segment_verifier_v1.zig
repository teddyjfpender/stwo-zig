//! SegmentV2 STARK verification using only fixed admission, expected public
//! input and canonical proof data. No native capture or prepared leaf enters
//! this module. The key must be admitted independently by the caller.
const std = @import("std");
const core = @import("stwo_core");
const recursion = struct {
    const poseidon2_channel = @import("poseidon2_channel.zig");
    const protocol = @import("protocol.zig");
    const verifier_tree = @import("verifier_tree.zig");
};
const PublicData = @import("../air/public_data_v2.zig").PublicDataV2;
const postcard = @import("interop_postcard");
const transcript = @import("detached_segment_protocol_v1.zig");
const components = @import("detached_segment_verifier_components_v1.zig");
const manifest_mod = components.manifest_mod;
const Hasher = recursion.poseidon2_channel.MerkleHasher;
const Proof = core.proof.StarkProof(Hasher);
pub const KeyV1 = transcript.KeyV1;
pub const ClaimsV1 = components.ClaimsV1;
pub const ProofCapture = core.pcs.verifier.VerifiedProofCapture(Hasher);
pub const MAX_PROOF_BYTES = @import("artifact_limits.zig").MAX_CANONICAL_PROOF_BYTES;

/// Derive decoder allocation bounds only from the admitted canonical AIRs.
/// Preparing these fixed adapters may allocate, but no proof length, claim or
/// opening controls those allocations. The subsequent wire walk allocates none.
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

pub fn verify(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    expected: *const PublicData,
    claims: ClaimsV1,
    proof_bytes: []const u8,
) !recursion.poseidon2_channel.Digest {
    var channel = recursion.poseidon2_channel.Channel{};
    return (try verifyWithChannel(recursion.poseidon2_channel.MerkleChannel, allocator, key, expected, claims, proof_bytes, &channel, null)).terminal;
}

/// Retain authenticated openings only for the next recursive producer. This
/// output is witness data and does not admit that producer's parent circuit.
pub fn verifyWithCapture(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    expected: *const PublicData,
    claims: ClaimsV1,
    proof_bytes: []const u8,
    capture: *ProofCapture,
) !recursion.poseidon2_channel.Digest {
    var channel = recursion.poseidon2_channel.Channel{};
    return (try verifyWithChannel(recursion.poseidon2_channel.MerkleChannel, allocator, key, expected, claims, proof_bytes, &channel, capture)).terminal;
}

pub const RecordingResultV1 = struct {
    terminal: recursion.poseidon2_channel.Digest,
    relations: components.Relations,
};

pub fn verifyWithChannel(
    comptime MerkleChannel: type,
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    expected: *const PublicData,
    claims: ClaimsV1,
    proof_bytes: []const u8,
    channel: anytype,
    capture: ?*ProofCapture,
) !RecordingResultV1 {
    try key.validate();
    _ = try expected.metadata();
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
    const draw_count = channel.drawCount();
    return .{ .terminal = recursion.protocol.transcriptId(channel.digestWords(), draw_count), .relations = relations };
}
