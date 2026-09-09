//! SegmentV2 STARK verification using only fixed admission, expected public
//! input and canonical proof data. No native capture or prepared leaf enters
//! this module. The key must be admitted independently by the caller.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const recursion = frontend.recursion;
const postcard = @import("interop_postcard");
const transcript = @import("recursive_segment_v2_detached_transcript.zig");
const components = @import("recursive_segment_v2_verifier_components.zig");
const support = @import("recursive_binary_outer_support.zig");
const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
const recording = recursion.recording_poseidon_channel_v4;
pub const KeyV1 = transcript.KeyV1;
pub const ClaimsV1 = components.ClaimsV1;
pub const ProofCapture = core.pcs.verifier.VerifiedProofCapture(recursion.engine.Hasher);
pub const MAX_PROOF_BYTES = @import("recursive_temporal_secure_parent_artifact_v1.zig").MAX_CANONICAL_PROOF_BYTES;

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
    return @import("recursive_detached_proof_preflight.zig").shape(allocator, admitted, key.pcs_config, MAX_PROOF_BYTES);
}

pub fn verify(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    expected: *const frontend.air.public_data_v2.PublicDataV2,
    claims: ClaimsV1,
    proof_bytes: []const u8,
) !recursion.poseidon2_channel.Digest {
    var channel = recursion.poseidon2_channel.Channel{};
    return (try verifyImpl(recursion.engine.MerkleChannel, allocator, key, expected, claims, proof_bytes, &channel, null)).terminal;
}

/// Retain authenticated openings only for the next recursive producer. This
/// output is witness data and does not admit that producer's parent circuit.
pub fn verifyWithCapture(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    expected: *const frontend.air.public_data_v2.PublicDataV2,
    claims: ClaimsV1,
    proof_bytes: []const u8,
    capture: *ProofCapture,
) !recursion.poseidon2_channel.Digest {
    var channel = recursion.poseidon2_channel.Channel{};
    return (try verifyImpl(recursion.engine.MerkleChannel, allocator, key, expected, claims, proof_bytes, &channel, capture)).terminal;
}

pub const RecordingResultV1 = struct {
    terminal: recursion.poseidon2_channel.Digest,
    relations: components.Relations,
};

/// Run the same verifier with a fresh recording channel. The caller must finish
/// the recording to check deferred channel errors and owns a successful capture.
/// No transcript framing or PCS replay is maintained separately here.
pub fn verifyWithCaptureRecording(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    expected: *const frontend.air.public_data_v2.PublicDataV2,
    claims: ClaimsV1,
    proof_bytes: []const u8,
    channel: *recording.Channel,
    capture: *ProofCapture,
) !RecordingResultV1 {
    if (!std.meta.eql(channel.inner, recursion.poseidon2_channel.Channel{}) or
        channel.first_fault != null or channel.pending_pow != null or
        channel.calls.items.len != 0 or channel.frames.items.len != 0 or
        channel.checks.items.len != 0 or channel.words.items.len != 0 or
        channel.operations.items.len != 0)
        return error.SegmentDetachedRecordingNotFresh;
    return verifyImpl(recording.MerkleChannel, allocator, key, expected, claims, proof_bytes, channel, capture);
}

fn verifyImpl(
    comptime MerkleChannel: type,
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    expected: *const frontend.air.public_data_v2.PublicDataV2,
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
    var proof = try postcard.deserializeProof(recursion.engine.Hasher, allocator, stream.reader());
    var proof_owned = true;
    defer if (proof_owned) proof.deinit(allocator);
    if (stream.pos != proof_bytes.len) return error.SegmentDetachedProofTrailingBytes;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, key.pcs_config))
        return error.SegmentDetachedProofConfigMismatch;
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != manifest_mod.TREE_COUNT + 1 or !std.meta.eql(commitments[0], key.preprocessed_root))
        return error.SegmentDetachedPreprocessedCommitmentMismatch;
    const Scheme = core.pcs.verifier.CommitmentSchemeVerifier(recursion.engine.Hasher, MerkleChannel);
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
    if (capture) |output|
        try core.verifier.verifyWithProofCapture(recursion.engine.Hasher, MerkleChannel, allocator, try owned_components.verifierComponents(), channel, &scheme, moved, output)
    else
        try core.verifier.verify(recursion.engine.Hasher, MerkleChannel, allocator, try owned_components.verifierComponents(), channel, &scheme, moved);
    const draw_count = if (@TypeOf(channel.*) == recording.Channel) channel.inner.n_draws else channel.n_draws;
    return .{ .terminal = recursion.protocol.transcriptId(channel.digestWords(), draw_count), .relations = relations };
}
