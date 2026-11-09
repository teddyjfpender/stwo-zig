//! Compatibility exports and recording adapter for neutral leaf verification.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const recording = frontend.recursion.recording_poseidon_channel_v4;
const owner = frontend.recursion.detached_segment_verifier_v1;
pub const KeyV1 = owner.KeyV1;
pub const ClaimsV1 = owner.ClaimsV1;
pub const ProofCapture = owner.ProofCapture;
pub const MAX_PROOF_BYTES = owner.MAX_PROOF_BYTES;
pub const proofPreflightShape = owner.proofPreflightShape;
pub const verify = owner.verify;
pub const verifyWithCapture = owner.verifyWithCapture;
pub const RecordingResultV1 = owner.RecordingResultV1;

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
    return @import("stwo_riscv_frontend").recursion.detached_recording_verifier_v1.verify(owner, allocator, key, expected, claims, proof_bytes, channel, capture);
}
