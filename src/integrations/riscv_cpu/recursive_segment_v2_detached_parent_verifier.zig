//! Compatibility exports; parent verification is owned by the neutral frontend.
const owner = @import("stwo_riscv_frontend").recursion.detached_parent_verifier_v1;
pub const ProofCapture = owner.ProofCapture;
pub const KeyV1 = owner.KeyV1;
pub const ClaimsV1 = owner.ClaimsV1;
pub const ExpectedV1 = owner.ExpectedV1;
pub const MAX_PROOF_BYTES = owner.MAX_PROOF_BYTES;
pub const proofPreflightShape = owner.proofPreflightShape;
pub const verify = owner.verify;
pub const RecordingResultV1 = owner.RecordingResultV1;
const std = @import("std");
const recording = @import("stwo_riscv_frontend").recursion.recording_poseidon_channel_v4;

pub fn verifyWithCaptureRecording(allocator: std.mem.Allocator, key: *const KeyV1, expected: *const ExpectedV1, claims: ClaimsV1, proof_bytes: []const u8, channel: *recording.Channel, capture: *ProofCapture) !RecordingResultV1 {
    return @import("stwo_riscv_frontend").recursion.detached_recording_verifier_v1.verify(owner, allocator, key, expected, claims, proof_bytes, channel, capture);
}
