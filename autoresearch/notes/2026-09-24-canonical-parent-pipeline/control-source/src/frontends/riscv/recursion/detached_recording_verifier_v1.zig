//! Recording-channel adapter around the canonical standalone verifier flow.
const std = @import("std");
const recording = @import("recording_poseidon_channel_v4.zig");
pub fn verify(comptime Verifier: type, allocator: std.mem.Allocator, key: *const Verifier.KeyV1, expected: anytype, claims: Verifier.ClaimsV1, proof_bytes: []const u8, channel: *recording.Channel, capture: *Verifier.ProofCapture) !Verifier.RecordingResultV1 {
    if (!channel.isFresh()) return error.SegmentDetachedRecordingNotFresh;
    return Verifier.verifyWithChannel(recording.MerkleChannel, allocator, key, expected, claims, proof_bytes, channel, capture);
}
