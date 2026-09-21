//! Immutable projections shared by verified segment and parent capture owners.
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Digest = @import("poseidon2_channel.zig").Digest;
const recording = @import("recording_poseidon_channel_v4.zig");

/// All slices are const, including nested capture views returned individually.
/// They remain valid until the owner is destroyed.
pub const CaptureViewV1 = struct {
    commitments: []const Digest,
    sampled_values: []const QM31,
    queried_values: []const M31,
    deep_answers: []const QM31,
    raw_queries: []const usize,
    unique_queries: []const usize,
    last_layer_coefficients: []const QM31,
    proof_of_work: u64,
    composition_randomness: QM31,
    oods_seed: QM31,
    deep_randomness: QM31,
    trace_count: usize,
    fri_layer_count: usize,
};
pub const FriLayerViewV1 = struct {
    commitment: Digest,
    folding_alpha: QM31,
    fold_step: u32,
    fold_width: u32,
    path_depth: u32,
    query_count: usize,
    positions: []const usize,
    values: []const QM31,
    siblings: []const Digest,
};
pub const TracePathViewV1 = struct { positions: []const usize, path_depth: u32, siblings: []const Digest };
pub const RecordingViewV1 = struct {
    trace: recording.TranscriptTrace,
    operations: []const recording.OperationV4,
    final_digest: Digest,
    final_draw_count: u32,
    identity_sha256: [32]u8,
};

pub const Family = enum { segment, parent };
