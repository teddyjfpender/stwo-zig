//! Canonical PCS-opening operations appended after the caller's STARK prefix.
//! Payload slices borrow the capture until the transcript witness is prepared.
const std = @import("std");
const core = @import("stwo_core");
const sequence = @import("blake3_transcript_witness.zig");
const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const Channel = core.channel.blake3.Channel;
const Capture = core.pcs.verifier.VerifiedProofCapture(core.vcs_lifted.blake3_merkle.MerkleHasher);
/// Returns owned query storage; free it after consuming the appended operations.
pub fn appendOpening(a: std.mem.Allocator, ops: *std.ArrayList(sequence.Operation), channel: *Channel, capture: *const Capture, config: core.pcs.PcsConfig, lifting_log_size: u32) ![]u32 {
    if (lifting_log_size > 31 or capture.queries.raw.len != config.fri_config.n_queries or capture.fri.layers.len == 0) return error.InvalidBlake3PcsTranscript;
    // Build transactionally: mismatched capture data cannot partially advance
    // the caller's channel or append a partial protocol sequence.
    var state = channel.*;
    var pending: std.ArrayList(sequence.Operation) = .empty;
    defer pending.deinit(a);
    state.mixFelts(capture.sampled_values);
    try pending.append(a, .{ .felts = capture.sampled_values });
    try pending.append(a, try secure(&state, capture.deep_randomness));
    for (capture.fri.layers) |layer| {
        state.mixRoot(layer.commitment);
        try pending.append(a, .{ .root = layer.commitment });
        try pending.append(a, try secure(&state, layer.folding_alpha));
    }
    state.mixFelts(capture.last_layer_coefficients);
    try pending.append(a, .{ .felts = capture.last_layer_coefficients });
    if (!state.verifyPowNonce(config.pow_bits, capture.proof_of_work)) return error.InvalidBlake3PcsTranscript;
    try pending.append(a, .{ .pow = .{ .bits = config.pow_bits, .nonce = capture.proof_of_work } });
    state.mixU64(capture.proof_of_work);
    try pending.append(a, .{ .integer = capture.proof_of_work });
    const raw = try core.queries.drawQueries(&state, a, lifting_log_size, capture.queries.raw.len);
    defer a.free(raw);
    const queries = try a.alloc(u32, raw.len);
    errdefer a.free(queries);
    for (raw, capture.queries.raw, queries) |actual, expected, *value| {
        if (actual != expected) return error.InvalidBlake3PcsTranscript;
        value.* = @intCast(actual);
    }
    try pending.append(a, .{ .queries = .{ .log_domain_size = lifting_log_size, .values = queries } });
    try ops.appendSlice(a, pending.items);
    channel.* = state;
    return queries;
}
fn secure(channel: *Channel, expected: QM31) !sequence.Operation {
    const start = channel.n_draws;
    const actual = channel.drawSecureFelt();
    if (!actual.eql(expected)) return error.InvalidBlake3PcsTranscript;
    var values: [8]M31 = @splat(M31.zero());
    values[0..4].* = expected.toM31Array();
    return .{ .secure = .{ .attempts = std.math.cast(u32, channel.n_draws - start) orelse return error.InvalidBlake3PcsTranscript, .consumption = .one, .values = values } };
}
