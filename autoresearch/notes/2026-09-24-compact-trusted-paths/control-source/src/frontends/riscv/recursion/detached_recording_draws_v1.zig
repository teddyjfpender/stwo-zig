//! Shared mapping from recorded field draws to native verifier capture values.
//! Leaf and recursive-parent profiles use the same relation/PCS/FRI draw ABI.
const recursion = struct {
    const recording_poseidon_channel_v4 = @import("recording_poseidon_channel_v4.zig");
};
const air = struct {
    const universal_challenges = @import("air/universal_challenges.zig");
};
const std = @import("std");
const core = @import("stwo_core");
const recording = recursion.recording_poseidon_channel_v4;
const universal = air.universal_challenges;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

/// Independently map retained draw operations to the verifier-minted fields.
/// This checks ownership associations, not a second description of mix order.
pub fn validate(execution: *const recording.ExecutionV4, capture: anytype, relations: *const universal.UniversalRelations, query_count: usize) !void {
    if (capture.queries.raw.len != query_count) return error.DetachedChildQueryMismatch;
    const query_log = try @import("capture_query_geometry_v1.zig").queryLogSizeFromCapture(capture);
    if (query_log >= 32) return error.DetachedChildQueryMismatch;
    const query_mask = (@as(u32, 1) << @intCast(query_log)) - 1;
    var draw_at: usize = 0;
    var query_at: usize = 0;
    for (execution.operations) |operation| {
        if (operation.effect != .draw) continue;
        if (operation.hash_count != 1) return error.DetachedChildDrawMismatch;
        const frame = execution.hash_frames[operation.first_hash_id];
        if (frame.purpose != .draw) return error.DetachedChildDrawMismatch;
        const words = frame.output[0..recording.RATE].*;
        if (draw_at < universal.RELATION_COUNT) {
            const element = relations.elements[draw_at];
            try same(secure(words[0..4].*), element.z);
            try same(secure(words[4..8].*), element.alpha);
        } else switch (draw_at - universal.RELATION_COUNT) {
            0 => try same(secure(words[0..4].*), capture.composition_randomness),
            1 => try same(secure(words[0..4].*), capture.oods_seed),
            2 => try same(secure(words[0..4].*), capture.deep_randomness),
            else => |suffix_at| {
                const fri_at = suffix_at - 3;
                if (fri_at < capture.fri.layers.len) {
                    try same(secure(words[0..4].*), capture.fri.layers[fri_at].folding_alpha);
                } else {
                    if (query_at >= query_count) return error.DetachedChildDrawMismatch;
                    for (words[0..@min(recording.RATE, query_count - query_at)]) |word| {
                        if (capture.queries.raw[query_at] != @as(usize, word.toU32() & query_mask)) return error.DetachedChildQueryMismatch;
                        query_at += 1;
                    }
                }
            },
        }
        draw_at += 1;
    }
    const query_draws = std.math.divCeil(usize, query_count, recording.RATE) catch unreachable;
    if (query_at != query_count or draw_at != universal.RELATION_COUNT + 3 + capture.fri.layers.len + query_draws) return error.DetachedChildDrawMismatch;
}

fn secure(words: [4]M31) QM31 {
    return QM31.fromU32Unchecked(words[0].toU32(), words[1].toU32(), words[2].toU32(), words[3].toU32());
}
fn same(actual: QM31, expected_value: QM31) !void {
    if (!actual.eql(expected_value)) return error.DetachedChildDrawMismatch;
}
