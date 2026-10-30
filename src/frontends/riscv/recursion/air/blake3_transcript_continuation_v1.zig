//! Verifier-owned state-port join for split transcripts. This is scheduling,
//! not proof authority: original hash/route AIRs enforce the digest equality.
const std = @import("std");
const core = @import("stwo_core");
const T = @import("blake3_transcript_witness.zig");
pub fn requiredUses(source: T.Caller, consumers: []const T.StatePorts) ![8]u32 {
    if (consumers.len == 0 or consumers.len > 4096 or source.circuit >= core.fields.m31.Modulus or @as(u64, source.first_wire) + 8 > core.fields.m31.Modulus) return error.InvalidTranscriptStateJoin;
    var uses: [8]u32 = @splat(0);
    for (consumers) |consumer| {
        if (!std.meta.eql(source, consumer.source)) return error.InvalidTranscriptStateJoin;
        for (&uses, consumer.uses) |*total, count| {
            if (count == 0 or count >= core.fields.m31.Modulus) return error.InvalidTranscriptStateJoin;
            total.* = std.math.add(u32, total.*, count) catch return error.InvalidTranscriptStateJoin;
            if (total.* >= core.fields.m31.Modulus) return error.InvalidTranscriptStateJoin;
        }
    }
    return uses;
}
pub fn requireExact(producer: T.StatePorts, consumers: []const T.StatePorts) !void {
    const expected = try requiredUses(producer.source, consumers);
    if (!std.meta.eql(expected, producer.uses)) return error.InvalidTranscriptStateJoin;
}
