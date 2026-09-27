//! V2 exact-count roster semantics over independently proved dyadic subtrees.
//! A digest binds the ordered proof keys and statements; proof bytes must still
//! be verified individually under their admitted keys.
const std = @import("std");
const spans = @import("span_statement_blake3.zig");

pub const VERSION: u32 = 2;
pub const Entry = struct {
    statement: spans.SpanStatement,
    expected_key_id: [32]u8,
};

pub fn validate(job: spans.JobContext, entries: []const Entry) !spans.ExecutedSpan {
    try job.validate();
    if (entries.len == 0 or entries.len > spans.MAX_SLOT_HEIGHT + 1)
        return error.IncompleteStream;
    if (entries.len != @popCount(job.segment_count))
        return error.InvalidExactForestNodeCount;
    var next: u64 = 0;
    var combined: ?spans.ExecutedSpan = null;
    for (entries) |entry| {
        try entry.statement.validate();
        const statement = entry.statement;
        if (!std.meta.eql(job, statement.job)) return error.StreamJobMismatch;
        if (statement.slots.first != next) return error.StreamOutOfOrder;
        const executed = switch (statement.body) {
            .executed => |body| body,
            .empty => return error.UnprovedExactForestPadding,
        };
        combined = if (combined) |earlier| try spans.foldExecuted(earlier, executed) else executed;
        next = statement.slots.endExclusive();
    }
    if (next != job.segment_count) return error.IncompleteStream;
    const result = combined.?;
    if (result.first_segment != 0 or result.segment_count != job.segment_count or
        result.first_cycle != 0 or result.cycle_count != job.complete.total_cycles or
        !std.meta.eql(result.entry, job.complete.initial_state) or
        !std.meta.eql(result.exit, job.complete.final_state) or
        !std.meta.eql(result.input.digest, @as(?spans.Digest, job.complete.public_input)) or
        !std.meta.eql(result.output.digest, @as(?spans.Digest, job.complete.public_output)))
        return error.IncompleteStream;
    return result;
}

pub fn digest(job: spans.JobContext, entries: []const Entry) ![32]u8 {
    _ = try validate(job, entries);
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update("stwo.riscv.execution.exact-forest.v2\x00");
    hashInt(&hash, u32, VERSION);
    hashInt(&hash, u32, job.segment_count);
    hashInt(&hash, u32, @intCast(entries.len));
    for (entries) |entry| {
        const words = try entry.statement.canonicalWords();
        for (words) |word| hashInt(&hash, u32, word.toU32());
        hash.update(&entry.expected_key_id);
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn hashInt(hash: *std.crypto.hash.Blake3, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "exact-count V2 protocol binds keys and rejects discontinuous forest state" {
    const fixture = @import("span_statement_blake3_test_fixture.zig");
    const job = try fixture.job(3);
    const middle = try fixture.state(4, 0x88);
    const boundary = try fixture.state(8, 0x88);
    const first = try fixture.leaf(job, 0, job.complete.initial_state, middle);
    const second = try fixture.leaf(job, 1, middle, boundary);
    const third = try fixture.leaf(job, 2, boundary, job.complete.final_state);
    var entries = [2]Entry{
        .{ .statement = try spans.SpanStatement.fold(first, second), .expected_key_id = @splat(1) },
        .{ .statement = third, .expected_key_id = @splat(2) },
    };
    try std.testing.expectEqual(@as(u32, 3), (try validate(job, &entries)).segment_count);
    const original = try digest(job, &entries);
    entries[1].expected_key_id[0] ^= 1;
    const changed = try digest(job, &entries);
    try std.testing.expect(!std.mem.eql(u8, &original, &changed));
    entries[1].statement = try fixture.leaf(
        job,
        2,
        try fixture.state(8, 0x99),
        job.complete.final_state,
    );
    try std.testing.expectError(error.StateDiscontinuity, validate(job, &entries));
}
