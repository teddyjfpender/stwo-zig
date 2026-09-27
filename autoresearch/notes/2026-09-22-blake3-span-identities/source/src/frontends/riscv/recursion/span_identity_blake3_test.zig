const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const span = @import("span_statement_blake3.zig");
const identity = span.identity;
const fixture = @import("span_statement_blake3_test_fixture.zig");

test "BLAKE3 Span identity separates jobs and statements with exact framing" {
    const context = try fixture.job(2);
    const middle = try fixture.state(8, 0xa0);
    const a = try fixture.leaf(context, 0, context.complete.initial_state, middle);
    const b = try fixture.leaf(context, 1, middle, context.complete.final_state);
    const left = try a.canonicalWords();
    const right = try b.canonicalWords();
    const parent = try (try span.SpanStatement.fold(a, b)).canonicalWords();
    const job = try identity.hash(&left, .job);
    try std.testing.expectEqual(job, try identity.hash(&right, .job));
    try std.testing.expectEqual(job, try identity.hash(&parent, .job));
    const statement = try identity.hash(&left, .statement);
    try std.testing.expect(!std.meta.eql(job, statement));
    try std.testing.expect(!std.meta.eql(statement, try identity.hash(&right, .statement)));
    var storage: [identity.MAX_BYTE_COUNT]u8 = undefined;
    const encoded = try identity.encode(&left, .statement, &storage);
    try std.testing.expectEqual(@as(usize, 2144), encoded.len);
    try std.testing.expectEqual(@as(usize, 1128), identity.byteCount(.job));
    try std.testing.expectEqualSlices(u8, identity.DOMAIN, encoded[0..identity.DOMAIN.len]);
    for (encoded[identity.DOMAIN.len..32]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, encoded[32..36], .little));
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, encoded[36..40], .little));
    try std.testing.expectEqual(@as(u32, 525), std.mem.readInt(u32, encoded[40..44], .little));
    var expected: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(encoded, &expected, .{});
    try std.testing.expectEqual(expected, statement.bytes);
    for (0..525) |index| try std.testing.expectEqual(identity.Source{ .statement_word = @intCast(index) }, try identity.sourceAt(.statement, identity.HEADER_WORD_COUNT + index));
    try std.testing.expectError(error.IdentityWordOutOfRange, identity.sourceAt(.statement, identity.HEADER_WORD_COUNT + 525));
}

test "BLAKE3 Span identity rejects invalid input before writes and binds high bits" {
    const context = try fixture.job(2);
    const leaf = try fixture.leaf(context, 0, context.complete.initial_state, try fixture.state(8, 0xa0));
    const words = try leaf.canonicalWords();
    const original = try identity.hash(&words, .statement);
    for (0..32) |byte| {
        var changed = leaf;
        changed.body.executed.exit.rw_memory.bytes[byte] ^= 0x80;
        const changed_words = try changed.canonicalWords();
        try std.testing.expect(!std.meta.eql(original, try identity.hash(&changed_words, .statement)));
    }
    var destination: [identity.MAX_BYTE_COUNT]u8 = @splat(0xa5);
    try std.testing.expectError(error.IdentityBufferTooSmall, identity.encode(&words, .statement, destination[0 .. destination.len - 1]));
    var invalid = words;
    invalid[1] = M31.fromCanonical(2);
    try std.testing.expectError(error.UnsupportedStatementVersion, identity.encode(&invalid, .statement, &destination));
    for (destination) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
}

test "BLAKE3 Span identity matches recursive hash witnesses and rejects digest substitution" {
    const hash = @import("air/blake3_hash_witness.zig");
    const support = @import("air/blake3_hash_test_support.zig");
    const context = try fixture.job(1);
    const leaf = try fixture.leaf(context, 0, context.complete.initial_state, context.complete.final_state);
    const words = try leaf.canonicalWords();
    var storage: [identity.MAX_BYTE_COUNT]u8 = undefined;
    for ([_]identity.Purpose{ .job, .statement }) |purpose| {
        const expected = try identity.hash(&words, purpose);
        const bytes = try identity.encode(&words, purpose, &storage);
        var prepared = try hash.prepare(std.testing.allocator, 919, bytes, expected.bytes);
        defer prepared.rows.deinit();
        try std.testing.expectEqual(expected.bytes, prepared.digest);
        try std.testing.expect(try support.closed(&prepared.rows));
        var bad_digest = expected.bytes;
        bad_digest[31] ^= 0x80;
        var wrong = try hash.prepare(std.testing.allocator, 919, bytes, bad_digest);
        defer wrong.rows.deinit();
        try std.testing.expect(!try support.closed(&wrong.rows));
    }
}
