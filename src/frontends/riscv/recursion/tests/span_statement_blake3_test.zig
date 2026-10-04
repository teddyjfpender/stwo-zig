const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const span = @import("../span_statement_blake3.zig");
const legacy = @import("../span_statement.zig");

const fixture = @import("../span_statement_blake3_test_fixture.zig");
const job = fixture.job;
const leaf = fixture.leaf;
const state = fixture.state;

test "BLAKE3 Span full-digest wire and format separation" {
    const context = try job(1);
    const statement = try leaf(context, 0, context.complete.initial_state, context.complete.final_state);
    const words = try statement.canonicalWords();
    try std.testing.expectEqual(@as(usize, 525), words.len);
    try std.testing.expectEqual(@as(usize, 412), legacy.SPAN_STATEMENT_CANONICAL_WORDS);
    try std.testing.expectEqual(statement, try span.SpanStatement.fromCanonicalWords(&words));
    _ = try span.RootStatement.init(statement);
    try std.testing.expectEqual(@as(u32, 0xffff), words[span.canonical_layout.protocol_start].toU32());
    var changed = words;
    changed[0] = M31.fromCanonical(@intFromEnum(legacy.Tag.span_statement));
    try std.testing.expectError(error.CanonicalTagMismatch, span.SpanStatement.fromCanonicalWords(&changed));
    changed = words;
    changed[1] = M31.fromCanonical(span.FORMAT_VERSION + 1);
    try std.testing.expectError(error.UnsupportedStatementVersion, span.SpanStatement.fromCanonicalWords(&changed));
    var legacy_words: legacy.StatementWords = @splat(M31.zero());
    legacy_words[0] = words[0];
    try std.testing.expectError(error.CanonicalTagMismatch, legacy.SpanStatement.fromCanonicalWords(&legacy_words));
}

test "BLAKE3 Span rejects aliases in all fourteen public digests" {
    const context = try job(1);
    const statement = try leaf(context, 0, context.complete.initial_state, context.complete.final_state);
    const words = try statement.canonicalWords();
    var checked: usize = 0;
    for (0..words.len) |index| {
        if (!span.isDigestWord(index)) continue;
        try std.testing.expect(span.isIntegerWord(index));
        var changed = words;
        changed[index] = M31.fromCanonical(0x10000);
        try std.testing.expectError(error.NonCanonicalDigestLimb, span.SpanStatement.fromCanonicalWords(&changed));
        checked += 1;
    }
    try std.testing.expectEqual(@as(usize, 14 * 16), checked);
}

test "BLAKE3 Span folds distinct children and binds high digest bits" {
    const context = try job(2);
    const middle = try state(8, 0xa0);
    const left = try leaf(context, 0, context.complete.initial_state, middle);
    const right = try leaf(context, 1, middle, context.complete.final_state);
    const parent = try span.SpanStatement.fold(left, right);
    _ = try span.RootStatement.init(parent);
    const words = try parent.canonicalWords();
    try std.testing.expectEqual(parent, try span.SpanStatement.fromCanonicalWords(&words));
    for (0..32) |index| {
        var wrong = right;
        wrong.body.executed.entry.rw_memory.bytes[index] ^= 0x80;
        try std.testing.expectError(error.StateDiscontinuity, span.SpanStatement.fold(left, wrong));
    }
    var wrong = parent;
    wrong.body.executed.output.digest.?.bytes[31] ^= 0x80;
    try std.testing.expectError(error.OutputMismatch, span.RootStatement.init(wrong));
}

test "BLAKE3 Span padding preserves coverage and rejects hidden words" {
    const context = try job(3);
    const first = try state(4, 0xa0);
    const second = try state(8, 0xb0);
    const a = try leaf(context, 0, context.complete.initial_state, first);
    const b = try leaf(context, 1, first, second);
    const c = try leaf(context, 2, second, context.complete.final_state);
    const padding = try span.SpanStatement.emptyLeaf(context, 3);
    const parent = try span.SpanStatement.fold(
        try span.SpanStatement.fold(a, b),
        try span.SpanStatement.fold(c, padding),
    );
    _ = try span.RootStatement.init(parent);
    var words = try padding.canonicalWords();
    words[words.len - 1] = M31.one();
    try std.testing.expectError(error.CanonicalPaddingNonZero, span.SpanStatement.fromCanonicalWords(&words));
    try std.testing.expectError(error.InteriorEmptySpan, span.SpanStatement.emptyLeaf(context, 2));
}
