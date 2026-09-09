//! Canonical publication for a recursively folded globally clocked V2 span.
//! Native folding and AIR consumers share the endpoint propagation/join rules.
//! These words become authenticated only through the admitted proof relation.
const std = @import("std");
const core = @import("stwo_core");
const span = @import("span_statement.zig");
const M31 = core.fields.m31.M31;
pub const VERSION: u32 = 1;
pub const SPAN_WORDS = span.SPAN_STATEMENT_CANONICAL_WORDS;
pub const SESSION_START = SPAN_WORDS;
pub const ENTRY_START = SESSION_START + 8;
pub const EXIT_START = ENTRY_START + 8;
pub const WORD_COUNT = EXIT_START + 8;
pub const Words = [WORD_COUNT]M31;
pub const Mode = enum(u8) { intermediate = 0, root = 1 };
pub const Error = span.Error || error{ NonCanonicalContinuationWord, SessionMismatch, LineageDiscontinuity, EndpointPropagationMismatch };

pub fn fromSegment(statement: *const @import("segment_statement_v2.zig").StatementV2) !Words {
    try statement.validate();
    var result: Words = undefined;
    result[0..SPAN_WORDS].* = statement.base_statement_words;
    for ([_]span.Digest{ statement.session_id, statement.entry_lineage_id, statement.exit_lineage_id }, 0..) |digest, index| {
        for (digest, 0..) |word, limb| result[SPAN_WORDS + index * 8 + limb] = M31.fromCanonical(word);
    }
    return result;
}

pub fn validate(words: *const Words, mode: Mode) Error!void {
    for (words) |word| if (word.toU32() >= core.fields.m31.Modulus) return error.NonCanonicalContinuationWord;
    const statement = try span.SpanStatement.fromCanonicalWords(words[0..SPAN_WORDS]);
    if (mode == .root) _ = try span.RootStatement.init(statement);
}

pub fn fold(left: *const Words, right: *const Words, mode: Mode) Error!Words {
    try validate(left, .intermediate);
    try validate(right, .intermediate);
    const statement = try span.SpanStatement.fold(try span.SpanStatement.fromCanonicalWords(left[0..SPAN_WORDS]), try span.SpanStatement.fromCanonicalWords(right[0..SPAN_WORDS]));
    var result: Words = undefined;
    result[0..SPAN_WORDS].* = try statement.canonicalWords();
    result[SESSION_START..][0..8].* = left[SESSION_START..][0..8].*;
    result[ENTRY_START..][0..8].* = left[ENTRY_START..][0..8].*;
    result[EXIT_START..][0..8].* = right[EXIT_START..][0..8].*;
    var checks: NativeChecks = .{};
    try emitFoldChecks(left, right, &result, &checks);
    try validate(&result, mode);
    return result;
}

/// Span validity/folding is separately enforced by the shared Span AIR.
/// This projection preserves exactly the extra information needed across levels.
pub fn emitFoldChecks(left: anytype, right: anytype, parent: anytype, sink: anytype) !void {
    try sink.equal(left[SESSION_START..][0..8], right[SESSION_START..][0..8], error.SessionMismatch);
    try sink.equal(parent[SESSION_START..][0..8], left[SESSION_START..][0..8], error.EndpointPropagationMismatch);
    try sink.equal(left[EXIT_START..][0..8], right[ENTRY_START..][0..8], error.LineageDiscontinuity);
    try sink.equal(parent[ENTRY_START..][0..8], left[ENTRY_START..][0..8], error.EndpointPropagationMismatch);
    try sink.equal(parent[EXIT_START..][0..8], right[EXIT_START..][0..8], error.EndpointPropagationMismatch);
}

const NativeChecks = struct {
    pub fn equal(_: *NativeChecks, left: anytype, right: anytype, err: Error) Error!void {
        for (left, right) |a, b| if (!a.eql(b)) return err;
    }
};
