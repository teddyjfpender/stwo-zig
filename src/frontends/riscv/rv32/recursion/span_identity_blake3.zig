//! Versioned BLAKE3 identities over canonical full-digest Span statements.
//! `sourceAt` owns the preimage layout for both native hashing and future AIR
//! input routing. It describes sources; it does not authenticate a caller wire.
const std = @import("std");
const core = @import("stwo_core");
const contract = @import("span_statement_executed_span.zig").Contract(true);
const semantics = @import("span_statement_semantics.zig").Semantics(contract);
const Hasher = core.vcs.blake3_hash.Blake3Hasher;

pub const Digest = contract.Digest;
pub const StatementWords = contract.StatementWords;
pub const FORMAT_VERSION: u32 = 1;
pub const DOMAIN = "stwo.riscv.blake3.identity.v1";
/// 32-byte zero-padded domain, followed by version, purpose and payload count.
pub const HEADER_WORD_COUNT: usize = 11;
pub const MAX_BYTE_COUNT: usize = (HEADER_WORD_COUNT + contract.SPAN_STATEMENT_CANONICAL_WORDS) * 4;
pub const Purpose = enum(u32) { statement = 1, job = 2 };
pub const Source = union(enum) { constant: u32, statement_word: u16 };
pub const Error = contract.Error || error{ IdentityWordOutOfRange, IdentityBufferTooSmall };

const domain_bytes: [32]u8 = blk: {
    if (DOMAIN.len >= 32) @compileError("identity domain must have terminating zero padding");
    var bytes: [32]u8 = @splat(0);
    @memcpy(bytes[0..DOMAIN.len], DOMAIN);
    break :blk bytes;
};

pub fn payloadWordCount(purpose: Purpose) usize {
    return switch (purpose) {
        .statement => contract.SPAN_STATEMENT_CANONICAL_WORDS,
        .job => contract.JOB_CONTEXT_CANONICAL_WORDS,
    };
}

pub fn byteCount(purpose: Purpose) usize {
    return (HEADER_WORD_COUNT + payloadWordCount(purpose)) * 4;
}

pub fn sourceAt(purpose: Purpose, index: usize) Error!Source {
    if (index >= HEADER_WORD_COUNT + payloadWordCount(purpose)) return error.IdentityWordOutOfRange;
    if (index < 8) return .{ .constant = std.mem.readInt(u32, domain_bytes[index * 4 ..][0..4], .little) };
    return switch (index) {
        8 => .{ .constant = FORMAT_VERSION },
        9 => .{ .constant = @intFromEnum(purpose) },
        10 => .{ .constant = @intCast(payloadWordCount(purpose)) },
        else => .{ .statement_word = @intCast(index - HEADER_WORD_COUNT + switch (purpose) {
            .statement => @as(usize, 0),
            .job => contract.canonical_layout.job_start,
        }) },
    };
}

/// Validation completes before the first sink update. The sink consumes bytes.
pub fn write(words: *const StatementWords, purpose: Purpose, sink: anytype) Error!void {
    _ = try semantics.SpanStatement.fromCanonicalWords(words);
    writeValidated(words, purpose, sink);
}

fn writeValidated(words: *const StatementWords, purpose: Purpose, sink: anytype) void {
    for (0..HEADER_WORD_COUNT + payloadWordCount(purpose)) |index| {
        const source = sourceAt(purpose, index) catch unreachable;
        const word = switch (source) {
            .constant => |value| value,
            .statement_word => |at| words[at].toU32(),
        };
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        sink.update(&bytes);
    }
}

pub fn hash(words: *const StatementWords, purpose: Purpose) Error!Digest {
    var hasher = Hasher.init();
    try write(words, purpose, &hasher);
    return .{ .bytes = hasher.finalize() };
}

pub fn encode(words: *const StatementWords, purpose: Purpose, destination: []u8) Error![]const u8 {
    _ = try semantics.SpanStatement.fromCanonicalWords(words);
    const count = byteCount(purpose);
    if (destination.len < count) return error.IdentityBufferTooSmall;
    var sink = ByteSink{ .bytes = destination[0..count] };
    writeValidated(words, purpose, &sink);
    std.debug.assert(sink.at == count);
    return destination[0..count];
}

const ByteSink = struct {
    bytes: []u8,
    at: usize = 0,
    pub fn update(self: *ByteSink, bytes: []const u8) void {
        @memcpy(self.bytes[self.at..][0..bytes.len], bytes);
        self.at += bytes.len;
    }
};
