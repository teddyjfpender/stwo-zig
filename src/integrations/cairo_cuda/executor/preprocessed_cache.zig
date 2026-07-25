//! One-time loader for authenticated Cairo preprocessed coefficients.
//!
//! STWZPPC stores Rust SIMD coefficient blocks. This boundary validates every
//! column identity and shape, canonicalizes blocked coefficient order, and
//! uploads directly into the immutable process arena.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const trace_commit = @import("trace_commit.zig");

pub const format_magic = "STWZPPC\x00";
pub const format_version: u32 = 1;

pub const Receipt = struct {
    artifact_identity: proof_ir.Digest,
    commitment_identity: proof_ir.Digest,
    column_count: u32,
    coefficient_words: u64,
    identity: proof_ir.Digest,

    pub fn validate(self: Receipt) !void {
        if (digestEmpty(self.artifact_identity) or
            digestEmpty(self.commitment_identity) or
            self.column_count == 0 or
            self.coefficient_words == 0 or
            digestEmpty(self.identity) or
            !std.mem.eql(u8, &self.identity, &receiptIdentity(self)))
        {
            return error.InvalidPreprocessedCacheReceipt;
        }
    }
};

pub fn load(
    allocator: std.mem.Allocator,
    session: anytype,
    path: []const u8,
    artifact_identity: proof_ir.Digest,
    expected_identities: anytype,
    prepared: *const trace_commit.Prepared,
    bound: *const trace_commit.Bound,
) !Receipt {
    if (digestEmpty(artifact_identity) or
        prepared.tree_ordinal != 0 or
        prepared.input_form != .coefficients or
        prepared.column_logs.len != expected_identities.len or
        prepared.column_offsets.len != expected_identities.len + 1 or
        bound.prepared != prepared)
    {
        return error.InvalidPreprocessedCacheBinding;
    }
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var reader_buffer: [1 << 20]u8 = undefined;
    var reader = file.readerStreaming(&reader_buffer);
    const stream = &reader.interface;
    if (!std.mem.eql(u8, try stream.takeArray(8), format_magic))
        return error.InvalidPreprocessedArtifact;
    if (try stream.takeInt(u32, .little) != format_version or
        try stream.takeInt(u32, .little) != expected_identities.len)
    {
        return error.InvalidPreprocessedArtifact;
    }

    var maximum_words: usize = 0;
    for (prepared.column_logs) |log_rows|
        maximum_words = @max(maximum_words, try pow2(log_rows));
    const staging = try allocator.alloc(u32, maximum_words);
    defer allocator.free(staging);

    var coefficient_words: u64 = 0;
    for (
        expected_identities,
        prepared.column_logs,
        0..,
    ) |expected_identity, expected_log, ordinal| {
        const identity_len = try stream.takeInt(u16, .little);
        if (try stream.takeInt(u16, .little) != 0 or
            identity_len != expected_identity.len)
        {
            return error.InvalidPreprocessedArtifact;
        }
        const log_rows = try stream.takeInt(u32, .little);
        const value_count = try stream.takeInt(u64, .little);
        const words = try pow2(log_rows);
        if (log_rows != expected_log or value_count != words)
            return error.InvalidPreprocessedArtifact;
        const identity = try allocator.alloc(u8, identity_len);
        defer allocator.free(identity);
        try stream.readSliceAll(identity);
        if (!std.mem.eql(u8, identity, expected_identity))
            return error.InvalidPreprocessedArtifact;

        const values = staging[0..words];
        try stream.readSliceAll(std.mem.sliceAsBytes(values));
        for (values) |value| {
            if (value >= 0x7fff_ffff)
                return error.NonCanonicalPreprocessedCoefficient;
        }
        if (log_rows > 16)
            canonicalizeSimdCoefficientBlocks(values, log_rows);
        const begin: usize = prepared.column_offsets[ordinal];
        const end: usize = prepared.column_offsets[ordinal + 1];
        if (end < begin or end - begin != words)
            return error.InvalidPreprocessedCacheBinding;
        try session.context.uploadSlice(
            u32,
            try bound.coefficients.sub(begin, words),
            values,
        );
        coefficient_words = std.math.add(
            u64,
            coefficient_words,
            words,
        ) catch return error.PreprocessedArtifactOverflow;
    }
    var trailing: [1]u8 = undefined;
    if (try stream.readSliceShort(&trailing) != 0)
        return error.InvalidPreprocessedArtifact;

    var receipt = Receipt{
        .artifact_identity = artifact_identity,
        .commitment_identity = prepared.identity,
        .column_count = @intCast(expected_identities.len),
        .coefficient_words = coefficient_words,
        .identity = undefined,
    };
    receipt.identity = receiptIdentity(receipt);
    try receipt.validate();
    return receipt;
}

fn canonicalizeSimdCoefficientBlocks(
    words: []u32,
    log_rows: u32,
) void {
    const log_lanes: u32 = 4;
    std.debug.assert(
        log_rows > 16 and
            words.len == @as(usize, 1) << @intCast(log_rows),
    );
    const log_vectors = log_rows - log_lanes;
    const half = log_vectors / 2;
    const outer = @as(usize, 1) << @intCast(half);
    const middle = @as(usize, 1) << @intCast(log_vectors & 1);
    for (0..outer) |a| {
        for (0..middle) |b| {
            for (0..outer) |c| {
                const i = (a << @intCast(log_vectors - half)) |
                    (b << @intCast(half)) | c;
                const j = (c << @intCast(log_vectors - half)) |
                    (b << @intCast(half)) | a;
                if (i >= j) continue;
                const lhs = words[i * 16 ..][0..16];
                const rhs = words[j * 16 ..][0..16];
                for (lhs, rhs) |*left, *right|
                    std.mem.swap(u32, left, right);
            }
        }
    }
}

fn receiptIdentity(value: Receipt) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/preprocessed-cache/v1\x00");
    hash.update(&value.artifact_identity);
    hash.update(&value.commitment_identity);
    hashInt(&hash, u32, value.column_count);
    hashInt(&hash, u64, value.coefficient_words);
    return hash.finalResult();
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn pow2(log_rows: u32) !usize {
    if (log_rows >= @bitSizeOf(usize))
        return error.PreprocessedArtifactOverflow;
    return @as(usize, 1) << @intCast(log_rows);
}

fn digestEmpty(value: proof_ir.Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

test "SIMD coefficient canonicalization is an involution" {
    const log_rows: u32 = 17;
    const values = try std.testing.allocator.alloc(
        u32,
        @as(usize, 1) << log_rows,
    );
    defer std.testing.allocator.free(values);
    for (values, 0..) |*value, index| value.* = @intCast(index);
    canonicalizeSimdCoefficientBlocks(values, log_rows);
    try std.testing.expectEqual(@as(u32, 128 * 16), values[16]);
    try std.testing.expectEqual(@as(u32, 16), values[128 * 16]);
    canonicalizeSimdCoefficientBlocks(values, log_rows);
    for (values, 0..) |value, index|
        try std.testing.expectEqual(@as(u32, @intCast(index)), value);
}
