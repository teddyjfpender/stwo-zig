//! Actual bounded PAGE public-claim witness proposal. Reads original premix
//! cells and original core captures; no bit SHA/BLAKE hashing or sibling tape.
//! These scalar equations are NEVER authority. The same claims must enter the
//! genuine PAGE arithmetic/core/input proof and actual fresh CPU receiver.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Raw = @import("block_v5_memory_source_batch_raw_v1.zig");
const Schema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const PackedSHA = @import("block_v5_memory_source_packed_sha_v1.zig");
const Original = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig");
const Blake = @import("block_v5_memory_source_blake_semantics_v1.zig");
const Sink = struct {
    pub fn zero(_: *@This(), value: Q) !void {
        if (!value.isZero()) return error.UnsatisfiedSourcePageClaimProposal;
    }
};
fn cell(reader: Semantic.Reader, group: Semantic.Group, row: u32, column: usize) !Q {
    const value = try reader.read(reader.context, group, row, @intCast(column));
    if (value.v >= core.fields.m31.Modulus) return error.NoncanonicalSourcePageClaimCell;
    return Q.fromBase(value);
}
fn sumInto(comptime T: type, target: *T, value: T) void {
    inline for (std.meta.fields(T)) |field| @field(target.*, field.name) = @field(target.*, field.name).add(@field(value, field.name));
}
fn readSource(comptime count: usize, reader: Semantic.Reader, row: u32) ![count]Q {
    var out: [count]Q = undefined;
    for (&out, 0..) |*value, column| value.* = try cell(reader, .source, row, column);
    return out;
}
fn pack(bits: []const Q) Q {
    var out = Q.zero();
    var weight = Q.one();
    for (bits) |bit| {
        out = out.add(weight.mul(bit));
        weight = weight.add(weight);
    }
    return out;
}
pub fn raw(admitted: *const Batch.Admission, page: Schema.Protocol.Page, reader: Semantic.Reader, challenges: Batch.Challenges) !Semantic.Claims {
    try admitted.require();
    if (page.chunks == 0 or page.chunks > 4096 or page.row_log < 1 or page.row_log > 12 or page.chunks > @as(u32, 1) << @intCast(page.row_log)) return error.InvalidSourcePageClaimProposal;
    var sink = Sink{};
    var out = Semantic.Claims.zero();
    for (0..page.chunks) |logical| {
        const descriptor = try Raw.kindAt(&admitted.source, try std.math.add(u64, page.first_chunk, logical));
        const values = try readSource(Original.BIT_COUNT, reader, @intCast(logical));
        switch (descriptor) {
            .sha => |sha| {
                var bytes: [64][8]Q = undefined;
                var state: [8][32]Q = undefined;
                var output: [32]Q = undefined;
                for (&bytes, 0..) |*byte, i| byte.* = values[8 * i ..][0..8].*;
                for (&state, 0..) |*word, i| word.* = values[512 + 32 * i ..][0..32].*;
                const blocks = try PackedSHA.chunkCompressionCount(&admitted.source, sha.stream, sha.block);
                for (&output, 0..) |*byte, i| byte.* = try cell(reader, .capture, @intCast(logical), 128 * (blocks - 1) + 96 + 4 * (i / 4) + (3 - i % 4));
                const A = Original.Algebra(Q);
                const pairs = [_]A.Pair{
                    .{ .z = challenges.source.bytes.z, .alpha = challenges.source.bytes.alpha },
                    .{ .z = challenges.source.input.z, .alpha = challenges.source.input.alpha },
                    .{ .z = challenges.source.sha_chain.z, .alpha = challenges.source.sha_chain.alpha },
                };
                const result = try PackedSHA.Algebra(Q).semanticBytes(&admitted.source, sha.stream, sha.block, bytes, state, output, pairs);
                out.source.bytes = out.source.bytes.add(result.bytes);
                out.source.input = out.source.input.add(result.input);
                out.source.sha_chain = out.source.sha_chain.add(result.sha_chain);
            },
            .record => {
                var inputs: [Original.INPUT_COUNT]Q = @splat(Q.zero());
                @memcpy(inputs[0..Original.BIT_COUNT], &values);
                inline for (.{ challenges.source.bytes, challenges.source.input, challenges.source.insertion, challenges.source.before, challenges.source.after, challenges.source.route, challenges.source.roots, challenges.source.ordering, challenges.source.sha_chain, challenges.source.word.initial, challenges.source.word.endpoint }, 0..) |pair, i| {
                    inputs[Original.BIT_COUNT + 2 * i] = pair.z;
                    inputs[Original.BIT_COUNT + 2 * i + 1] = pair.alpha;
                }
                const result = try Raw.Algebra(Q).record(&admitted.source, descriptor, &inputs, .{ .z = challenges.indexed.z, .alpha = challenges.indexed.alpha }, &sink);
                sumInto(@TypeOf(out.source), &out.source, result.source);
                out.indexed = out.indexed.add(result.indexed);
            },
        }
    }
    return out;
}
pub fn fold(admitted: *const Batch.Admission, rows: []const Semantic.FoldRow, reader: Semantic.Reader, challenges: Batch.Challenges) !Semantic.Claims {
    try admitted.require();
    if (rows.len == 0 or rows.len > 4096) return error.InvalidSourcePageClaimProposal;
    var out = Semantic.Claims.zero();
    var sink = Sink{};
    const B = Blake.Algebra(Q);
    var next = rows[0].first_compression;
    for (rows, 0..) |row, logical| {
        if (row.first_compression != next or row.compressions > 4) return error.InvalidSourcePageClaimProposal;
        try Blake.requireRecipes(row.descriptor.kind, row.descriptor.height, row.recipes, row.first_compression, row.compressions);
        next = try std.math.add(u32, next, row.compressions);
        const values = try readSource(Eq.BIT_COUNT, reader, @intCast(logical));
        var result = try Eq.Algebra(Q).compute(false, admitted, row.descriptor, &values, Eq.Algebra(Q).challenges(challenges), &sink);
        var frames: [2]B.Frame = undefined;
        var digests: [2][32]Q = undefined;
        for (&digests, 0..) |*digest, side| {
            for (digest, 0..) |*byte, i| byte.* = pack(values[320 + side * 256 + 8 * i ..][0..8]);
        }
        switch (row.descriptor.kind) {
            .leaf => for (&frames, 0..) |*frame, side| {
                var bytes: [4]Q = undefined;
                for (&bytes, 0..) |*byte, i| byte.* = pack(values[64 + side * 32 + 8 * i ..][0..8]);
                frame.* = .{ .leaf = bytes };
            },
            .branch => for (&frames, 0..) |*frame, side| {
                var bytes: [64]Q = undefined;
                for (0..32) |i| {
                    bytes[i] = pack(values[832 + side * 256 + 8 * i ..][0..8]);
                    bytes[32 + i] = pack(values[1344 + side * 256 + 8 * i ..][0..8]);
                }
                frame.* = .{ .node = bytes };
            },
            .empty, .root => frames = @splat(.{ .leaf = @splat(Q.zero()) }),
        }
        var captures: [4][192]Q = undefined;
        for (captures[0..row.compressions], 0..) |*capture, block| for (capture, 0..) |*value, column| {
            value.* = try cell(reader, .capture, row.first_compression + @as(u32, @intCast(block)), column);
        };
        const provider = try B.providers(&sink, row.descriptor.kind, row.descriptor.height, frames, digests, row.recipes, captures[0..row.compressions], row.first_compression, .{ .z = challenges.hash.z, .alpha = challenges.hash.alpha });
        try sink.zero(result.hash.add(provider));
        result.hash = result.hash.add(provider);
        sumInto(@TypeOf(out.fold), &out.fold, result);
    }
    return out;
}
