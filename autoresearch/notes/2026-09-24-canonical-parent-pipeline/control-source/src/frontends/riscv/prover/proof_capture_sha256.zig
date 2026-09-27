//! Engine-generic transport seal for a successful STARK proof capture.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;

const Sha256 = std.crypto.hash.sha2.Sha256;
// Preserve the already-published SegmentV3 capture identity while moving its
// engine-generic implementation to one shared owner.
const DOMAIN = "stwo-zig/riscv/ethereum-segment-v3-proof-capture/v1\x00";

/// Hashes only canonical value data. It supports both byte-valued native
/// commitments and word-valued Poseidon2 commitments without naming an
/// engine or treating this transport digest as an in-circuit authority.
pub fn compute(capture: anytype) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u32, capture.commitments.len);
    for (capture.commitments) |value| hashCommitment(&hash, value);
    hashInt(&hash, u32, capture.column_log_sizes.len);
    for (capture.column_log_sizes) |logs| {
        hashInt(&hash, u32, logs.len);
        for (logs) |value| hashInt(&hash, u32, value);
    }
    hashInt(&hash, u32, capture.sampled_points.len);
    for (capture.sampled_points) |columns| {
        hashInt(&hash, u32, columns.len);
        for (columns) |points| {
            hashInt(&hash, u32, points.len);
            for (points) |point| {
                hashQm31(&hash, point.x);
                hashQm31(&hash, point.y);
            }
        }
    }
    hashQm31Slice(&hash, capture.sampled_values);
    hashInt(&hash, u32, capture.queried_values.len);
    for (capture.queried_values) |value| hashInt(&hash, u32, value.toU32());
    hashQm31Slice(&hash, capture.deep_answers);
    hashInt(&hash, u32, capture.trace_paths.len);
    for (capture.trace_paths) |path| {
        hashInt(&hash, u32, path.path_depth);
        hashUsizeSlice(&hash, path.positions);
        hashInt(&hash, u32, path.siblings.len);
        for (path.siblings) |value| hashCommitment(&hash, value);
    }
    hashInt(&hash, u32, capture.fri.layers.len);
    for (capture.fri.layers) |layer| {
        hashCommitment(&hash, layer.commitment);
        hashQm31(&hash, layer.folding_alpha);
        hashInt(&hash, u32, layer.fold_step);
        hashInt(&hash, u32, layer.fold_width);
        hashInt(&hash, u32, layer.path_depth);
        hashInt(&hash, u32, layer.query_count);
        hashUsizeSlice(&hash, layer.positions);
        hashQm31Slice(&hash, layer.values);
        hashInt(&hash, u32, layer.siblings.len);
        for (layer.siblings) |value| hashCommitment(&hash, value);
    }
    hashQm31Slice(&hash, capture.last_layer_coefficients);
    hashInt(&hash, u64, capture.proof_of_work);
    hashQm31(&hash, capture.composition_randomness);
    hashQm31(&hash, capture.oods_seed);
    hashQm31(&hash, capture.deep_randomness);
    hashUsizeSlice(&hash, capture.queries.raw);
    hashUsizeSlice(&hash, capture.queries.unique);
    return hash.finalResult();
}

fn hashUsizeSlice(hash: *Sha256, values: []const usize) void {
    hashInt(hash, u32, values.len);
    for (values) |value| hashInt(hash, u64, value);
}

fn hashQm31Slice(hash: *Sha256, values: []const QM31) void {
    hashInt(hash, u32, values.len);
    for (values) |value| hashQm31(hash, value);
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

fn hashCommitment(hash: *Sha256, value: anytype) void {
    const info = @typeInfo(@TypeOf(value));
    if (info != .array) @compileError("commitment hash must be a fixed array");
    if (info.array.child == u8) {
        hash.update(&value);
    } else if (info.array.child == u32) {
        for (value) |word| hashInt(hash, u32, word);
    } else {
        @compileError("unsupported commitment hash element type");
    }
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
