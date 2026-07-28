//! Minimal postcard (varint / LEB128) binary codec.
//!
//! This module provides encode/decode primitives compatible with Rust's
//! `postcard` crate (https://docs.rs/postcard), which is used by stark-v to
//! serialize proofs.  The encoding uses unsigned LEB128 varints for integer
//! values and length-prefixed sequences for vectors.
//!
//! The proof serializer produces byte-equivalent output to stark-v's
//! `postcard::to_allocvec(&proof)` so that proofs can be exchanged across
//! language boundaries.

const std = @import("std");
const fri = @import("stwo_core").fri;
const m31_mod = @import("stwo_core").fields.m31;
const qm31_mod = @import("stwo_core").fields.qm31;
const pcs = @import("stwo_core").pcs;
const proof_mod = @import("stwo_core").proof;
const vcs_verifier = @import("stwo_core").vcs_lifted.verifier;
const proof_wire = @import("stwo_proof_wire");

pub const proof_preflight = @import("postcard/proof_preflight.zig");

const M31 = m31_mod.M31;
const QM31 = qm31_mod.QM31;

// ---------------------------------------------------------------------------
// Varint (unsigned LEB128)
// ---------------------------------------------------------------------------

/// Encode an unsigned 64-bit integer as a varint (unsigned LEB128).
pub fn writeVarint(writer: anytype, value: u64) !void {
    var v = value;
    while (v >= 0x80) {
        try writer.writeByte(@intCast((v & 0x7F) | 0x80));
        v >>= 7;
    }
    try writer.writeByte(@intCast(v));
}

/// Decode an unsigned varint (unsigned LEB128) into a u64.
pub fn readVarint(reader: anytype) !u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    while (true) {
        const byte = try reader.readByte();
        result |= @as(u64, byte & 0x7F) << shift;
        if (byte & 0x80 == 0) break;
        if (shift >= 63) return error.VarintOverflow;
        shift +|= 7;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Basic type serializers
// ---------------------------------------------------------------------------

/// Write a u32 as a varint.
pub fn writeU32(writer: anytype, value: u32) !void {
    try writeVarint(writer, @as(u64, value));
}

/// Read a varint and narrow to u32.
pub fn readU32(reader: anytype) !u32 {
    const v = try readVarint(reader);
    if (v > std.math.maxInt(u32)) return error.VarintOverflow;
    return @intCast(v);
}

/// Write a u64 as a varint.
pub fn writeU64(writer: anytype, value: u64) !void {
    try writeVarint(writer, value);
}

/// Read a u64 varint.
pub fn readU64(reader: anytype) !u64 {
    return readVarint(reader);
}

/// Write a byte slice with a varint length prefix.
pub fn writeBytes(writer: anytype, data: []const u8) !void {
    try writeVarint(writer, data.len);
    try writer.writeAll(data);
}

/// Read a length-prefixed byte sequence.  Caller must free returned slice.
pub fn readBytes(allocator: std.mem.Allocator, reader: anytype) ![]u8 {
    const len = try readVarint(reader);
    if (len > std.math.maxInt(usize)) return error.VarintOverflow;
    const buf = try allocator.alloc(u8, @intCast(len));
    errdefer allocator.free(buf);
    const n = try reader.readAll(buf);
    if (n != buf.len) return error.EndOfStream;
    return buf;
}

/// Write `Option<T>`:  0 for null, 1 followed by the value for non-null.
/// `writeFn` serializes the inner value.
pub fn writeOption(
    writer: anytype,
    comptime T: type,
    value: ?T,
    writeFn: fn (@TypeOf(writer), T) anyerror!void,
) !void {
    if (value) |v| {
        try writer.writeByte(1);
        try writeFn(writer, v);
    } else {
        try writer.writeByte(0);
    }
}

/// Read `Option<T>`.  `readFn` deserializes the inner value.
pub fn readOption(
    reader: anytype,
    comptime T: type,
    readFn: fn (@TypeOf(reader)) anyerror!T,
) !?T {
    const tag = try reader.readByte();
    if (tag == 0) return null;
    if (tag != 1) return error.InvalidOptionTag;
    return try readFn(reader);
}

// ---------------------------------------------------------------------------
// Proof serializer — matches stark-v's `#[derive(Serialize)]` field order.
// ---------------------------------------------------------------------------

/// Serialize a `StarkProof(H)` to a writer using postcard-compatible encoding.
///
/// The field ordering matches Rust's `#[derive(Serialize)]` (i.e. struct
/// declaration order in stark-v):
///
///  1. PcsConfig (pow_bits, fri_config fields, lifting_log_size)
///  2. commitments (Vec<Hash>)
///  3. sampled_values (Vec<Vec<Vec<QM31>>>)
///  4. decommitments (Vec<MerkleDecommitment>)
///  5. queried_values (Vec<Vec<Vec<M31>>>)
///  6. proof_of_work (u64)
///  7. fri_proof (first_layer, inner_layers, last_layer_poly)
pub fn serializeProof(comptime H: type, writer: anytype, proof_arg: proof_mod.StarkProof(H)) !void {
    const csp = proof_arg.commitment_scheme_proof;

    // -- PcsConfig --
    try writeU32(writer, csp.config.pow_bits);
    try writeU32(writer, csp.config.fri_config.log_blowup_factor);
    if (csp.config.fri_config.n_queries > std.math.maxInt(u32)) return error.ValueOutOfRange;
    try writeU64(writer, @intCast(csp.config.fri_config.n_queries));
    try writeU32(writer, csp.config.fri_config.log_last_layer_degree_bound);
    try writeU32(writer, csp.config.fri_config.fold_step);

    // lifting_log_size: Option<u32>
    if (csp.config.lifting_log_size) |ls| {
        try writer.writeByte(1);
        try writeU32(writer, ls);
    } else {
        try writer.writeByte(0);
    }

    // -- commitments: Vec<Hash> --
    try writeVarint(writer, csp.commitments.items.len);
    for (csp.commitments.items) |hash| {
        try writer.writeAll(&hash);
    }

    // -- sampled_values: Vec<Vec<Vec<QM31>>> --
    try writeVarint(writer, csp.sampled_values.items.len);
    for (csp.sampled_values.items) |tree_cols| {
        try writeVarint(writer, tree_cols.len);
        for (tree_cols) |col| {
            try writeVarint(writer, col.len);
            for (col) |value| {
                try writeQm31(writer, value);
            }
        }
    }

    // -- decommitments: Vec<MerkleDecommitment> --
    try writeVarint(writer, csp.decommitments.items.len);
    for (csp.decommitments.items) |decommitment| {
        try writeVarint(writer, decommitment.hash_witness.len);
        for (decommitment.hash_witness) |hash| {
            try writer.writeAll(&hash);
        }
    }

    // -- queried_values: Vec<Vec<Vec<M31>>> --
    try writeVarint(writer, csp.queried_values.items.len);
    for (csp.queried_values.items) |tree_cols| {
        try writeVarint(writer, tree_cols.len);
        for (tree_cols) |col| {
            try writeVarint(writer, col.len);
            for (col) |value| {
                try writeU32(writer, value.toU32());
            }
        }
    }

    // -- proof_of_work: u64 --
    try writeU64(writer, csp.proof_of_work);

    // -- fri_proof --
    try writeFriLayer(H, writer, csp.fri_proof.first_layer);
    try writeVarint(writer, csp.fri_proof.inner_layers.len);
    for (csp.fri_proof.inner_layers) |layer| {
        try writeFriLayer(H, writer, layer);
    }
    try writeVarint(writer, csp.fri_proof.last_layer_poly.coefficients().len);
    for (csp.fri_proof.last_layer_poly.coefficients()) |coeff| {
        try writeQm31(writer, coeff);
    }
}

/// Deserialize a `StarkProof(H)` from a reader using postcard-compatible
/// encoding.  All inner slices are heap-allocated via `allocator`.
pub fn deserializeProof(
    comptime H: type,
    allocator: std.mem.Allocator,
    reader: anytype,
) !proof_mod.StarkProof(H) {
    const line = @import("stwo_core").poly.line;

    // -- PcsConfig --
    const pow_bits = try readU32(reader);
    const log_blowup_factor = try readU32(reader);
    const n_queries_u64 = try readU64(reader);
    if (n_queries_u64 > std.math.maxInt(usize)) return error.VarintOverflow;
    const log_last_layer_degree_bound = try readU32(reader);
    const fold_step = try readU32(reader);

    const lifting_tag = try reader.readByte();
    const lifting_log_size: ?u32 = if (lifting_tag == 1)
        try readU32(reader)
    else if (lifting_tag == 0)
        null
    else
        return error.InvalidOptionTag;

    var fri_config = try fri.FriConfig.init(
        log_last_layer_degree_bound,
        log_blowup_factor,
        @intCast(n_queries_u64),
    );
    fri_config.fold_step = fold_step;
    const config = pcs.PcsConfig{
        .pow_bits = pow_bits,
        .fri_config = fri_config,
        .lifting_log_size = lifting_log_size,
    };

    // -- commitments --
    const n_commitments = try readVarintUsize(reader);
    const commitments_slice = try allocator.alloc(H.Hash, n_commitments);
    errdefer allocator.free(commitments_slice);
    for (commitments_slice) |*hash| {
        const n = try reader.readAll(hash);
        if (n != hash.len) return error.EndOfStream;
    }
    const commitments = pcs.TreeVec(H.Hash).initOwned(commitments_slice);

    // -- sampled_values --
    const sampled_values = try readTreeQm31(allocator, reader);
    errdefer {
        var sv = sampled_values;
        sv.deinitDeep(allocator);
    }

    // -- decommitments --
    const decommitments = try readDecommitments(H, allocator, reader);
    errdefer {
        var ds = decommitments;
        for (ds.items) |*d| d.deinit(allocator);
        ds.deinit(allocator);
    }

    // -- queried_values --
    const queried_values = try readTreeM31(allocator, reader);
    errdefer {
        var qv = queried_values;
        qv.deinitDeep(allocator);
    }

    // -- proof_of_work --
    const proof_of_work = try readU64(reader);

    // -- fri_proof --
    const first_layer = try readFriLayer(H, allocator, reader);
    errdefer {
        var fl = first_layer;
        fl.deinit(allocator);
    }

    const n_inner = try readVarintUsize(reader);
    const inner_layers = try allocator.alloc(fri.FriLayerProof(H), n_inner);
    errdefer allocator.free(inner_layers);
    var inner_init: usize = 0;
    errdefer {
        for (inner_layers[0..inner_init]) |*il| il.deinit(allocator);
    }
    for (inner_layers) |*layer| {
        layer.* = try readFriLayer(H, allocator, reader);
        inner_init += 1;
    }

    const n_last = try readVarintUsize(reader);
    const last_coeffs = try allocator.alloc(QM31, n_last);
    errdefer allocator.free(last_coeffs);
    for (last_coeffs) |*coeff| {
        coeff.* = try readQm31(reader);
    }

    return .{
        .commitment_scheme_proof = .{
            .config = config,
            .commitments = commitments,
            .sampled_values = sampled_values,
            .decommitments = decommitments,
            .queried_values = queried_values,
            .proof_of_work = proof_of_work,
            .fri_proof = .{
                .first_layer = first_layer,
                .inner_layers = inner_layers,
                .last_layer_poly = line.LinePoly.initOwned(last_coeffs),
            },
        },
    };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn readVarintUsize(reader: anytype) !usize {
    const v = try readVarint(reader);
    if (v > std.math.maxInt(usize)) return error.VarintOverflow;
    return @intCast(v);
}

fn writeQm31(writer: anytype, value: QM31) !void {
    const coords = value.toM31Array();
    for (coords) |m| {
        try writeU32(writer, m.toU32());
    }
}

fn readQm31(reader: anytype) !QM31 {
    var coords: [4]M31 = undefined;
    for (&coords) |*c| {
        const v = try readU32(reader);
        if (v >= m31_mod.Modulus) return error.NonCanonicalM31;
        c.* = M31.fromCanonical(v);
    }
    return QM31.fromM31Array(coords);
}

fn writeFriLayer(comptime H: type, writer: anytype, layer: fri.FriLayerProof(H)) !void {
    try writeVarint(writer, layer.fri_witness.len);
    for (layer.fri_witness) |value| {
        try writeQm31(writer, value);
    }
    try writeVarint(writer, layer.decommitment.hash_witness.len);
    for (layer.decommitment.hash_witness) |hash| {
        try writer.writeAll(&hash);
    }
    try writer.writeAll(&layer.commitment);
}

fn readFriLayer(
    comptime H: type,
    allocator: std.mem.Allocator,
    reader: anytype,
) !fri.FriLayerProof(H) {
    const n_witness = try readVarintUsize(reader);
    const fri_witness = try allocator.alloc(QM31, n_witness);
    errdefer allocator.free(fri_witness);
    for (fri_witness) |*value| {
        value.* = try readQm31(reader);
    }

    const n_hashes = try readVarintUsize(reader);
    const hash_witness = try allocator.alloc(H.Hash, n_hashes);
    errdefer allocator.free(hash_witness);
    for (hash_witness) |*hash| {
        const n = try reader.readAll(hash);
        if (n != hash.len) return error.EndOfStream;
    }

    var commitment: H.Hash = undefined;
    const cn = try reader.readAll(&commitment);
    if (cn != commitment.len) return error.EndOfStream;

    return .{
        .fri_witness = fri_witness,
        .decommitment = .{ .hash_witness = hash_witness },
        .commitment = commitment,
    };
}

fn readTreeQm31(allocator: std.mem.Allocator, reader: anytype) !pcs.TreeVec([][]QM31) {
    const n_trees = try readVarintUsize(reader);
    const trees = try allocator.alloc([][]QM31, n_trees);
    errdefer allocator.free(trees);
    var tree_init: usize = 0;
    errdefer {
        for (trees[0..tree_init]) |cols| {
            for (cols) |col| allocator.free(col);
            allocator.free(cols);
        }
    }
    for (trees) |*tree| {
        const n_cols = try readVarintUsize(reader);
        const cols = try allocator.alloc([]QM31, n_cols);
        var col_init: usize = 0;
        errdefer {
            for (cols[0..col_init]) |col| allocator.free(col);
            allocator.free(cols);
        }
        for (cols) |*col| {
            const n_vals = try readVarintUsize(reader);
            const vals = try allocator.alloc(QM31, n_vals);
            errdefer allocator.free(vals);
            for (vals) |*v| {
                v.* = try readQm31(reader);
            }
            col.* = vals;
            col_init += 1;
        }
        tree.* = cols;
        tree_init += 1;
    }
    return pcs.TreeVec([][]QM31).initOwned(trees);
}

fn readTreeM31(allocator: std.mem.Allocator, reader: anytype) !pcs.TreeVec([][]M31) {
    const n_trees = try readVarintUsize(reader);
    const trees = try allocator.alloc([][]M31, n_trees);
    errdefer allocator.free(trees);
    var tree_init: usize = 0;
    errdefer {
        for (trees[0..tree_init]) |cols| {
            for (cols) |col| allocator.free(col);
            allocator.free(cols);
        }
    }
    for (trees) |*tree| {
        const n_cols = try readVarintUsize(reader);
        const cols = try allocator.alloc([]M31, n_cols);
        var col_init: usize = 0;
        errdefer {
            for (cols[0..col_init]) |col| allocator.free(col);
            allocator.free(cols);
        }
        for (cols) |*col| {
            const n_vals = try readVarintUsize(reader);
            const vals = try allocator.alloc(M31, n_vals);
            errdefer allocator.free(vals);
            for (vals) |*v| {
                const raw = try readU32(reader);
                if (raw >= m31_mod.Modulus) return error.NonCanonicalM31;
                v.* = M31.fromCanonical(raw);
            }
            col.* = vals;
            col_init += 1;
        }
        tree.* = cols;
        tree_init += 1;
    }
    return pcs.TreeVec([][]M31).initOwned(trees);
}

fn readDecommitments(
    comptime H: type,
    allocator: std.mem.Allocator,
    reader: anytype,
) !pcs.TreeVec(vcs_verifier.MerkleDecommitmentLifted(H)) {
    const n = try readVarintUsize(reader);
    const items = try allocator.alloc(vcs_verifier.MerkleDecommitmentLifted(H), n);
    errdefer allocator.free(items);
    var init_count: usize = 0;
    errdefer {
        for (items[0..init_count]) |*d| d.deinit(allocator);
    }
    for (items) |*item| {
        const n_hashes = try readVarintUsize(reader);
        const hashes = try allocator.alloc(H.Hash, n_hashes);
        errdefer allocator.free(hashes);
        for (hashes) |*hash| {
            const rd = try reader.readAll(hash);
            if (rd != hash.len) return error.EndOfStream;
        }
        item.* = .{ .hash_witness = hashes };
        init_count += 1;
    }
    return pcs.TreeVec(vcs_verifier.MerkleDecommitmentLifted(H)).initOwned(items);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "postcard: varint roundtrip" {
    const cases = [_]u64{ 0, 1, 0x7F, 0x80, 0xFF, 0x3FFF, 0x4000, 300, 1 << 21, 1 << 28, 1 << 35, 1 << 49, std.math.maxInt(u64) };
    for (cases) |value| {
        var buf: [16]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try writeVarint(fbs.writer(), value);
        const written = fbs.getWritten();

        var rbs = std.io.fixedBufferStream(written);
        const decoded = try readVarint(rbs.reader());
        try std.testing.expectEqual(value, decoded);
    }
}

test "postcard: varint encoding matches known values" {
    // 0 -> [0x00]
    {
        var buf: [16]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try writeVarint(fbs.writer(), 0);
        try std.testing.expectEqualSlices(u8, &[_]u8{0x00}, fbs.getWritten());
    }
    // 1 -> [0x01]
    {
        var buf: [16]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try writeVarint(fbs.writer(), 1);
        try std.testing.expectEqualSlices(u8, &[_]u8{0x01}, fbs.getWritten());
    }
    // 127 -> [0x7F]
    {
        var buf: [16]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try writeVarint(fbs.writer(), 127);
        try std.testing.expectEqualSlices(u8, &[_]u8{0x7F}, fbs.getWritten());
    }
    // 128 -> [0x80, 0x01]
    {
        var buf: [16]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try writeVarint(fbs.writer(), 128);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x80, 0x01 }, fbs.getWritten());
    }
    // 300 -> [0xAC, 0x02]
    {
        var buf: [16]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try writeVarint(fbs.writer(), 300);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAC, 0x02 }, fbs.getWritten());
    }
}

test "postcard: u32 roundtrip" {
    const cases = [_]u32{ 0, 1, 255, 256, 1000, std.math.maxInt(u32) };
    for (cases) |value| {
        var buf: [16]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try writeU32(fbs.writer(), value);
        var rbs = std.io.fixedBufferStream(fbs.getWritten());
        const decoded = try readU32(rbs.reader());
        try std.testing.expectEqual(value, decoded);
    }
}

test "postcard: option roundtrip" {
    const W = std.io.FixedBufferStream([]u8);
    const writeFn = struct {
        fn f(writer: W.Writer, v: u32) anyerror!void {
            return writeU32(writer, v);
        }
    }.f;
    const R = std.io.FixedBufferStream([]const u8);
    const readFn = struct {
        fn f(reader: R.Reader) anyerror!u32 {
            return readU32(reader);
        }
    }.f;

    // Some(42)
    {
        var buf: [16]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try writeOption(fbs.writer(), u32, @as(?u32, 42), writeFn);
        var rbs = std.io.fixedBufferStream(@as([]const u8, fbs.getWritten()));
        const decoded = try readOption(rbs.reader(), u32, readFn);
        try std.testing.expectEqual(@as(?u32, 42), decoded);
    }
    // None
    {
        var buf: [16]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try writeOption(fbs.writer(), u32, @as(?u32, null), writeFn);
        var rbs = std.io.fixedBufferStream(@as([]const u8, fbs.getWritten()));
        const decoded = try readOption(rbs.reader(), u32, readFn);
        try std.testing.expectEqual(@as(?u32, null), decoded);
    }
}
