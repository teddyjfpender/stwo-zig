//! M9 (default-off, STWO_RV64_M9_POSEIDON2_LEAVES) CPU reference for
//! Poseidon2-M31-W24 lifted Merkle leaves with the SAME layout contract as the
//! CUDA Blake2s `mixed_leaf_kernel` (src/backends/cuda/native/commitment/
//! progressive.cu, MixedSegment in mixed_layout.h):
//!   * a leaf domain of `1 << log_size` rows;
//!   * an ordered list of segments, each `n_columns` column-major columns of
//!     `1 << source_log_size` canonical M31 words with `stride_words` between
//!     columns (stride >= rows);
//!   * leaf row r reads source row `liftedIndex(r, log_size - source_log_size)`
//!     of every segment (the lifted-VCS map used by prover/vcs_lifted/leaves.zig);
//!   * words are absorbed in segment order, column order, into the experimental
//!     M7 sponge (crypto/poseidon2_m31_sponge.zig: rate 12, capacity 12, leaf
//!     domain, additive absorption, mandatory 1-marker, 9-limb digest), i.e.
//!     byte-identical to vcs/poseidon2_m31_merkle.zig `updateLeaf`/`finalize`.
//! Seeded chaining (the Blake "eager prefix bank" analogue): a call may start
//! from per-row sponge states at a smaller power-of-two `seed_size` (lifted to
//! `log_size` by the same map) after `absorbed_before` words, and may emit
//! its own prefix states instead of digests. A P2 prefix state is the 24-limb
//! sponge state; the absorb position is `absorbed % 12` and is owned by the
//! caller, so no pending words exist (full rate blocks are permuted eagerly,
//! exactly as Sponge.absorb does).
//! This is a numerical substrate only: no PCS, channel or profile selects it.
const std = @import("std");
const F = @import("../fields/m31.zig");
const S = @import("../crypto/poseidon2_m31_sponge.zig");
const P = @import("../crypto/poseidon2_m31_w24.zig");
const H = @import("../vcs/poseidon2_m31_merkle.zig").Poseidon2M31MerkleHasher;
pub const M31 = F.M31;
pub const RATE = S.RATE;
pub const STATE_WORDS = P.WIDTH;
pub const DIGEST_WORDS = S.DIGEST_WORDS;
pub const FLAG = "STWO_RV64_M9_POSEIDON2_LEAVES";

/// Default-off switch for the future integration (see design doc). Nothing in
/// the prover reads it yet; it exists so every call site uses one name.
pub fn enabled() bool {
    const value = std.posix.getenv(FLAG) orelse return false;
    return std.mem.eql(u8, value, "1");
}

pub const Segment = struct {
    columns: []const u32,
    stride_words: usize,
    n_columns: u32,
    source_log_size: u5,
};

pub const Error = error{ InvalidGeometry, NonCanonicalInput };

pub inline fn liftedIndex(row: usize, log_ratio: u5) usize {
    if (log_ratio == 0) return row;
    return ((row >> (@as(u6, log_ratio) + 1)) << 1) | (row & 1);
}

pub fn validate(log_size: u5, segments: []const Segment, absorbed_before: u32, seed_log_size: ?u5) Error!u64 {
    if (log_size < 1 or log_size > 28) return error.InvalidGeometry;
    var words: u64 = absorbed_before;
    for (segments) |segment| {
        if (segment.source_log_size < 1 or segment.source_log_size > log_size) return error.InvalidGeometry;
        const rows = @as(usize, 1) << segment.source_log_size;
        if (segment.stride_words < rows) return error.InvalidGeometry;
        if (segment.n_columns != 0 and segment.columns.len < (segment.n_columns - 1) * segment.stride_words + rows)
            return error.InvalidGeometry;
        words += segment.n_columns;
    }
    if (seed_log_size) |seed| {
        if (absorbed_before == 0 or seed < 1 or seed > log_size) return error.InvalidGeometry;
    } else if (absorbed_before != 0) return error.InvalidGeometry;
    if (words > std.math.maxInt(u32)) return error.InvalidGeometry;
    return words;
}

/// The sponge state of one leaf row after absorbing every segment word.
pub fn absorbRow(sponge: *S.Sponge, log_size: u5, segments: []const Segment, row: usize) Error!void {
    for (segments) |segment| {
        const source_row = liftedIndex(row, log_size - segment.source_log_size);
        for (0..segment.n_columns) |column| {
            const word = segment.columns[column * segment.stride_words + source_row];
            if (word >= F.Modulus) return error.NonCanonicalInput;
            sponge.absorb(M31.fromCanonical(word));
        }
    }
}

pub fn seededSponge(seed: ?[]const [STATE_WORDS]u32, seed_log_size: u5, log_size: u5, absorbed_before: u32, row: usize) S.Sponge {
    if (seed) |states| {
        const state = states[liftedIndex(row, log_size - seed_log_size)];
        var sponge = S.Sponge.init(.leaf);
        for (&sponge.state, state) |*limb, word| limb.* = M31.fromCanonical(word);
        sponge.at = absorbed_before % RATE;
        return sponge;
    }
    return S.Sponge.init(.leaf);
}

/// Digest (9 canonical limbs) for each requested row.
pub fn hashRows(
    log_size: u5,
    segments: []const Segment,
    absorbed_before: u32,
    seed: ?[]const [STATE_WORDS]u32,
    seed_log_size: u5,
    rows: []const usize,
    out: [][DIGEST_WORDS]u32,
) Error!void {
    _ = try validate(log_size, segments, absorbed_before, if (seed != null) seed_log_size else null);
    for (rows, out) |row, *digest| {
        var sponge = seededSponge(seed, seed_log_size, log_size, absorbed_before, row);
        try absorbRow(&sponge, log_size, segments, row);
        for (sponge.finish(), digest) |limb, *word| word.* = limb.v;
    }
}

/// Prefix (unfinalized) 24-limb states for each requested row.
pub fn prefixRows(
    log_size: u5,
    segments: []const Segment,
    absorbed_before: u32,
    seed: ?[]const [STATE_WORDS]u32,
    seed_log_size: u5,
    rows: []const usize,
    out: [][STATE_WORDS]u32,
) Error!void {
    _ = try validate(log_size, segments, absorbed_before, if (seed != null) seed_log_size else null);
    for (rows, out) |row, *state| {
        var sponge = seededSponge(seed, seed_log_size, log_size, absorbed_before, row);
        try absorbRow(&sponge, log_size, segments, row);
        for (sponge.state, state) |limb, *word| word.* = limb.v;
    }
}

/// Node compression of the existing experimental family (2 permutations).
pub fn hashParent(left: [DIGEST_WORDS]u32, right: [DIGEST_WORDS]u32) [DIGEST_WORDS]u32 {
    var sponge = S.Sponge.init(.node);
    for (left ++ right) |word| sponge.absorb(M31.fromCanonical(word));
    var out: [DIGEST_WORDS]u32 = undefined;
    for (sponge.finish(), &out) |limb, *word| word.* = limb.v;
    return out;
}

/// Deterministic test-column generator shared with the CUDA harness
/// (tests/cuda/rv64/m9_poseidon2/m9_poseidon2_leaves.cu): canonical, never equal to p.
pub fn columnWord(seed: u64, column: u64, row: u64) u32 {
    var z = (seed << 40) ^ (column << 24) ^ row;
    z +%= 0x9e3779b97f4a7c15;
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    z ^= z >> 31;
    const v: u32 = @truncate(z >> 33);
    return if (v == F.Modulus) 0 else v;
}

// ---------------------------------------------------------------- tests

/// Independent model: the expansion algorithm of prover/vcs_lifted/leaves.zig
/// (clone the previous height's hasher into the larger layer, then absorb that
/// height's columns), run with the generic Poseidon2 Merkle hasher.
fn expansionModel(allocator: std.mem.Allocator, sorted: []const Segment) ![][DIGEST_WORDS]u32 {
    var prev = try allocator.alloc(H, 2);
    defer allocator.free(prev);
    prev[0] = H.defaultWithInitialState();
    prev[1] = prev[0];
    var prev_log: u5 = 1;
    for (sorted) |segment| {
        if (segment.source_log_size != prev_log) {
            const ratio: u6 = segment.source_log_size - prev_log;
            const size = @as(usize, 1) << segment.source_log_size;
            const expanded = try allocator.alloc(H, size);
            for (0..size) |idx| expanded[idx] = prev[((idx >> (ratio + 1)) << 1) + (idx & 1)];
            allocator.free(prev);
            prev = expanded;
            prev_log = segment.source_log_size;
        }
        var values = try allocator.alloc(M31, segment.n_columns);
        defer allocator.free(values);
        for (prev, 0..) |*hasher, row| {
            for (0..segment.n_columns) |c| values[c] = M31.fromCanonical(segment.columns[c * segment.stride_words + row]);
            hasher.updateLeaf(values);
        }
    }
    const out = try allocator.alloc([DIGEST_WORDS]u32, prev.len);
    for (prev, out) |hasher, *digest| digest.* = decodeWords(S.decode(hasher.finalize()) catch unreachable);
    return out;
}

fn decodeWords(values: [DIGEST_WORDS]M31) [DIGEST_WORDS]u32 {
    var out: [DIGEST_WORDS]u32 = undefined;
    for (values, &out) |v, *w| w.* = v.v;
    return out;
}

const TestShape = struct { logs: []const u5, widths: []const u32 };

fn buildColumns(allocator: std.mem.Allocator, shape: TestShape, seed: u64, pad: usize) ![]Segment {
    const segments = try allocator.alloc(Segment, shape.logs.len);
    var column_id: u64 = 0;
    for (segments, shape.logs, shape.widths) |*segment, log, width| {
        const rows = @as(usize, 1) << log;
        const stride = rows + pad;
        const data = try allocator.alloc(u32, @max(1, width) * stride);
        @memset(data, F.Modulus); // poison padding; must never be read
        for (0..width) |c| {
            for (0..rows) |r| data[c * stride + r] = columnWord(seed, column_id, r);
            column_id += 1;
        }
        segment.* = .{ .columns = data, .stride_words = stride, .n_columns = width, .source_log_size = log };
    }
    return segments;
}

test "mixed-segment P2 leaves equal the lifted expansion model over random shapes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const shapes = [_]TestShape{
        .{ .logs = &.{3}, .widths = &.{1} },
        .{ .logs = &.{4}, .widths = &.{12} },
        .{ .logs = &.{4}, .widths = &.{13} },
        .{ .logs = &.{5}, .widths = &.{24} },
        .{ .logs = &.{ 2, 4, 4, 6 }, .widths = &.{ 5, 7, 12, 1 } },
        .{ .logs = &.{ 1, 3, 6, 7 }, .widths = &.{ 11, 25, 3, 40 } },
        .{ .logs = &.{ 6, 6, 6 }, .widths = &.{ 199, 0, 1 } },
    };
    for (shapes, 0..) |shape, i| {
        const segments = try buildColumns(a, shape, 1000 + i, i % 3);
        const log_size = shape.logs[shape.logs.len - 1];
        const rows = @as(usize, 1) << log_size;
        const expected = try expansionModel(a, segments);
        const indices = try a.alloc(usize, rows);
        for (indices, 0..) |*x, r| x.* = r;
        const actual = try a.alloc([DIGEST_WORDS]u32, rows);
        try hashRows(log_size, segments, 0, null, 0, indices, actual);
        for (expected, actual) |e, g| try std.testing.expectEqualSlices(u32, &e, &g);
        // Same digests as the experimental Merkle hasher on a gathered row.
        var leaf = H.defaultWithInitialState();
        for (segments) |segment| for (0..segment.n_columns) |c| {
            const src = liftedIndex(rows - 1, log_size - segment.source_log_size);
            leaf.updateLeaf(&.{M31.fromCanonical(segment.columns[c * segment.stride_words + src])});
        };
        try std.testing.expectEqualSlices(u32, &actual[rows - 1], &decodeWords(try S.decode(leaf.finalize())));
    }
}

test "seeded prefix chaining equals a single call at every split" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const shape = TestShape{ .logs = &.{ 2, 3, 3, 5, 6 }, .widths = &.{ 9, 12, 4, 17, 6 } };
    const segments = try buildColumns(a, shape, 77, 1);
    const log_size: u5 = 6;
    const rows = @as(usize, 1) << log_size;
    const indices = try a.alloc(usize, rows);
    for (indices, 0..) |*x, r| x.* = r;
    const whole = try a.alloc([DIGEST_WORDS]u32, rows);
    try hashRows(log_size, segments, 0, null, 0, indices, whole);
    for (1..segments.len) |split| {
        const first = segments[0..split];
        const seed_log = first[first.len - 1].source_log_size;
        var absorbed: u32 = 0;
        for (first) |s| absorbed += s.n_columns;
        const seed_rows = @as(usize, 1) << seed_log;
        const seed = try a.alloc([STATE_WORDS]u32, seed_rows);
        try prefixRows(seed_log, first, 0, null, 0, indices[0..seed_rows], seed);
        const chained = try a.alloc([DIGEST_WORDS]u32, rows);
        try hashRows(log_size, segments[split..], absorbed, seed, seed_log, indices, chained);
        for (whole, chained) |w, c| try std.testing.expectEqualSlices(u32, &w, &c);
    }
    // Non-canonical inputs are refused, never reduced.
    var bad = [_]u32{ 1, F.Modulus };
    const bad_segment = [_]Segment{.{ .columns = &bad, .stride_words = 2, .n_columns = 1, .source_log_size = 1 }};
    var out: [2][DIGEST_WORDS]u32 = undefined;
    try std.testing.expectError(error.NonCanonicalInput, hashRows(1, &bad_segment, 0, null, 0, &.{ 0, 1 }, &out));
}

test "parent compression matches the experimental Merkle hasher and pinned fingerprint" {
    var left: [DIGEST_WORDS]u32 = undefined;
    var right: [DIGEST_WORDS]u32 = undefined;
    for (&left, &right, 0..) |*l, *r, i| {
        l.* = columnWord(5, 0, i);
        r.* = columnWord(5, 1, i);
    }
    const expected = try S.decode(H.hashChildren(.{ .left = S.encode(toM31(left)), .right = S.encode(toM31(right)) }));
    try std.testing.expectEqualSlices(u32, &decodeWords(expected), &hashParent(left, right));
    // Generator fingerprint pinned for the CUDA harness.
    try std.testing.expectEqual(@as(u32, columnWord(1, 2, 3)), columnWord(1, 2, 3));
}

fn toM31(words: [DIGEST_WORDS]u32) [DIGEST_WORDS]M31 {
    var out: [DIGEST_WORDS]M31 = undefined;
    for (words, &out) |w, *v| v.* = M31.fromCanonical(w);
    return out;
}
