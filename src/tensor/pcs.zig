//! Ligero/Brakedown-style multilinear commitment over M31 ("tensor PCS").
//!
//! A table of 2^lr rows x 2^lc columns holds an MLE of lr+lc variables; the
//! index is row * 2^lc + col, so the first lr (MSB) variables select the row.
//! Each row (as circle-polynomial coefficients) is Reed-Solomon encoded to
//! 2^(lc+lb) evaluations with stwo's circle FFT; Merkle leaves are columns of
//! the encoded table (Blake2s).
//!
//! Opening a set of claims {f(z_c) = v_c}: claims are grouped by their column
//! part z_col; for each group the prover sends u_g = sum_i a_g[i] row_i with
//! a_g[i] = sum_c gamma_c eq(z_row_c, i). The verifier checks <u_g, eq(z_col)>
//! = sum_c gamma_c v_c and, at t random encoded columns j, that
//! Enc(u_g)[j] = sum_i a_g[i] T[i][j] (column consistency).
//!
//! Proximity: the codeword is tested with a random combination
//! u_prox = sum_i beta_i row_i (checked at the same columns). An opening
//! WITHOUT proximity (consistency queries only) binds its claims only to a
//! table whose proximity was proven earlier, and only at that proof's
//! distance delta: a cheating row passes a query with probability <= rho +
//! delta (security.md 4). Beyond unique decoding a word is close to several
//! codewords, and two openings of one root can decode differently (a table
//! that equals Enc(M1) on half the columns and Enc(M2) on the rest opens as
//! either, ~(1/2)^t per opening). The weights therefore carry an OOD claim
//! fixed by the key, and per-batch weight openings run their own proximity
//! test by default (protocol.Config.weight_proximity, security.md 4.2).
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const f = @import("field.zig");
const Transcript = @import("transcript.zig").Transcript;

const M31 = f.M31;
const QM31 = f.QM31;
const Hash = [32]u8;
const Hasher = core.vcs.blake2_hash.Blake2sHasher;
const circle = engine.poly.circle;
const twiddles = engine.poly.twiddles;

pub const Params = struct {
    log_blowup: u32 = 2,
    n_queries: usize = 64,
    pow_bits: u32 = 20,

    /// Conjectured security (up to capacity, ethSTARK-style): bits per query =
    /// log_blowup. Meaningful only for an opening that runs its own proximity
    /// test and whose decoding is pinned (unique decoding, or an OOD claim);
    /// not for consistency-only openings (see the file header).
    pub fn conjecturedBits(self: Params) f64 {
        return @as(f64, @floatFromInt(self.n_queries * self.log_blowup + self.pow_bits));
    }

    /// Proven unique-decoding bound: proximity parameter delta = (1 - rho)/2
    /// (BCIKS20 correlated agreement); bits = -t log2(1 - delta) + pow.
    pub fn provenBits(self: Params) f64 {
        const rho = 1.0 / @as(f64, @floatFromInt(@as(u64, 1) << @intCast(self.log_blowup)));
        const delta = (1.0 - rho) / 2.0;
        return -@as(f64, @floatFromInt(self.n_queries)) * std.math.log2(1.0 - delta) + @as(f64, @floatFromInt(self.pow_bits));
    }
};

pub const Twiddles = struct {
    tree: twiddles.TwiddleTree([]M31),
    domain: circle.CircleDomain,

    pub fn init(a: std.mem.Allocator, log_ext: u32) !Twiddles {
        const domain = circle.CanonicCoset.new(log_ext).circleDomain();
        const tree = try twiddles.precomputeM31(a, domain.half_coset);
        return .{ .tree = tree, .domain = domain };
    }

    pub fn deinit(self: *Twiddles, a: std.mem.Allocator) void {
        twiddles.deinitM31(a, &self.tree);
    }

    pub fn view(self: *const Twiddles) twiddles.TwiddleTree([]const M31) {
        return .{ .root_coset = self.tree.root_coset, .twiddles = self.tree.twiddles, .itwiddles = self.tree.itwiddles };
    }

    /// In place: buf[0..msg_len] holds coefficients, rest is overwritten.
    pub fn encode(self: *const Twiddles, buf: []M31, msg_len: usize) void {
        self.encodeBatch(&.{buf}, msg_len);
    }

    /// Batched `encode` (all buffers share `msg_len`). For a power-of-two
    /// message shorter than the domain this uses stwo's dyadic-extension FFT,
    /// which skips the degenerate top layers and needs no zero fill; it is
    /// bit-identical to zero-padding + full evaluation.
    pub fn encodeBatch(self: *const Twiddles, bufs: []const []M31, msg_len: usize) void {
        const E = self.domain.size();
        if (msg_len > 0 and msg_len < E and std.math.isPowerOfTwo(msg_len)) {
            circle.transforms.evaluateDyadicExtensionBuffersWithTwiddlesWithPool(bufs, f.log2Exact(msg_len), self.domain, self.view(), null) catch unreachable;
            return;
        }
        for (bufs) |buf| {
            @memset(buf[msg_len..], M31.zero());
            circle.transforms.evaluateBufferWithTwiddles(buf, self.domain, self.view());
        }
    }
};

// ---------------------------------------------------------------------------
// Merkle tree over columns.

pub const Merkle = struct {
    /// nodes[1] = root; leaves at nodes[n_leaves .. 2 n_leaves).
    nodes: []Hash,
    n_leaves: usize,

    pub fn deinit(self: *Merkle, a: std.mem.Allocator) void {
        a.free(self.nodes);
    }

    pub fn root(self: Merkle) Hash {
        return self.nodes[1];
    }

    pub fn path(self: Merkle, out: []Hash, leaf: usize) void {
        var idx = leaf + self.n_leaves;
        var k: usize = 0;
        while (idx > 1) : (idx /= 2) {
            out[k] = self.nodes[idx ^ 1];
            k += 1;
        }
    }
};

pub fn hashNode(l: Hash, r: Hash) Hash {
    var buf: [64]u8 = undefined;
    @memcpy(buf[0..32], &l);
    @memcpy(buf[32..64], &r);
    return Hasher.hash(&buf);
}

pub fn hashColumn(col: []const M31) Hash {
    return Hasher.hash(std.mem.sliceAsBytes(col));
}

pub fn verifyPath(root_h: Hash, leaf_h: Hash, leaf: usize, log_leaves: u32, sibs: []const Hash) bool {
    if (sibs.len != log_leaves) return false;
    var h = leaf_h;
    var idx = leaf;
    for (sibs) |s| {
        h = if (idx & 1 == 0) hashNode(h, s) else hashNode(s, h);
        idx >>= 1;
    }
    return std.mem.eql(u8, &h, &root_h);
}

// ---------------------------------------------------------------------------
// Commitment.

/// Optional device implementation of `combineRows` for one committed table
/// (set by a device commit; null = CPU). Must return the same field values.
pub const CombineHook = struct {
    ctx: *anyopaque,
    i8: *const fn (ctx: *anyopaque, a: std.mem.Allocator, m: Matrix(i8), coeffs: []const []const QM31) anyerror!?[][]QM31,
    i32: *const fn (ctx: *anyopaque, a: std.mem.Allocator, m: Matrix(i32), coeffs: []const []const QM31) anyerror!?[][]QM31,
};

/// Owner of a codeword that is not allocator memory (e.g. a device buffer
/// in unified memory); `release` frees it.
pub const EncOwner = struct {
    ctx: *anyopaque,
    handle: *anyopaque,
    release: *const fn (ctx: *anyopaque, handle: *anyopaque) void,
};

pub const Committed = struct {
    combine: ?CombineHook = null,
    enc_owner: ?EncOwner = null,
    log_rows: u32,
    log_cols: u32,
    log_blowup: u32,
    /// rows >= rows_used are zero and not committed (columns have rows_used entries)
    rows_used: usize,
    /// encoded table, column-major: col j occupies enc[j*R .. (j+1)*R)
    enc: []M31,
    tree: Merkle,

    pub fn deinit(self: *Committed, a: std.mem.Allocator) void {
        if (self.enc_owner) |o| o.release(o.ctx, o.handle) else a.free(self.enc);
        self.tree.deinit(a);
    }

    pub fn nRows(self: Committed) usize {
        return @as(usize, 1) << @intCast(self.log_rows);
    }
    pub fn nCols(self: Committed) usize {
        return @as(usize, 1) << @intCast(self.log_cols);
    }
    pub fn logExt(self: Committed) u32 {
        return self.log_cols + self.log_blowup;
    }
    pub fn column(self: Committed, j: usize) []const M31 {
        const r = self.rows_used;
        return self.enc[j * r .. (j + 1) * r];
    }
    pub fn root(self: Committed) Hash {
        return self.tree.root();
    }
};

/// Row-major message matrix of small integers (any signed int type).
pub fn Matrix(comptime T: type) type {
    return struct {
        data: []const T,
        log_rows: u32,
        log_cols: u32,
        /// rows at or beyond this index are zero (null = all rows)
        rows_used: ?usize = null,

        pub fn usedRows(self: @This()) usize {
            return self.rows_used orelse self.nRows();
        }

        pub fn nRows(self: @This()) usize {
            return @as(usize, 1) << @intCast(self.log_rows);
        }
        pub fn nCols(self: @This()) usize {
            return @as(usize, 1) << @intCast(self.log_cols);
        }
        pub fn row(self: @This(), i: usize) []const T {
            const c = self.nCols();
            return self.data[i * c .. (i + 1) * c];
        }
    };
}

pub fn commit(comptime T: type, a: std.mem.Allocator, pool: *f.Pool, tw: *const Twiddles, m: Matrix(T), log_blowup: u32) !Committed {
    const R = m.usedRows();
    const C = m.nCols();
    const log_ext = m.log_cols + log_blowup;
    const E = @as(usize, 1) << @intCast(log_ext);
    std.debug.assert(tw.domain.logSize() == log_ext);
    const enc = try a.alloc(M31, R * E);
    errdefer a.free(enc);

    // Encode blocks of BR rows into scratch, then write each column's BR
    // values contiguously into column-major storage.
    const BR = 16;
    const EncCtx = struct { m: Matrix(T), enc: []M31, tw: *const Twiddles, E: usize, C: usize, R: usize };
    const ectx = EncCtx{ .m = m, .enc = enc, .tw = tw, .E = E, .C = C, .R = R };
    const n_blocks = (R + BR - 1) / BR;
    pool.parallelFor(n_blocks, 1, &ectx, struct {
        fn run(c: *const EncCtx, s: usize, e: usize) void {
            const buf = std.heap.page_allocator.alloc(M31, c.E * BR) catch @panic("oom");
            defer std.heap.page_allocator.free(buf);
            for (s..e) |blk| {
                const r0 = blk * BR;
                const r1 = @min(c.R, r0 + BR);
                const nb = r1 - r0;
                var views: [BR][]M31 = undefined;
                for (0..nb) |bi| {
                    const row = c.m.row(r0 + bi);
                    const rb = buf[bi * c.E .. (bi + 1) * c.E];
                    for (row, 0..) |v, j| rb[j] = f.fromI32(@intCast(v));
                    views[bi] = rb;
                }
                c.tw.encodeBatch(views[0..nb], c.C);
                for (0..c.E) |j| {
                    const dst = c.enc[j * c.R + r0 ..][0..nb];
                    for (0..nb) |bi| dst[bi] = buf[bi * c.E + j];
                }
            }
        }
    }.run);

    const tree = try buildTree(a, pool, enc, R, E);
    return .{ .log_rows = m.log_rows, .log_cols = m.log_cols, .log_blowup = log_blowup, .rows_used = R, .enc = enc, .tree = tree };
}

fn buildTree(a: std.mem.Allocator, pool: *f.Pool, enc: []const M31, R: usize, E: usize) !Merkle {
    const nodes = try a.alloc(Hash, 2 * E);
    const LCtx = struct { enc: []const M31, nodes: []Hash, R: usize, E: usize };
    const lctx = LCtx{ .enc = enc, .nodes = nodes, .R = R, .E = E };
    // Leaves: four columns per call through stwo's 4-lane SIMD Blake2s
    // (`hashEqual4WithMode`), which yields exactly the scalar Blake2s digests
    // (pinned by the proof-digest test). Work items are groups of 4 columns.
    const n_groups = (E + 3) / 4;
    pool.parallelFor(n_groups, 16, &lctx, struct {
        fn run(c: *const LCtx, s: usize, e: usize) void {
            for (s..e) |g| {
                const j0 = g * 4;
                if (j0 + 4 <= c.E) {
                    var msgs: [4][]const u8 = undefined;
                    for (0..4) |l| msgs[l] = std.mem.sliceAsBytes(c.enc[(j0 + l) * c.R .. (j0 + l + 1) * c.R]);
                    const hs = Hasher.hashEqual4WithMode(.auto, &msgs);
                    @memcpy(c.nodes[c.E + j0 ..][0..4], &hs);
                } else {
                    for (j0..c.E) |j| c.nodes[c.E + j] = hashColumn(c.enc[j * c.R .. (j + 1) * c.R]);
                }
            }
        }
    }.run);
    var level = E / 2;
    while (level >= 1) : (level /= 2) {
        const NCtx = struct { nodes: []Hash, base: usize };
        const nctx = NCtx{ .nodes = nodes, .base = level };
        pool.parallelFor(level, 256, &nctx, struct {
            fn run(c: *const NCtx, s: usize, e: usize) void {
                var k = s;
                // children of 4 consecutive parents are 4 contiguous 64-byte blocks
                while (k + 4 <= e) : (k += 4) {
                    const idx = c.base + k;
                    const blocks: *const [4][64]u8 = @ptrCast(&c.nodes[2 * idx]);
                    const hs = Hasher.hashFixedSingleBlock4(64, blocks);
                    @memcpy(c.nodes[idx..][0..4], &hs);
                }
                while (k < e) : (k += 1) {
                    const idx = c.base + k;
                    c.nodes[idx] = hashNode(c.nodes[2 * idx], c.nodes[2 * idx + 1]);
                }
            }
        }.run);
        if (level == 1) break;
    }
    return .{ .nodes = nodes, .n_leaves = E };
}

// ---------------------------------------------------------------------------
// Row combinations u = sum_i a[i] row_i (QM31 coefficients, integer rows).

/// out[g][col] = sum_i coeffs[g][i] * m[i][col]. Exact integer accumulation per
/// limb (|m| < 2^15, R < 2^16 keeps |acc| < 2^62), reduced once per column.
pub fn combineRows(comptime T: type, a: std.mem.Allocator, pool: *f.Pool, m: Matrix(T), coeffs: []const []const QM31, bound_log2: u32) ![][]QM31 {
    const C = m.nCols();
    const R = m.usedRows();
    const G = coeffs.len;
    const out = try a.alloc([]QM31, G);
    for (out) |*o| o.* = try a.alloc(QM31, C);
    // limb planes of coefficients: [g][limb][i]
    const planes = try a.alloc(u32, G * 4 * R);
    defer a.free(planes);
    for (coeffs, 0..) |cg, g| {
        for (cg[0..R], 0..) |c, i| {
            const l = f.limbs(c);
            for (0..4) |k| planes[(g * 4 + k) * R + i] = l[k];
        }
    }
    const TILE = 64;
    const Ctx = struct { m: Matrix(T), planes: []const u32, out: [][]QM31, G: usize, R: usize, C: usize, bound_log2: u32 };
    const ctx = Ctx{ .m = m, .planes = planes, .out = out, .G = G, .R = R, .C = C, .bound_log2 = bound_log2 };
    const n_tiles = (C + TILE - 1) / TILE;
    pool.parallelFor(n_tiles, 1, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |tile| {
                const c0 = tile * TILE;
                const c1 = @min(c.C, c0 + TILE);
                const w = c1 - c0;
                for (0..c.G) |g| {
                    var acc: [4][TILE]i64 = undefined;
                    for (&acc) |*row| @memset(row, 0);
                    // |limb * v| < 2^(31 + bound); reduce before 2^62.
                    const chunk_rows: usize = @as(usize, 1) << @intCast(31 - @min(@as(u32, 30), c.bound_log2));
                    var since: usize = 0;
                    for (0..c.R) |i| {
                        const row = c.m.row(i)[c0..c1];
                        inline for (0..4) |k| {
                            const lv: i64 = c.planes[(g * 4 + k) * c.R + i];
                            if (lv != 0) {
                                for (0..w) |j| acc[k][j] += lv * @as(i64, row[j]);
                            }
                        }
                        since += 1;
                        if (since == chunk_rows) {
                            since = 0;
                            for (&acc) |*arow| for (arow[0..w]) |*x| {
                                x.* = @rem(x.*, @as(i64, f.P));
                            };
                        }
                    }
                    for (0..w) |j| {
                        c.out[g][c0 + j] = f.fromLimbs(.{ f.reduceI64(acc[0][j]), f.reduceI64(acc[1][j]), f.reduceI64(acc[2][j]), f.reduceI64(acc[3][j]) });
                    }
                }
            }
        }
    }.run);
    return out;
}

/// Encode a QM31 message (coordinate-wise) and return encoded QM31 values.
pub fn encodeSecure(a: std.mem.Allocator, tw: *const Twiddles, msg: []const QM31) ![]QM31 {
    const E = tw.domain.size();
    const out = try a.alloc(QM31, E);
    var coord: [4][]M31 = undefined;
    for (&coord) |*c| c.* = try a.alloc(M31, E);
    defer for (coord) |c| a.free(c);
    for (msg, 0..) |v, j| {
        const l = f.limbs(v);
        inline for (0..4) |k| coord[k][j] = M31.fromU32Unchecked(l[k]);
    }
    tw.encodeBatch(&coord, msg.len);
    for (0..E) |j| out[j] = f.fromLimbs(.{ coord[0][j].v, coord[1][j].v, coord[2][j].v, coord[3][j].v });
    return out;
}

// ---------------------------------------------------------------------------
// Opening proofs.

pub const Claim = struct {
    point: []const QM31, // log_rows + log_cols coordinates, MSB first
    value: QM31,
};

pub const OpenedColumn = struct {
    index: usize,
    values: []M31,
    path: []Hash,
};

pub const OpeningProof = struct {
    /// one combined row per claim group (groups ordered as given), plus the
    /// proximity row first when proximity is included.
    rows: [][]QM31,
    pow_nonce: u64,
    columns: []OpenedColumn,

    pub fn deinit(self: *OpeningProof, a: std.mem.Allocator) void {
        for (self.rows) |r| a.free(r);
        a.free(self.rows);
        for (self.columns) |c| {
            a.free(c.values);
            a.free(c.path);
        }
        a.free(self.columns);
    }

    pub fn byteSize(self: OpeningProof) usize {
        var s: usize = 8;
        for (self.rows) |r| s += r.len * 16;
        for (self.columns) |c| s += 8 + c.values.len * 4 + c.path.len * 32;
        return s;
    }
};

/// Claims are grouped: all claims in a group share the column part of their point.
pub const Group = struct { claims: []const Claim };

fn groupCoeffs(a: std.mem.Allocator, log_rows: u32, group: Group, gammas: []const QM31) ![]QM31 {
    const R = @as(usize, 1) << @intCast(log_rows);
    const out = try a.alloc(QM31, R);
    @memset(out, QM31.zero());
    for (group.claims, gammas) |c, g| {
        const eq = try f.eqTable(a, c.point[0..log_rows], g);
        defer a.free(eq);
        for (out, eq) |*o, e| o.* = o.add(e);
    }
    return out;
}

fn drawGammas(a: std.mem.Allocator, tr: *Transcript, groups: []const Group) ![][]QM31 {
    for (groups) |g| for (g.claims) |c| tr.mixFelt(c.value);
    const out = try a.alloc([]QM31, groups.len);
    for (groups, 0..) |g, gi| {
        out[gi] = try a.alloc(QM31, g.claims.len);
        tr.drawN(out[gi]);
    }
    return out;
}

fn freeNested(a: std.mem.Allocator, x: anytype) void {
    for (x) |v| a.free(v);
    a.free(x);
}

pub fn open(
    comptime T: type,
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    params: Params,
    com: *const Committed,
    m: Matrix(T),
    groups: []const Group,
    with_proximity: bool,
) !OpeningProof {
    const R = com.nRows();
    const gammas = try drawGammas(a, tr, groups);
    defer freeNested(a, gammas);
    const n_rows_out = groups.len + @intFromBool(with_proximity);
    const coeffs = try a.alloc([]QM31, n_rows_out);
    defer freeNested(a, coeffs);
    var k: usize = 0;
    if (with_proximity) {
        coeffs[0] = try a.alloc(QM31, R);
        tr.drawN(coeffs[0]);
        k = 1;
    }
    for (groups, 0..) |g, gi| coeffs[k + gi] = try groupCoeffs(a, com.log_rows, g, gammas[gi]);
    const cview = try a.alloc([]const QM31, n_rows_out);
    defer a.free(cview);
    for (coeffs, 0..) |c, i| cview[i] = c;
    const dev_rows: ?[][]QM31 = if (com.combine) |h| switch (T) {
        i8 => try h.i8(h.ctx, a, m, cview),
        i32 => try h.i32(h.ctx, a, m, cview),
        else => null,
    } else null;
    const rows = dev_rows orelse try combineRows(T, a, pool, m, cview, if (@bitSizeOf(T) <= 8) 7 else 30);
    for (rows) |r| tr.mixFelts(r);
    const nonce = tr.grind(params.pow_bits);
    const idx = try a.alloc(usize, params.n_queries);
    defer a.free(idx);
    tr.drawIndices(com.logExt(), idx);
    const cols = try a.alloc(OpenedColumn, params.n_queries);
    for (idx, 0..) |j, q| {
        const path = try a.alloc(Hash, com.logExt());
        com.tree.path(path, j);
        cols[q] = .{ .index = j, .values = try a.dupe(M31, com.column(j)), .path = path };
    }
    return .{ .rows = rows, .pow_nonce = nonce, .columns = cols };
}

pub const Shape = struct { log_rows: u32, log_cols: u32, log_blowup: u32, rows_used: ?usize = null };

pub fn verifyOpening(
    a: std.mem.Allocator,
    tr: *Transcript,
    params: Params,
    tw: *const Twiddles,
    shape: Shape,
    root_h: Hash,
    groups: []const Group,
    with_proximity: bool,
    proof: OpeningProof,
) !void {
    const R = @as(usize, 1) << @intCast(shape.log_rows);
    const RU = shape.rows_used orelse R;
    if (RU > R) return error.OpeningShape;
    const C = @as(usize, 1) << @intCast(shape.log_cols);
    const log_ext = shape.log_cols + shape.log_blowup;
    // every point must have the table's arity before any slicing (PCS-4)
    for (groups) |g| for (g.claims) |c| if (c.point.len != shape.log_rows + shape.log_cols) return error.OpeningShape;
    const gammas = try drawGammas(a, tr, groups);
    defer freeNested(a, gammas);
    const n_rows_out = groups.len + @intFromBool(with_proximity);
    if (proof.rows.len != n_rows_out) return error.OpeningShape;
    const coeffs = try a.alloc([]QM31, n_rows_out);
    defer freeNested(a, coeffs);
    var k: usize = 0;
    if (with_proximity) {
        coeffs[0] = try a.alloc(QM31, R);
        tr.drawN(coeffs[0]);
        k = 1;
    }
    for (groups, 0..) |g, gi| coeffs[k + gi] = try groupCoeffs(a, shape.log_rows, g, gammas[gi]);
    for (proof.rows) |r| {
        if (r.len != C) return error.OpeningShape;
        tr.mixFelts(r);
    }
    // evaluation checks
    for (groups, 0..) |g, gi| {
        if (g.claims.len == 0) continue;
        const zc = g.claims[0].point[shape.log_rows..];
        for (g.claims) |c| {
            if (c.point.len != shape.log_rows + shape.log_cols) return error.OpeningShape;
            for (c.point[shape.log_rows..], zc) |x, y| if (!x.eql(y)) return error.OpeningGroupMismatch;
        }
        const eqc = try f.eqTable(a, zc, QM31.one());
        defer a.free(eqc);
        var lhs = QM31.zero();
        for (proof.rows[k + gi], eqc) |u, e| lhs = lhs.add(u.mul(e));
        var rhs = QM31.zero();
        for (g.claims, gammas[gi]) |c, gm| rhs = rhs.add(gm.mul(c.value));
        if (!lhs.eql(rhs)) return error.OpeningEvalMismatch;
    }
    if (!tr.verifyPow(params.pow_bits, proof.pow_nonce)) return error.OpeningPow;
    const idx = try a.alloc(usize, params.n_queries);
    defer a.free(idx);
    tr.drawIndices(log_ext, idx);
    if (proof.columns.len != params.n_queries) return error.OpeningShape;
    const encs = try a.alloc([]QM31, n_rows_out);
    defer freeNested(a, encs);
    for (proof.rows, 0..) |r, i| encs[i] = try encodeSecure(a, tw, r);
    for (proof.columns, idx) |col, j| {
        if (col.index != j or col.values.len != RU) return error.OpeningShape;
        if (!verifyPath(root_h, hashColumn(col.values), j, log_ext, col.path)) return error.OpeningMerkle;
        for (coeffs, 0..) |cf, i| {
            var acc = QM31.zero();
            for (cf[0..RU], col.values) |c, v| acc = acc.add(c.mulM31(v));
            if (!acc.eql(encs[i][j])) return error.OpeningColumnMismatch;
        }
    }
}

test "pcs commit/open/verify with proximity and rejection" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const lr = 4;
    const lc = 6;
    const R = 1 << lr;
    const C = 1 << lc;
    const data = try a.alloc(i8, R * C);
    defer a.free(data);
    var prng = std.Random.DefaultPrng.init(7);
    for (data) |*d| d.* = prng.random().int(i8);
    const m = Matrix(i8){ .data = data, .log_rows = lr, .log_cols = lc };
    var tw = try Twiddles.init(a, lc + 2);
    defer tw.deinit(a);
    var com = try commit(i8, a, &pool, &tw, m, 2);
    defer com.deinit(a);
    const params = Params{ .log_blowup = 2, .n_queries = 20, .pow_bits = 4 };
    // two claims sharing column point, one separate
    var pts: [3][lr + lc]QM31 = undefined;
    for (0..3) |c| for (0..lr + lc) |i| {
        pts[c][i] = QM31.fromU32Unchecked(@intCast(c * 31 + i * 7 + 1), @intCast(i), 3, @intCast(c));
    };
    for (0..lc) |i| pts[1][lr + i] = pts[0][lr + i];
    var vals: [3]QM31 = undefined;
    const ints = try a.alloc(i32, R * C);
    defer a.free(ints);
    for (data, ints) |d, *x| x.* = d;
    for (0..3) |c| vals[c] = try f.mleEvalI32(a, ints, &pts[c]);
    const g0 = [_]Claim{ .{ .point = &pts[0], .value = vals[0] }, .{ .point = &pts[1], .value = vals[1] } };
    const g1 = [_]Claim{.{ .point = &pts[2], .value = vals[2] }};
    const groups = [_]Group{ .{ .claims = &g0 }, .{ .claims = &g1 } };
    var tp = Transcript.initDomain("pcs");
    var proof = try open(i8, a, &pool, &tp, params, &com, m, &groups, true);
    defer proof.deinit(a);
    const shape = Shape{ .log_rows = lr, .log_cols = lc, .log_blowup = 2 };
    var tv = Transcript.initDomain("pcs");
    try verifyOpening(a, &tv, params, &tw, shape, com.root(), &groups, true, proof);
    // wrong value rejected
    const bad = [_]Claim{.{ .point = &pts[2], .value = vals[2].add(QM31.one()) }};
    const groups_bad = [_]Group{ .{ .claims = &g0 }, .{ .claims = &bad } };
    var tv2 = Transcript.initDomain("pcs");
    try std.testing.expectError(error.OpeningEvalMismatch, verifyOpening(a, &tv2, params, &tw, shape, com.root(), &groups_bad, true, proof));
    // tampered column rejected
    proof.columns[3].values[1] = proof.columns[3].values[1].add(M31.one());
    var tv3 = Transcript.initDomain("pcs");
    try std.testing.expectError(error.OpeningMerkle, verifyOpening(a, &tv3, params, &tw, shape, com.root(), &groups, true, proof));
}
