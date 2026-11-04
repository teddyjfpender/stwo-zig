//! Hiding (zero-knowledge) variant of the tensor PCS.
//!
//! Differences from `pcs.zig` (see design/tensor-frontend/zk.md for the
//! argument):
//!
//!  * Masked encoding. Each committed row is the circle-polynomial with the
//!    row's C cells as its first C coefficients followed by `slots` fresh
//!    uniform coefficients (tau), RS-encoded to E = 2^(lc+lb) points. The span
//!    of the slot basis elements is pi^(lc-1)(x) * L_slots, which restricted to
//!    any set of at most slots/2 domain points is onto, so any slots/2 opened
//!    columns are uniform and independent of the message. Opening budget =
//!    slots/2 distinct columns per commitment over its whole lifetime.
//!  * Salted leaves: leaf_j = Blake2s(column_j || salt_j), 32-byte salts from an
//!    OS-seeded ChaCha20 stream; a salt is revealed only with its column.
//!  * Masked combined rows: every revealed combination u = sum_i A_i row_i (the
//!    proximity row and each claim group) includes 4 dedicated, otherwise
//!    unused mask rows M_0..M_3 with coefficient c * e_k (e_k the QM31 basis
//!    over M31, c != 0 a challenge), so u is uniform given the checks. For a
//!    claim group, mu = sum_k e_k <M_k, b> is sent before the batching
//!    challenges and is batched as one more claim (soundness unchanged).
//!  * Several tables (separate Merkle trees with the same column count and
//!    blowup) can be opened together at shared query positions; claims are
//!    arbitrary rank-1 forms (row coefficient vector per table) x (column
//!    vector b).
const std = @import("std");
const core = @import("stwo_core");
const f = @import("field.zig");
const pcs = @import("pcs.zig");
const Transcript = @import("transcript.zig").Transcript;

const M31 = f.M31;
const QM31 = f.QM31;
const Hash = [32]u8;
const Hasher = core.vcs.blake2_hash.Blake2sHasher;
const ChaCha = core.crypto.chacha20_rng.ChaCha20Rng;

pub const SALT = 32;

// ---------------------------------------------------------------------------
// Randomness.

/// Prover randomness: ChaCha20 keystream keyed by 32 bytes of OS entropy.
pub const Rng = struct {
    inner: ChaCha,

    pub fn initOs() Rng {
        var seed: [32]u8 = undefined;
        std.crypto.random.bytes(&seed);
        return .{ .inner = ChaCha.fromSeed(seed) };
    }

    /// Deterministic seed: tests only.
    pub fn initSeed(seed: [32]u8) Rng {
        return .{ .inner = ChaCha.fromSeed(seed) };
    }

    pub fn u32_(self: *Rng) u32 {
        return self.inner.nextU32();
    }

    /// Uniform in [0, p) by rejection.
    pub fn m31(self: *Rng) M31 {
        while (true) {
            const w = self.inner.nextU32() & 0x7fff_ffff;
            if (w != f.P) return M31.fromCanonical(w);
        }
    }

    pub fn qm31(self: *Rng) QM31 {
        return QM31.fromU32Unchecked(self.m31().v, self.m31().v, self.m31().v, self.m31().v);
    }

    pub fn fillM31(self: *Rng, out: []M31) void {
        for (out) |*o| o.* = self.m31();
    }

    pub fn bytes(self: *Rng, out: []u8) void {
        var i: usize = 0;
        while (i < out.len) : (i += 4) {
            const w = self.inner.nextU32();
            var b: [4]u8 = undefined;
            std.mem.writeInt(u32, &b, w, .little);
            const n = @min(4, out.len - i);
            @memcpy(out[i..][0..n], b[0..n]);
        }
    }
};

/// QM31 basis over M31: e_0 = 1, e_1 = i, e_2 = u, e_3 = iu (fromLimbs is linear).
pub fn basis(k: usize) QM31 {
    var l: f.Limbs = @splat(0);
    l[k] = 1;
    return f.fromLimbs(l);
}

// ---------------------------------------------------------------------------
// Commitment.

pub const Shape = struct {
    log_cols: u32,
    log_blowup: u32,
    /// random coefficient slots per row (power of two, >= 2)
    slots: u32,
    /// committed rows (data rows used + extra rows)
    n_rows: usize,

    pub fn nCols(self: Shape) usize {
        return @as(usize, 1) << @intCast(self.log_cols);
    }
    pub fn logExt(self: Shape) u32 {
        return self.log_cols + self.log_blowup;
    }
    pub fn msgLen(self: Shape) usize {
        return self.nCols() + self.slots;
    }
    /// Rate precondition of the hiding PCS: message (C + S) at most half the codeword.
    /// The query-count / soundness argument (zk.md 3.1) assumes it; refused as an
    /// error on both sides, never only asserted (ZK-5).
    pub fn rateOk(self: Shape) bool {
        return self.msgLen() <= (@as(usize, 1) << @intCast(self.logExt())) / 2;
    }
    /// Max distinct columns that may ever be opened.
    pub fn budget(self: Shape) usize {
        return self.slots / 2;
    }
};

/// Slots needed so that one opening with `n_queries` queries is within budget.
pub fn slotsFor(n_queries: usize) u32 {
    var s: u32 = 2;
    while (s / 2 < n_queries) s *= 2;
    return s;
}

/// Tracks distinct opened columns of a long-lived commitment.
///
/// Thread-safe (ZK-4): the budget is charged through the `*Budget` of a commitment
/// that callers hold as `*const` (a `ZkWeights` shared by concurrent `zk.prove`
/// calls), so the check-and-update of `charge` and the reads of `left`/`used` hold
/// `mu`. Without it two concurrent openings could both pass the check and together
/// open more than `slots/2` distinct columns, breaking Lemma 1 for the weights.
pub const Budget = struct {
    opened: std.DynamicBitSetUnmanaged = .{},
    count: usize = 0,
    limit: usize,
    mu: std.Thread.Mutex = .{},

    pub fn init(a: std.mem.Allocator, n_cols_ext: usize, limit: usize) !Budget {
        return .{ .opened = try std.DynamicBitSetUnmanaged.initEmpty(a, n_cols_ext), .limit = limit };
    }
    pub fn deinit(self: *Budget, a: std.mem.Allocator) void {
        self.opened.deinit(a);
    }
    /// Charge a set of query positions atomically; fails (without charging) if the
    /// union would exceed the budget.
    pub fn charge(self: *Budget, idx: []const usize) !void {
        self.mu.lock();
        defer self.mu.unlock();
        var extra: usize = 0;
        // distinct new positions (query sets are small: quadratic dedup, no allocation)
        for (idx, 0..) |j, i| {
            if (j >= self.opened.bit_length) return error.OpeningShape;
            if (self.opened.isSet(j)) continue;
            const dup = for (idx[0..i]) |k| {
                if (k == j) break true;
            } else false;
            if (!dup) extra += 1;
        }
        if (self.count + extra > self.limit) return error.OpeningBudgetExceeded;
        for (idx) |j| self.opened.set(j);
        self.count += extra;
    }
    /// Columns still openable.
    pub fn left(self: *Budget) usize {
        self.mu.lock();
        defer self.mu.unlock();
        return self.limit - self.count;
    }
    /// Distinct columns opened so far and the limit.
    pub fn used(self: *Budget) [2]usize {
        self.mu.lock();
        defer self.mu.unlock();
        return .{ self.count, self.limit };
    }
};

pub const Commitment = struct {
    shape: Shape,
    /// encoded table, column-major: column j at enc[j*n_rows ..]
    enc: []M31,
    /// prover secret: slot coefficients, row-major n_rows x slots
    tau: []M31,
    salts: [][SALT]u8,
    tree: pcs.Merkle,
    /// optional lifetime budget (weights); heap-allocated so it can be charged through a const pointer
    budget: ?*Budget = null,

    pub fn deinit(self: *Commitment, a: std.mem.Allocator) void {
        a.free(self.enc);
        a.free(self.tau);
        a.free(self.salts);
        self.tree.deinit(a);
        if (self.budget) |b| {
            b.deinit(a);
            a.destroy(b);
        }
    }
    pub fn column(self: *const Commitment, j: usize) []const M31 {
        const r = self.shape.n_rows;
        return self.enc[j * r .. (j + 1) * r];
    }
    pub fn root(self: *const Commitment) Hash {
        return self.tree.root();
    }
    pub fn enableBudget(self: *Commitment, a: std.mem.Allocator) !void {
        const b = try a.create(Budget);
        b.* = try Budget.init(a, @as(usize, 1) << @intCast(self.shape.logExt()), self.shape.budget());
        self.budget = b;
    }
};

pub fn leafHash(col: []const M31, salt: *const [SALT]u8) Hash {
    var h = Hasher.init();
    h.update(std.mem.sliceAsBytes(col));
    h.update(salt);
    return h.finalize();
}

/// Commit to data rows `m` (rows_used of them) followed by `n_extra` extra
/// rows given as M31 (row-major, C each).
pub fn commit(
    comptime T: type,
    a: std.mem.Allocator,
    pool: *f.Pool,
    tw: *const pcs.Twiddles,
    rng: *Rng,
    m: pcs.Matrix(T),
    extra: []const M31,
    slots: u32,
    log_blowup: u32,
) !Commitment {
    const C = m.nCols();
    std.debug.assert(extra.len % C == 0);
    const RD = m.usedRows();
    const R = RD + extra.len / C;
    const shape = Shape{ .log_cols = m.log_cols, .log_blowup = log_blowup, .slots = slots, .n_rows = R };
    const E = @as(usize, 1) << @intCast(shape.logExt());
    std.debug.assert(tw.domain.logSize() == shape.logExt());
    if (!shape.rateOk()) return error.ZkRate;
    const tau = try a.alloc(M31, R * slots);
    errdefer a.free(tau);
    rng.fillM31(tau);
    const salts = try a.alloc([SALT]u8, E);
    errdefer a.free(salts);
    for (salts) |*s| rng.bytes(s);
    const enc = try a.alloc(M31, R * E);
    errdefer a.free(enc);

    // rows encoded per block: 16, fewer for wide rows (per-thread scratch <= 2^22 cells)
    const BR: usize = @max(1, @min(16, (@as(usize, 1) << 22) / E));
    const Ctx = struct { m: pcs.Matrix(T), extra: []const M31, tau: []const M31, enc: []M31, tw: *const pcs.Twiddles, E: usize, C: usize, R: usize, RD: usize, S: usize, BR: usize };
    const ctx = Ctx{ .m = m, .extra = extra, .tau = tau, .enc = enc, .tw = tw, .E = E, .C = C, .R = R, .RD = RD, .S = slots, .BR = BR };
    const n_blocks = (R + BR - 1) / BR;
    pool.parallelFor(n_blocks, 1, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            const BR_ = c.BR;
            const buf = std.heap.page_allocator.alloc(M31, c.E * BR_) catch @panic("oom");
            defer std.heap.page_allocator.free(buf);
            for (s..e) |blk| {
                const r0 = blk * BR_;
                const r1 = @min(c.R, r0 + BR_);
                const nb = r1 - r0;
                // messages C + S zero-padded to 2C (S <= C by rateOk) go through the
                // batched dyadic-extension FFT, bit-identical to encode(C + S)
                const ml = 2 * c.C;
                var views: [16][]M31 = undefined;
                for (0..nb) |bi| {
                    const i = r0 + bi;
                    const rb = buf[bi * c.E .. (bi + 1) * c.E];
                    if (i < c.RD) {
                        for (c.m.row(i), 0..) |v, j| rb[j] = f.fromI32(@intCast(v));
                    } else {
                        @memcpy(rb[0..c.C], c.extra[(i - c.RD) * c.C ..][0..c.C]);
                    }
                    @memcpy(rb[c.C..][0..c.S], c.tau[i * c.S ..][0..c.S]);
                    @memset(rb[c.C + c.S .. ml], M31.zero());
                    views[bi] = rb;
                }
                c.tw.encodeBatch(views[0..nb], ml);
                for (0..c.E) |j| {
                    const dst = c.enc[j * c.R + r0 ..][0..nb];
                    for (0..nb) |bi| dst[bi] = buf[bi * c.E + j];
                }
            }
        }
    }.run);

    const nodes = try a.alloc(Hash, 2 * E);
    const LCtx = struct { enc: []const M31, salts: []const [SALT]u8, nodes: []Hash, R: usize, E: usize };
    const lctx = LCtx{ .enc = enc, .salts = salts, .nodes = nodes, .R = R, .E = E };
    // Salted leaves, four columns per 4-lane SIMD Blake2s call: each message
    // column_j || salt_j is assembled in per-worker scratch, so the digests equal
    // leafHash (scalar Blake2s over the same bytes; pinned by the seeded tests).
    const n_groups = (E + 3) / 4;
    pool.parallelFor(n_groups, 16, &lctx, struct {
        fn run(c: *const LCtx, s: usize, e: usize) void {
            const L = c.R * 4 + SALT;
            const buf = std.heap.page_allocator.alloc(u8, 4 * L) catch @panic("oom");
            defer std.heap.page_allocator.free(buf);
            for (s..e) |g| {
                const j0 = g * 4;
                if (j0 + 4 <= c.E) {
                    var msgs: [4][]const u8 = undefined;
                    for (0..4) |l| {
                        const mb = buf[l * L ..][0..L];
                        @memcpy(mb[0 .. c.R * 4], std.mem.sliceAsBytes(c.enc[(j0 + l) * c.R ..][0..c.R]));
                        @memcpy(mb[c.R * 4 ..], &c.salts[j0 + l]);
                        msgs[l] = mb;
                    }
                    const hs = Hasher.hashEqual4WithMode(.auto, &msgs);
                    @memcpy(c.nodes[c.E + j0 ..][0..4], &hs);
                } else {
                    for (j0..c.E) |j| c.nodes[c.E + j] = leafHash(c.enc[j * c.R .. (j + 1) * c.R], &c.salts[j]);
                }
            }
        }
    }.run);
    pcs.buildLevels(pool, nodes, E);
    return .{ .shape = shape, .enc = enc, .tau = tau, .salts = salts, .tree = .{ .nodes = nodes, .n_leaves = E } };
}

/// Combined rows (length C + slots) of one table: out[o] = sum_i coeffs[o][i] * row_i,
/// including the slot coefficients.
pub fn combine(
    comptime T: type,
    a: std.mem.Allocator,
    pool: *f.Pool,
    com: *const Commitment,
    m: pcs.Matrix(T),
    extra: []const M31,
    coeffs: []const []const QM31,
) ![][]QM31 {
    const C = m.nCols();
    const RD = m.usedRows();
    const R = com.shape.n_rows;
    const S = com.shape.slots;
    const G = coeffs.len;
    const out = try a.alloc([]QM31, G);
    for (out) |*o| {
        o.* = try a.alloc(QM31, C + S);
        @memset(o.*, QM31.zero());
    }
    if (RD > 0) {
        const data_rows = try pcs.combineRows(T, a, pool, m, coeffs, if (@bitSizeOf(T) <= 8) 7 else 30);
        defer {
            for (data_rows) |r| a.free(r);
            a.free(data_rows);
        }
        for (out, data_rows) |o, d| @memcpy(o[0..C], d);
    }
    for (0..G) |g| {
        for (RD..R) |i| {
            const c = coeffs[g][i];
            if (c.isZero()) continue;
            const row = extra[(i - RD) * C ..][0..C];
            for (out[g][0..C], row) |*o, v| o.* = o.*.add(c.mulM31(v));
        }
    }
    // slot part: out[g][C+s] = sum_i coeffs[g][i] tau[i][s]
    const Ctx = struct { coeffs: []const []const QM31, tau: []const M31, out: [][]QM31, R: usize, S: usize, C: usize };
    const ctx = Ctx{ .coeffs = coeffs, .tau = com.tau, .out = out, .R = R, .S = S, .C = C };
    pool.parallelFor(S, 8, &ctx, struct {
        fn run(c: *const Ctx, s0: usize, s1: usize) void {
            for (c.coeffs, 0..) |cg, g| {
                for (s0..s1) |s| {
                    var acc = QM31.zero();
                    for (0..c.R) |i| acc = acc.add(cg[i].mulM31(c.tau[i * c.S + s]));
                    c.out[g][c.C + s] = acc;
                }
            }
        }
    }.run);
    return out;
}

// ---------------------------------------------------------------------------
// Openings.

/// Four consecutive mask rows of table `table` starting at `row`.
/// Mask rows of a combined row: 4 rows from `row`. For the proximity rows,
/// `count` rows, row i masked by rows row + 4i .. row + 4i + 3 (fresh beta_i
/// and beta_mu_i each: the proximity term is eps^count, security.md 3.2).
pub const MaskRef = struct {
    table: usize,
    row: usize,
    count: usize = 1,
};

/// Number of proximity rows of an opening.
pub fn nProx(prox: ?MaskRef) usize {
    return if (prox) |p| p.count else 0;
}

pub const Claim = struct {
    /// row coefficient vector per table (len n_rows of that table, or 0 = zero)
    rows: []const []const QM31,
    value: QM31,
};

pub const Group = struct {
    /// column vector b (len C)
    col: []const QM31,
    claims: []const Claim,
    mask: MaskRef,
};

pub const TableColumns = struct {
    /// n_queries x n_rows, query-major
    values: []M31,
    salts: [][SALT]u8,
    /// n_queries x log_ext
    paths: []Hash,
};

pub const Opening = struct {
    mus: []QM31,
    /// proximity row first (if any), then one row per group; each C + slots
    rows: [][]QM31,
    pow_nonce: u64,
    tables: []TableColumns,

    pub fn deinit(self: *Opening, a: std.mem.Allocator) void {
        a.free(self.mus);
        for (self.rows) |r| a.free(r);
        a.free(self.rows);
        for (self.tables) |t| {
            a.free(t.values);
            a.free(t.salts);
            a.free(t.paths);
        }
        a.free(self.tables);
    }

    pub fn byteSize(self: Opening) usize {
        var s: usize = 8 + self.mus.len * 16;
        for (self.rows) |r| s += r.len * 16;
        for (self.tables) |t| s += t.values.len * 4 + t.salts.len * SALT + t.paths.len * 32 + t.salts.len * 8;
        return s;
    }
};

/// mu = sum_k e_k <M_k[0..C], b> for 4 mask rows given as integer rows.
pub fn maskValue(comptime T: type, m: pcs.Matrix(T), row0: usize, col: []const QM31) QM31 {
    var mu = QM31.zero();
    for (0..4) |k| {
        var acc = QM31.zero();
        for (m.row(row0 + k), col) |v, b| acc = acc.add(b.mulM31(f.fromI32(@intCast(v))));
        mu = mu.add(acc.mul(basis(k)));
    }
    return mu;
}

pub const Coeffs = struct {
    /// coeffs[o][t]: row coefficients of output row o on table t (len n_rows_t)
    v: [][][]QM31,
    gammas: [][]QM31,

    pub fn deinit(self: *Coeffs, a: std.mem.Allocator) void {
        for (self.v) |o| {
            for (o) |t| a.free(t);
            a.free(o);
        }
        a.free(self.v);
        for (self.gammas) |g| a.free(g);
        a.free(self.gammas);
    }
};

/// Transcript steps shared by prover and verifier, up to (not including) the rows.
pub fn drawCoeffs(a: std.mem.Allocator, tr: *Transcript, shapes: []const Shape, groups: []const Group, mus: []const QM31, prox: ?MaskRef) !Coeffs {
    std.debug.assert(mus.len == groups.len);
    for (groups, mus) |g, mu| {
        for (g.claims) |c| tr.mixFelt(c.value);
        tr.mixFelt(mu);
    }
    const gammas = try a.alloc([]QM31, groups.len);
    for (groups, 0..) |g, gi| {
        gammas[gi] = try a.alloc(QM31, g.claims.len + 1);
        tr.drawN(gammas[gi]);
    }
    const n_out = groups.len + nProx(prox);
    const v = try a.alloc([][]QM31, n_out);
    for (v) |*o| {
        o.* = try a.alloc([]QM31, shapes.len);
        for (o.*, shapes) |*t, s| {
            t.* = try a.alloc(QM31, s.n_rows);
            @memset(t.*, QM31.zero());
        }
    }
    var k0: usize = 0;
    if (prox) |pm| {
        if (pm.count == 0) return error.OpeningShape;
        for (0..pm.count) |i| {
            for (v[i], 0..) |t, ti| tr.drawN(t[0..shapes[ti].n_rows]);
            const bmu = tr.draw();
            // Row i reads only its own 4 mask rows: the other proximity rows'
            // masks get coefficient 0 here. With the random coefficients drawN
            // put there, the 4k x 4k M31 block mapping the proximity masks to
            // the k combined rows is not triangular and is singular with
            // probability ~1/p (2^-31 per opening), not ~k/|F|; a singular
            // block reveals a fixed linear combination of data rows in the
            // clear. Block diagonal, it is invertible iff every beta_mu_i != 0.
            // Soundness: row i still tests every row outside the other rows'
            // masks, with its own masks (security.md 3.2 on [D; M_i], the
            // k events independent). k = 1: nothing changes.
            for (0..pm.count) |j| if (j != i) for (0..4) |k| {
                v[i][pm.table][pm.row + 4 * j + k] = QM31.zero();
            };
            for (0..4) |k| v[i][pm.table][pm.row + 4 * i + k] = bmu.mul(basis(k));
        }
        k0 = pm.count;
    }
    for (groups, 0..) |g, gi| {
        const o = v[k0 + gi];
        for (g.claims, 0..) |c, ci| {
            const gm = gammas[gi][ci];
            for (c.rows, 0..) |rv, ti| {
                if (rv.len == 0) continue;
                for (o[ti], rv[0..shapes[ti].n_rows]) |*x, y| x.* = x.*.add(gm.mul(y));
            }
        }
        const gmu = gammas[gi][g.claims.len];
        for (0..4) |k| o[g.mask.table][g.mask.row + k] = o[g.mask.table][g.mask.row + k].add(gmu.mul(basis(k)));
    }
    return .{ .v = v, .gammas = gammas };
}

/// Prover: after combining rows (sum over tables of `combine`), finish the opening.
pub fn finish(
    a: std.mem.Allocator,
    tr: *Transcript,
    params: pcs.Params,
    coms: []const *const Commitment,
    mus: []QM31,
    rows: [][]QM31,
) !Opening {
    // takes ownership of mus and rows (also on error)
    errdefer {
        a.free(mus);
        for (rows) |r| a.free(r);
        a.free(rows);
    }
    for (rows) |r| tr.mixFelts(r);
    const nonce = tr.grind(params.pow_bits);
    const log_ext = coms[0].shape.logExt();
    const idx = try a.alloc(usize, params.n_queries);
    defer a.free(idx);
    tr.drawIndices(log_ext, idx);
    // budget check before anything is released
    for (coms) |c| if (c.budget) |b| try b.charge(idx);
    const tables = try a.alloc(TableColumns, coms.len);
    for (coms, 0..) |c, ti| {
        std.debug.assert(c.shape.logExt() == log_ext);
        const R = c.shape.n_rows;
        const vals = try a.alloc(M31, params.n_queries * R);
        const salts = try a.alloc([SALT]u8, params.n_queries);
        const paths = try a.alloc(Hash, params.n_queries * log_ext);
        for (idx, 0..) |j, q| {
            @memcpy(vals[q * R ..][0..R], c.column(j));
            salts[q] = c.salts[j];
            c.tree.path(paths[q * log_ext ..][0..log_ext], j);
        }
        tables[ti] = .{ .values = vals, .salts = salts, .paths = paths };
    }
    return .{ .mus = mus, .rows = rows, .pow_nonce = nonce, .tables = tables };
}

pub fn verifyOpening(
    a: std.mem.Allocator,
    tr: *Transcript,
    params: pcs.Params,
    tw: *const pcs.Twiddles,
    shapes: []const Shape,
    roots: []const Hash,
    groups: []const Group,
    prox: ?MaskRef,
    proof: Opening,
) !void {
    if (shapes.len == 0 or roots.len != shapes.len or proof.tables.len != shapes.len) return error.OpeningShape;
    if (proof.mus.len != groups.len) return error.OpeningShape;
    const C = shapes[0].nCols();
    const ML = shapes[0].msgLen();
    const log_ext = shapes[0].logExt();
    for (shapes) |s| if (s.logExt() != log_ext or s.nCols() != C or s.slots != shapes[0].slots or !s.rateOk()) return error.OpeningShape;
    for (groups) |g| {
        if (g.col.len != C) return error.OpeningShape;
        for (g.claims) |c| {
            if (c.rows.len != shapes.len) return error.OpeningShape;
            for (c.rows, shapes) |r, s| if (r.len != 0 and r.len < s.n_rows) return error.OpeningShape;
        }
    }
    var co = try drawCoeffs(a, tr, shapes, groups, proof.mus, prox);
    defer co.deinit(a);
    const n_out = co.v.len;
    if (proof.rows.len != n_out) return error.OpeningShape;
    for (proof.rows) |r| {
        if (r.len != ML) return error.OpeningShape;
        tr.mixFelts(r);
    }
    const k0: usize = nProx(prox);
    for (groups, 0..) |g, gi| {
        var lhs = QM31.zero();
        for (proof.rows[k0 + gi][0..C], g.col) |u, b| lhs = lhs.add(u.mul(b));
        var rhs = QM31.zero();
        for (g.claims, 0..) |c, ci| rhs = rhs.add(co.gammas[gi][ci].mul(c.value));
        rhs = rhs.add(co.gammas[gi][g.claims.len].mul(proof.mus[gi]));
        if (!lhs.eql(rhs)) return error.OpeningEvalMismatch;
    }
    if (!tr.verifyPow(params.pow_bits, proof.pow_nonce)) return error.OpeningPow;
    const idx = try a.alloc(usize, params.n_queries);
    defer a.free(idx);
    tr.drawIndices(log_ext, idx);
    const encs = try a.alloc([]QM31, n_out);
    defer {
        for (encs) |e| a.free(e);
        a.free(encs);
    }
    for (proof.rows, 0..) |r, i| encs[i] = try pcs.encodeSecure(a, tw, r);
    for (proof.tables, shapes) |t, s| {
        if (t.values.len != params.n_queries * s.n_rows or t.salts.len != params.n_queries or t.paths.len != params.n_queries * log_ext) return error.OpeningShape;
    }
    for (idx, 0..) |j, q| {
        for (proof.tables, shapes, roots) |t, s, rt| {
            const col = t.values[q * s.n_rows ..][0..s.n_rows];
            if (!pcs.verifyPath(rt, leafHash(col, &t.salts[q]), j, log_ext, t.paths[q * log_ext ..][0..log_ext])) return error.OpeningMerkle;
        }
        for (0..n_out) |o| {
            var acc = QM31.zero();
            for (proof.tables, shapes, 0..) |t, s, ti| {
                const col = t.values[q * s.n_rows ..][0..s.n_rows];
                for (co.v[o][ti], col) |c, v| acc = acc.add(c.mulM31(v));
            }
            if (!acc.eql(encs[o][j])) return error.OpeningColumnMismatch;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests.

fn rankM31(a: std.mem.Allocator, rows: usize, cols: usize, mat_in: []const M31) !usize {
    const m = try a.dupe(M31, mat_in);
    defer a.free(m);
    var rank: usize = 0;
    var c: usize = 0;
    while (c < cols and rank < rows) : (c += 1) {
        var piv: ?usize = null;
        for (rank..rows) |r| if (!m[r * cols + c].isZero()) {
            piv = r;
            break;
        };
        const p = piv orelse continue;
        if (p != rank) for (0..cols) |k| std.mem.swap(M31, &m[p * cols + k], &m[rank * cols + k]);
        const inv = try m[rank * cols + c].inv();
        for (0..rows) |r| {
            if (r == rank) continue;
            const fac = m[r * cols + c].mul(inv);
            if (fac.isZero()) continue;
            for (0..cols) |k| m[r * cols + k] = m[r * cols + k].sub(fac.mul(m[rank * cols + k]));
        }
        rank += 1;
    }
    return rank;
}

test "masked encoding: slot span is onto any slots/2 positions (sampled)" {
    const a = std.testing.allocator;
    const lc = 6;
    const lb = 2;
    const C = 1 << lc;
    const S: usize = 16;
    var tw = try pcs.Twiddles.init(a, lc + lb);
    defer tw.deinit(a);
    const E: usize = 1 << (lc + lb);
    // basis evaluations of the slot coefficients
    const ev = try a.alloc(M31, S * E);
    defer a.free(ev);
    const buf = try a.alloc(M31, E);
    defer a.free(buf);
    for (0..S) |s| {
        @memset(buf, M31.zero());
        buf[C + s] = M31.one();
        tw.encode(buf, C + S);
        @memcpy(ev[s * E ..][0..E], buf);
    }
    var prng = std.Random.DefaultPrng.init(11);
    const mat = try a.alloc(M31, (S / 2) * S);
    defer a.free(mat);
    var trial: usize = 0;
    while (trial < 300) : (trial += 1) {
        // random distinct positions; every 3rd trial use clustered/adjacent positions
        var pos: [S / 2]usize = undefined;
        var n: usize = 0;
        const start = prng.random().uintLessThan(usize, E);
        while (n < S / 2) {
            const j = if (trial % 3 == 0) (start + n * (1 + trial % 5)) % E else prng.random().uintLessThan(usize, E);
            var dup = false;
            for (pos[0..n]) |q| dup = dup or q == j;
            if (dup) continue;
            pos[n] = j;
            n += 1;
        }
        for (0..S / 2) |r| for (0..S) |s| {
            mat[r * S + s] = ev[s * E + pos[r]];
        };
        try std.testing.expectEqual(@as(usize, S / 2), try rankM31(a, S / 2, S, mat));
    }
    // every single position has a non-zero slot evaluation (pi^(lc-1)(x) != 0 on the domain)
    for (0..E) |j| {
        var nz = false;
        for (0..S) |s| nz = nz or !ev[s * E + j].isZero();
        try std.testing.expect(nz);
    }
}

fn testTable(a: std.mem.Allocator, lr: u32, lc: u32, seed: u64) ![]i32 {
    const n = @as(usize, 1) << @intCast(lr + lc);
    const d = try a.alloc(i32, n);
    var prng = std.Random.DefaultPrng.init(seed);
    for (d) |*x| x.* = prng.random().intRangeAtMost(i32, -1000, 1000);
    return d;
}

test "zk pcs: two tables, groups, masks; verify and reject tampering" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 3);
    defer pool.deinit();
    const lc = 5;
    const lb = 2;
    const C = 1 << lc;
    const params = pcs.Params{ .log_blowup = lb, .n_queries = 8, .pow_bits = 2 };
    const S = slotsFor(params.n_queries);
    var tw = try pcs.Twiddles.init(a, lc + lb);
    defer tw.deinit(a);
    var rng = Rng.initSeed([_]u8{1} ** 32);
    // table 0: 16 rows, the last 8 of which are mask rows (prox 8..11, group 12..15)
    const d0 = try testTable(a, 4, lc, 3);
    defer a.free(d0);
    const m0 = pcs.Matrix(i32){ .data = d0, .log_rows = 4, .log_cols = lc };
    // table 1: 4 data rows + 2 extra M31 rows
    const d1 = try testTable(a, 2, lc, 4);
    defer a.free(d1);
    const m1 = pcs.Matrix(i32){ .data = d1, .log_rows = 2, .log_cols = lc };
    const ex = try a.alloc(M31, 2 * C);
    defer a.free(ex);
    rng.fillM31(ex);
    var c0 = try commit(i32, a, &pool, &tw, &rng, m0, &.{}, S, lb);
    defer c0.deinit(a);
    var c1 = try commit(i32, a, &pool, &tw, &rng, m1, ex, S, lb);
    defer c1.deinit(a);
    const shapes = [_]Shape{ c0.shape, c1.shape };
    // one group: claim = sum over rows 0..3 of table0 with coeffs + row 5 of table1 (extra row 1), column vector b
    var b: [C]QM31 = undefined;
    for (&b, 0..) |*x, i| x.* = QM31.fromU32Unchecked(@intCast(i + 3), 7, @intCast(i * i), 1);
    var r0: [16]QM31 = [_]QM31{QM31.zero()} ** 16;
    var r1: [6]QM31 = [_]QM31{QM31.zero()} ** 6;
    for (0..4) |i| r0[i] = QM31.fromU32Unchecked(@intCast(i + 1), 2, 3, 4);
    r1[5] = QM31.fromU32Unchecked(9, 9, 9, 9);
    var value = QM31.zero();
    for (0..4) |i| for (0..C) |j| {
        value = value.add(r0[i].mul(b[j]).mulM31(f.fromI32(d0[i * C + j])));
    };
    for (0..C) |j| value = value.add(r1[5].mul(b[j]).mulM31(ex[C + j]));
    const rows_view = [_][]const QM31{ &r0, &r1 };
    const claims = [_]Claim{.{ .rows = &rows_view, .value = value }};
    const groups = [_]Group{.{ .col = &b, .claims = &claims, .mask = .{ .table = 0, .row = 12 } }};
    const prox = MaskRef{ .table = 0, .row = 8 };

    var tp = Transcript.initDomain("zkpcs");
    const mus = try a.alloc(QM31, 1);
    mus[0] = maskValue(i32, m0, 12, &b);
    var co = try drawCoeffs(a, &tp, &shapes, &groups, mus, prox);
    defer co.deinit(a);
    const n_out = co.v.len;
    const rows = try a.alloc([]QM31, n_out);
    {
        const cv0 = try a.alloc([]const QM31, n_out);
        defer a.free(cv0);
        const cv1 = try a.alloc([]const QM31, n_out);
        defer a.free(cv1);
        for (0..n_out) |o| {
            cv0[o] = co.v[o][0];
            cv1[o] = co.v[o][1];
        }
        const ua = try combine(i32, a, &pool, &c0, m0, &.{}, cv0);
        defer a.free(ua);
        const ub = try combine(i32, a, &pool, &c1, m1, ex, cv1);
        defer {
            for (ub) |r| a.free(r);
            a.free(ub);
        }
        for (0..n_out) |o| {
            for (ua[o], ub[o]) |*x, y| x.* = x.*.add(y);
            rows[o] = ua[o];
        }
    }
    const coms = [_]*const Commitment{ &c0, &c1 };
    var proof = try finish(a, &tp, params, &coms, mus, rows);
    defer proof.deinit(a);
    const roots = [_]Hash{ c0.root(), c1.root() };
    {
        var tv = Transcript.initDomain("zkpcs");
        try verifyOpening(a, &tv, params, &tw, &shapes, &roots, &groups, prox, proof);
    }
    // wrong claim value
    {
        const bad = [_]Claim{.{ .rows = &rows_view, .value = value.add(QM31.one()) }};
        const gb = [_]Group{.{ .col = &b, .claims = &bad, .mask = .{ .table = 0, .row = 12 } }};
        var tv = Transcript.initDomain("zkpcs");
        try std.testing.expectError(error.OpeningEvalMismatch, verifyOpening(a, &tv, params, &tw, &shapes, &roots, &gb, prox, proof));
    }
    // tampered mu
    {
        proof.mus[0] = proof.mus[0].add(QM31.one());
        var tv = Transcript.initDomain("zkpcs");
        try std.testing.expect(std.meta.isError(verifyOpening(a, &tv, params, &tw, &shapes, &roots, &groups, prox, proof)));
        proof.mus[0] = proof.mus[0].sub(QM31.one());
    }
    // tampered salt, column value, combined row
    {
        proof.tables[1].salts[2][0] ^= 1;
        var tv = Transcript.initDomain("zkpcs");
        try std.testing.expectError(error.OpeningMerkle, verifyOpening(a, &tv, params, &tw, &shapes, &roots, &groups, prox, proof));
        proof.tables[1].salts[2][0] ^= 1;
        proof.tables[0].values[3] = proof.tables[0].values[3].add(M31.one());
        var tv2 = Transcript.initDomain("zkpcs");
        try std.testing.expectError(error.OpeningMerkle, verifyOpening(a, &tv2, params, &tw, &shapes, &roots, &groups, prox, proof));
        proof.tables[0].values[3] = proof.tables[0].values[3].sub(M31.one());
        proof.rows[0][C + 1] = proof.rows[0][C + 1].add(QM31.one());
        var tv3 = Transcript.initDomain("zkpcs");
        try std.testing.expect(std.meta.isError(verifyOpening(a, &tv3, params, &tw, &shapes, &roots, &groups, prox, proof)));
        proof.rows[0][C + 1] = proof.rows[0][C + 1].sub(QM31.one());
    }
    var tv = Transcript.initDomain("zkpcs");
    try verifyOpening(a, &tv, params, &tw, &shapes, &roots, &groups, prox, proof);
}

test "zk pcs budget refuses to exceed slots/2 distinct columns" {
    const a = std.testing.allocator;
    var b = try Budget.init(a, 64, 4);
    defer b.deinit(a);
    try b.charge(&.{ 1, 2, 2 });
    try b.charge(&.{ 1, 3 });
    try std.testing.expectError(error.OpeningBudgetExceeded, b.charge(&.{ 4, 5 }));
    try b.charge(&.{ 4, 1 });
    try std.testing.expectEqual(@as(usize, 4), b.count);
}

test "zk pcs budget: concurrent charges never exceed the limit (ZK-4)" {
    const a = std.testing.allocator;
    const N_COLS: usize = 1 << 14;
    const LIMIT: usize = 4096;
    const N_THREADS = 8;
    var b = try Budget.init(a, N_COLS, LIMIT);
    defer b.deinit(a);
    var ok = [_]std.atomic.Value(usize){std.atomic.Value(usize).init(0)} ** N_THREADS;
    const W = struct {
        fn run(bp: *Budget, t: usize, cnt: *std.atomic.Value(usize)) void {
            // each thread charges its own distinct columns, one at a time, and a
            // column shared by all threads (charged once overall)
            var j: usize = t;
            while (j < N_COLS) : (j += N_THREADS) {
                const idx = [_]usize{ j, 0 };
                bp.charge(&idx) catch continue;
                _ = cnt.fetchAdd(1, .monotonic);
            }
        }
    };
    var th: [N_THREADS]std.Thread = undefined;
    for (&th, 0..) |*h, t| h.* = try std.Thread.spawn(.{}, W.run, .{ &b, t, &ok[t] });
    for (th) |h| h.join();
    var succeeded: usize = 0;
    for (&ok) |*c| succeeded += c.load(.monotonic);
    const u = b.used();
    // every successful charge added exactly one new column (column 0 at most once
    // more), and the bitset agrees with the count
    try std.testing.expect(u[0] <= LIMIT);
    try std.testing.expectEqual(b.opened.count(), u[0]);
    try std.testing.expect(succeeded == u[0] or succeeded + 1 == u[0]);
    try std.testing.expectEqual(LIMIT - u[0], b.left());
}

test "zk pcs: SIMD salted leaves and parallel levels equal scalar leafHash + hashNode tree" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 3);
    defer pool.deinit();
    for ([_]u32{ 2, 3, 6 }) |lc| for ([_]usize{ 1, 3, 5, 17 }) |rows| {
        const lb: u32 = 2;
        var tw = try pcs.Twiddles.init(a, lc + lb);
        defer tw.deinit(a);
        const C = @as(usize, 1) << @intCast(lc);
        const data = try a.alloc(i32, rows * C);
        defer a.free(data);
        for (data, 0..) |*d, i| d.* = @as(i32, @intCast(i % 97)) - 40;
        var log_rows: u32 = 0;
        while ((@as(usize, 1) << @intCast(log_rows)) < rows) log_rows += 1;
        const m = pcs.Matrix(i32){ .data = data, .log_rows = log_rows, .log_cols = lc, .rows_used = rows };
        var rng = Rng.initSeed([_]u8{@intCast(rows)} ** 32);
        var com = try commit(i32, a, &pool, &tw, &rng, m, &.{}, 2, lb);
        defer com.deinit(a);
        const E = @as(usize, 1) << @intCast(lc + lb);
        const nodes = try a.alloc(Hash, 2 * E);
        defer a.free(nodes);
        for (0..E) |j| nodes[E + j] = leafHash(com.column(j), &com.salts[j]);
        var i = E - 1;
        while (i >= 1) : (i -= 1) nodes[i] = pcs.hashNode(nodes[2 * i], nodes[2 * i + 1]);
        try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(nodes[1..]), std.mem.sliceAsBytes(com.tree.nodes[1..]));
        // batched dyadic encode of the (C + S)-coefficient rows equals encode(C + S)
        const S: usize = com.shape.slots;
        const rb = try a.alloc(M31, E);
        defer a.free(rb);
        for (0..rows) |r| {
            for (0..C) |j| rb[j] = f.fromI32(data[r * C + j]);
            @memcpy(rb[C..][0..S], com.tau[r * S ..][0..S]);
            tw.encode(rb, C + S);
            for (0..E) |j| try std.testing.expect(rb[j].eql(com.enc[j * rows + r]));
        }
    };
}

test "zk pcs: k proximity rows read only their own masks (mask block invertible)" {
    // With k > 1 the mask block of the k proximity rows must be block diagonal:
    // with random cross coefficients it is a generic 4k x 4k M31 matrix,
    // singular with probability ~1/p, and a singular block reveals a fixed
    // combination of data rows in the clear (zero knowledge lost).
    if (f.IS_OM31) return error.SkipZigTest;
    const a = std.testing.allocator;
    const kp = 3;
    const row0 = 2;
    const shapes = [_]Shape{.{ .log_cols = 4, .log_blowup = 2, .slots = 8, .n_rows = row0 + 4 * kp + 1 }};
    var tr = Transcript.initDomain("zkpcs-prox-block");
    var co = try drawCoeffs(a, &tr, &shapes, &.{}, &.{}, .{ .table = 0, .row = row0, .count = kp });
    defer co.deinit(a);
    try std.testing.expectEqual(@as(usize, kp), co.v.len);
    // M31 matrix: output coordinate (4 i + c) x mask row (4 j + k)
    var mat: [16 * kp * kp]M31 = undefined;
    for (0..kp) |i| for (0..kp) |j| for (0..4) |k| {
        const x = co.v[i][0][row0 + 4 * j + k];
        if (i != j) try std.testing.expect(x.isZero());
        const xs = x.toM31Array();
        for (0..4) |c| mat[(4 * i + c) * 4 * kp + 4 * j + k] = xs[c];
    };
    try std.testing.expectEqual(@as(usize, 4 * kp), try rankM31(a, 4 * kp, 4 * kp, &mat));
    // the data rows and the row after the masks keep their random coefficients
    for (0..kp) |i| {
        try std.testing.expect(!co.v[i][0][0].isZero());
        try std.testing.expect(!co.v[i][0][row0 + 4 * kp].isZero());
    }
}
