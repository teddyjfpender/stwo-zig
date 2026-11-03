//! Recursive ("two-level") tensor PCS: Ligero/Brakedown openings whose
//! combined rows are committed instead of sent.
//!
//! The outer table is the same commitment as `pcs.commit` (rows = circle
//! polynomial coefficients RS-encoded with stwo's circle FFT, Merkle leaves =
//! encoded columns). Plain Ligero (`pcs.open`) sends every combined row
//! u_g = sum_i a_g[i] row_i (2^lc QM31 each) and the verifier re-encodes it.
//! Here, at each non-final level:
//!
//!   1. the prover commits U = (u_0 .. u_{G-1}) (proximity rows first, then
//!      one row per claim group) as an M31 table V[g][c][k] = limb_c(u_g[k])
//!      with a fresh `pcs.commit` (inner blowup);
//!   2. the verifier draws rho (log G' coords, G' = next pow2 >= G),
//!      lambda = eq(rho, .), then t column indices j after PoW;
//!   3. the prover opens the outer columns (Merkle multiproof); the verifier
//!      computes y_j = <sum_g lambda_g a_g, col_j> itself;
//!   4. claims on U:  <u_g, eq(z_col_g)> = sum_c gamma_c v_c   (eval groups)
//!                    sum_g lambda_g Enc(u_g)[j] = y_j          (queries)
//!      Enc(u)[j] is a tensor-structured functional of the coefficient
//!      vector: stwo's circle basis is b_k(P) = prod_b f_b(P)^{bit_b(k)} with
//!      f = (y, x, pi(x), pi^2(x), ..) at the domain point P_j (bit-reversed
//!      order). All claims are batched with random gamma' and reduced by one
//!      degree-2 sumcheck over sum_{g,k} U[g,k] W[g,k] to U~(r); the prover
//!      sends the four limb MLEs V~(r_g, c, r_k) and the verifier evaluates
//!      W~(r) itself in O(t log C);
//!   5. the four limb claims share their column point and form one group of
//!      the next level (with proximity), which is opened recursively; the
//!      final level sends its rows as in plain Ligero.
//!
//! Soundness argument: design/tensor-frontend/size.md.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const f = @import("field.zig");
const pcs = @import("pcs.zig");
const sc = @import("sumcheck.zig");
const Transcript = @import("transcript.zig").Transcript;

const M31 = f.M31;
const QM31 = f.QM31;
const Hash = [32]u8;
const circle = engine.poly.circle;
const CirclePointM31 = core.circle.CirclePointM31;
const utils = core.utils;

pub const Claim = pcs.Claim;
pub const Group = pcs.Group;
pub const Shape = pcs.Shape;

pub const Params = struct {
    /// query / blowup / PoW parameters of the outer (big) commitment
    outer: pcs.Params = .{},
    /// parameters of every inner (committed-row) commitment
    inner: pcs.Params = .{ .log_blowup = 2, .n_queries = 54, .pow_bits = 20 },
    /// number of committed-row levels (0 = plain Ligero with multiproofs)
    depth: u32 = 1,
    /// prover-cost bound used by the shape search: a level with 2^lc columns
    /// may commit its combined rows only if 4 * 2^lc * 2^inner_blowup <=
    /// max(used >> inner_work_shift, 2^14), i.e. the inner encoding stays a
    /// small fraction of the level's own row-combination work.
    inner_work_shift: u32 = 3,
    /// independent random proximity rows per proximity test (at every level).
    /// The correlated-agreement error of one row is ~ E/|F| (BCIKS20, unique
    /// decoding), i.e. ~2^-105 at E = 2^19 over QM31; k rows give its k-th power.
    prox_rows: u32 = 1,

    pub fn nProx(self: Params, with_proximity: bool) usize {
        return if (with_proximity) self.prox_rows else 0;
    }

    pub fn level(self: Params, i: usize) pcs.Params {
        return if (i == 0) self.outer else self.inner;
    }

    pub fn conjecturedBits(self: Params) f64 {
        return if (self.depth == 0) self.outer.conjecturedBits() else @min(self.outer.conjecturedBits(), self.inner.conjecturedBits());
    }
    pub fn provenBits(self: Params) f64 {
        return if (self.depth == 0) self.outer.provenBits() else @min(self.outer.provenBits(), self.inner.provenBits());
    }
};

// ---------------------------------------------------------------------------
// Circle-code functionals.

/// Factors of the circle basis at the encoded position `j` of a code with
/// 2^log_ext evaluations, for messages of 2^log_c coefficients. Returned in
/// MSB-first variable order: Enc(u)[j] = sum_k u_k prod_v fac[v]^{bit_v(k)},
/// where variable v is bit (log_c - 1 - v) of k.
pub fn circleFactors(log_ext: u32, j: usize, log_c: u32, out: []M31) void {
    std.debug.assert(out.len == log_c and log_c <= log_ext);
    if (log_c == 0) return;
    const domain = circle.CanonicCoset.new(log_ext).circleDomain();
    const p = domain.at(utils.bitReverseIndex(j, log_ext));
    // factor for coefficient bit b: b=0 -> y, b=1 -> x, b>=2 -> doubleX^(b-1)(x)
    out[log_c - 1] = p.y;
    var x = p.x;
    var b: u32 = 1;
    while (b < log_c) : (b += 1) {
        out[log_c - 1 - b] = x;
        x = CirclePointM31.doubleX(x);
    }
}

/// Multilinear extension of the tensor vector prod_v fac[v]^{bit_v(k)} at r.
pub fn tensorEvalAt(fac: []const M31, r: []const QM31) QM31 {
    std.debug.assert(fac.len == r.len);
    var acc = QM31.one();
    for (fac, r) |fv, rv| {
        // (1 - r) + r * fac = 1 + r (fac - 1)
        acc = acc.mul(QM31.one().add(rv.mulM31(fv.sub(M31.one()))));
    }
    return acc;
}

/// The tensor vector itself (2^len entries, MSB-first).
pub fn tensorTable(a: std.mem.Allocator, fac: []const M31) ![]M31 {
    const out = try a.alloc(M31, @as(usize, 1) << @intCast(fac.len));
    out[0] = M31.one();
    var len: usize = 1;
    var k: usize = fac.len;
    while (k > 0) {
        k -= 1;
        for (0..len) |i| out[i + len] = out[i].mul(fac[k]);
        len *= 2;
    }
    return out;
}

/// Enc(u)[j] for a QM31 coefficient vector (verifier helper): folds MSB first.
pub fn evalCoeffs(a: std.mem.Allocator, u: []const QM31, fac: []const M31) !QM31 {
    std.debug.assert(u.len == (@as(usize, 1) << @intCast(fac.len)));
    const buf = try a.dupe(QM31, u);
    defer a.free(buf);
    var len = buf.len;
    for (fac) |fv| {
        const half = len / 2;
        for (0..half) |i| buf[i] = buf[i].add(buf[i + half].mulM31(fv));
        len = half;
    }
    return buf[0];
}

// ---------------------------------------------------------------------------
// Merkle multiproofs (shared siblings across queries).

/// Sorted, deduplicated copy of `idx`.
pub fn sortedUnique(a: std.mem.Allocator, idx: []const usize) ![]usize {
    const s = try a.dupe(usize, idx);
    std.mem.sort(usize, s, {}, std.sort.asc(usize));
    var n: usize = 0;
    for (s, 0..) |v, i| {
        if (i == 0 or v != s[n - 1]) {
            s[n] = v;
            n += 1;
        }
    }
    return a.realloc(s, n);
}

/// Siblings needed to authenticate the (sorted unique) leaves, bottom-up.
pub fn multiproof(a: std.mem.Allocator, tree: pcs.Merkle, leaves: []const usize) ![]Hash {
    var out: std.ArrayList(Hash) = .empty;
    errdefer out.deinit(a);
    const buf = try a.dupe(usize, leaves);
    defer a.free(buf);
    var cur = buf;
    var level_base = tree.n_leaves; // node index of position 0 at this level
    while (level_base > 1) : (level_base /= 2) {
        var n_next: usize = 0;
        var i: usize = 0;
        while (i < cur.len) {
            const pos = cur[i];
            if (i + 1 < cur.len and cur[i + 1] == (pos ^ 1)) {
                i += 2;
            } else {
                try out.append(a, tree.nodes[level_base + (pos ^ 1)]);
                i += 1;
            }
            cur[n_next] = pos >> 1;
            n_next += 1;
        }
        cur = cur[0..n_next];
    }
    return out.toOwnedSlice(a);
}

/// Recomputes the root from sorted unique leaves and their hashes. Consumes
/// exactly all siblings or fails.
pub fn verifyMultiproof(a: std.mem.Allocator, root_h: Hash, log_leaves: u32, leaves: []const usize, leaf_hashes: []const Hash, sibs: []const Hash) !bool {
    std.debug.assert(leaves.len == leaf_hashes.len);
    if (leaves.len == 0) return sibs.len == 0;
    const pos = try a.dupe(usize, leaves);
    defer a.free(pos);
    const hs = try a.dupe(Hash, leaf_hashes);
    defer a.free(hs);
    var n = pos.len;
    const n_leaves = @as(usize, 1) << @intCast(log_leaves);
    for (pos[0..n], 0..) |p, i| {
        if (p >= n_leaves) return false;
        if (i > 0 and p <= pos[i - 1]) return false;
    }
    var si: usize = 0;
    var lvl: u32 = 0;
    while (lvl < log_leaves) : (lvl += 1) {
        var n_next: usize = 0;
        var i: usize = 0;
        while (i < n) {
            const p = pos[i];
            var h: Hash = undefined;
            if (i + 1 < n and pos[i + 1] == (p ^ 1)) {
                h = pcs.hashNode(hs[i], hs[i + 1]);
                i += 2;
            } else {
                if (si >= sibs.len) return false;
                const s = sibs[si];
                si += 1;
                h = if (p & 1 == 0) pcs.hashNode(hs[i], s) else pcs.hashNode(s, hs[i]);
                i += 1;
            }
            pos[n_next] = p >> 1;
            hs[n_next] = h;
            n_next += 1;
        }
        n = n_next;
    }
    return si == sibs.len and n == 1 and std.mem.eql(u8, &hs[0], &root_h);
}

// ---------------------------------------------------------------------------
// Proof objects.

pub const LevelProof = struct {
    pow_nonce: u64 = 0,
    /// opened columns at the sorted unique query positions, concatenated
    /// (rows_used values each)
    col_values: []M31 = &.{},
    decommit: []Hash = &.{},
    /// final level only: the combined rows (proximity row first)
    rows: [][]QM31 = &.{},
    /// non-final levels: root of the committed rows, batching sumcheck,
    /// limb MLE values V~(r_g, c, r_k) for c = 0..3
    inner_root: Hash = [_]u8{0} ** 32,
    sumcheck: sc.Proof = .{ .rounds = &.{}, .deg = 2 },
    limb_vals: [4]QM31 = [_]QM31{QM31.zero()} ** 4,

    pub fn deinit(self: *LevelProof, a: std.mem.Allocator) void {
        a.free(self.col_values);
        a.free(self.decommit);
        for (self.rows) |r| a.free(r);
        a.free(self.rows);
        self.sumcheck.deinit(a);
    }

    pub fn byteSize(self: LevelProof, final: bool) usize {
        var s: usize = 8 + self.col_values.len * 4 + self.decommit.len * 32;
        for (self.rows) |r| s += r.len * 16;
        if (!final) s += 32 + self.sumcheck.byteSize() + 4 * 16;
        return s;
    }
};

pub const Proof = struct {
    levels: []LevelProof,

    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        for (self.levels) |*l| l.deinit(a);
        a.free(self.levels);
    }

    pub fn byteSize(self: Proof) usize {
        var s: usize = 0;
        for (self.levels, 0..) |l, i| s += l.byteSize(i + 1 == self.levels.len);
        return s;
    }
};

// ---------------------------------------------------------------------------
// Shape selection (size model).

fn ceilLog2(n: usize) u32 {
    if (n <= 1) return 0;
    return @intCast(std.math.log2_int_ceil(usize, n));
}

/// Inner table shape for G combined rows of 2^log_c coefficients.
pub const InnerShape = struct {
    log_g: u32,
    log_total: u32,
    log_rows: u32,
    log_cols: u32,
    rows_used: usize,
};

pub fn innerShape(n_rows: usize, log_c: u32, log_cols: u32) InnerShape {
    const log_g = ceilLog2(n_rows);
    const log_total = log_g + 2 + log_c;
    return .{
        .log_g = log_g,
        .log_total = log_total,
        .log_rows = log_total - log_cols,
        .log_cols = log_cols,
        .rows_used = (n_rows * 4) << @intCast(log_c - log_cols),
    };
}

/// Predicted opening bytes of a table with `used` entries split at log_cols,
/// `n_rows` combined rows, with `depth` committed-row levels below.
pub fn predictLevel(params: Params, lvl: usize, log_total: u32, used: usize, log_cols: u32, n_rows: usize, depth: u32) f64 {
    const p = params.level(lvl);
    const C = @as(usize, 1) << @intCast(log_cols);
    const ru = (used + C - 1) / C;
    const t: f64 = @floatFromInt(p.n_queries);
    const log_ext: f64 = @floatFromInt(log_cols + p.log_blowup);
    const sib_levels = @max(1.0, log_ext - std.math.log2(t) + 1.0);
    var bytes: f64 = 8 + t * @as(f64, @floatFromInt(ru)) * 4 + t * sib_levels * 32;
    _ = log_total;
    if (depth == 0) {
        bytes += @as(f64, @floatFromInt(n_rows * C * 16));
    } else {
        const lbi = params.level(lvl + 1).log_blowup;
        const budget = @max(used >> @intCast(params.inner_work_shift), @as(usize, 1) << 14);
        if ((4 * C) << @intCast(lbi) > budget) return std.math.inf(f64);
        const best = bestInner(params, lvl + 1, n_rows, log_cols, depth - 1);
        bytes += 32 + 64 + @as(f64, @floatFromInt(ceilLog2(n_rows) + log_cols)) * 32 + best.bytes;
    }
    return bytes;
}

pub fn bestInner(params: Params, lvl: usize, n_rows: usize, log_c: u32, depth: u32) struct { log_cols: u32, bytes: f64 } {
    var best_lc: u32 = 0;
    var best: f64 = std.math.inf(f64);
    var lc: u32 = 1;
    while (lc <= log_c) : (lc += 1) {
        const sh = innerShape(n_rows, log_c, lc);
        const b = predictLevel(params, lvl, sh.log_total, (n_rows * 4) << @intCast(log_c), lc, 1 + params.prox_rows, depth);
        if (b < best) {
            best = b;
            best_lc = lc;
        }
    }
    return .{ .log_cols = best_lc, .bytes = best };
}

/// Best outer split for a table of 2^log_total entries (used of them nonzero)
/// opened with n_rows combined rows.
pub fn bestOuter(params: Params, log_total: u32, used: usize, n_groups: usize, with_proximity: bool, max_log_cols: u32) struct { log_cols: u32, bytes: f64 } {
    const n_rows = n_groups + params.nProx(with_proximity);
    var best_lc: u32 = 1;
    var best: f64 = std.math.inf(f64);
    var lc: u32 = 1;
    while (lc <= @min(log_total, max_log_cols)) : (lc += 1) {
        const b = predictLevel(params, 0, log_total, used, lc, n_rows, params.depth);
        if (b < best) {
            best = b;
            best_lc = lc;
        }
    }
    return .{ .log_cols = best_lc, .bytes = best };
}

// ---------------------------------------------------------------------------
// Shared transcript logic.

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

fn freeNested(a: std.mem.Allocator, x: anytype) void {
    for (x) |v| a.free(v);
    a.free(x);
}

const Setup = struct {
    gammas: [][]QM31,
    /// combination coefficients per output row (proximity first)
    coeffs: [][]QM31,

    fn deinit(self: *Setup, a: std.mem.Allocator) void {
        freeNested(a, self.gammas);
        freeNested(a, self.coeffs);
    }
};

fn setup(a: std.mem.Allocator, tr: *Transcript, log_rows: u32, groups: []const Group, n_prox: usize) !Setup {
    const R = @as(usize, 1) << @intCast(log_rows);
    for (groups) |g| for (g.claims) |c| tr.mixFelt(c.value);
    const gammas = try a.alloc([]QM31, groups.len);
    for (groups, 0..) |g, gi| {
        gammas[gi] = try a.alloc(QM31, g.claims.len);
        tr.drawN(gammas[gi]);
    }
    const n_out = groups.len + n_prox;
    const coeffs = try a.alloc([]QM31, n_out);
    for (0..n_prox) |k| {
        coeffs[k] = try a.alloc(QM31, R);
        tr.drawN(coeffs[k]);
    }
    for (groups, 0..) |g, gi| coeffs[n_prox + gi] = try groupCoeffs(a, log_rows, g, gammas[gi]);
    return .{ .gammas = gammas, .coeffs = coeffs };
}

fn evalTarget(g: Group, gammas: []const QM31) QM31 {
    var rhs = QM31.zero();
    for (g.claims, gammas) |c, gm| rhs = rhs.add(gm.mul(c.value));
    return rhs;
}

inline fn basisElem(c: usize) QM31 {
    var l = [_]u32{ 0, 0, 0, 0 };
    l[c] = 1;
    return f.fromLimbs(l);
}

fn bitsPoint(out: []QM31, v: usize) void {
    const n = out.len;
    for (0..n) |k| out[k] = if ((v >> @intCast(n - 1 - k)) & 1 == 1) QM31.one() else QM31.zero();
}

// ---------------------------------------------------------------------------
// Prover.

pub fn open(
    comptime T: type,
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    params: Params,
    com: *const pcs.Committed,
    m: pcs.Matrix(T),
    groups: []const Group,
    with_proximity: bool,
) !Proof {
    var levels: std.ArrayList(LevelProof) = .empty;
    errdefer {
        for (levels.items) |*l| l.deinit(a);
        levels.deinit(a);
    }
    try openRec(T, a, pool, tr, params, 0, com, m, groups, with_proximity, &levels);
    return .{ .levels = try levels.toOwnedSlice(a) };
}

fn openColumns(a: std.mem.Allocator, tr: *Transcript, p: pcs.Params, com: *const pcs.Committed, lp: *LevelProof) ![]usize {
    lp.pow_nonce = tr.grind(p.pow_bits);
    const idx = try a.alloc(usize, p.n_queries);
    defer a.free(idx);
    tr.drawIndices(com.logExt(), idx);
    const uq = try sortedUnique(a, idx);
    errdefer a.free(uq);
    const ru = com.rows_used;
    lp.col_values = try a.alloc(M31, uq.len * ru);
    for (uq, 0..) |j, q| @memcpy(lp.col_values[q * ru ..][0..ru], com.column(j));
    lp.decommit = try multiproof(a, com.tree, uq);
    return uq;
}

fn openRec(
    comptime T: type,
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    params: Params,
    lvl: usize,
    com: *const pcs.Committed,
    m: pcs.Matrix(T),
    groups: []const Group,
    with_proximity: bool,
    levels: *std.ArrayList(LevelProof),
) !void {
    const p = params.level(lvl);
    var su = try setup(a, tr, com.log_rows, groups, params.nProx(with_proximity));
    defer su.deinit(a);
    const cview = try a.alloc([]const QM31, su.coeffs.len);
    defer a.free(cview);
    for (su.coeffs, 0..) |c, i| cview[i] = c;
    const rows = try combineRowsAny(T, a, pool, m, cview);
    const n_rows = rows.len;
    try levels.append(a, .{});
    const li = levels.items.len - 1;

    if (lvl == params.depth) {
        // final level: send the rows
        levels.items[li].rows = rows;
        for (rows) |r| tr.mixFelts(r);
        const uq = try openColumns(a, tr, p, com, &levels.items[li]);
        a.free(uq);
        return;
    }
    defer freeNested(a, rows);

    // commit the combined rows: V[g][c][k] = limb_c(u_g[k])
    const log_c = com.log_cols;
    const C = com.nCols();
    const best = bestInner(params, lvl + 1, n_rows, log_c, params.depth - @as(u32, @intCast(lvl)) - 1);
    const ish = innerShape(n_rows, log_c, best.log_cols);
    const G = @as(usize, 1) << @intCast(ish.log_g);
    const vdata = try a.alloc(i32, @as(usize, 1) << @intCast(ish.log_total));
    defer a.free(vdata);
    @memset(vdata, 0);
    {
        const VCtx = struct { rows: []const []const QM31, v: []i32, C: usize };
        const vctx = VCtx{ .rows = rows, .v = vdata, .C = C };
        pool.parallelFor(rows.len * 4, 1, &vctx, struct {
            fn run(c: *const VCtx, s: usize, e: usize) void {
                for (s..e) |gc| {
                    const dst = c.v[gc * c.C ..][0..c.C];
                    for (c.rows[gc / 4], dst) |val, *d| d.* = @intCast(f.limbs(val)[gc % 4]);
                }
            }
        }.run);
    }
    const pi = params.level(lvl + 1);
    var itw = try pcs.Twiddles.init(a, ish.log_cols + pi.log_blowup);
    defer itw.deinit(a);
    const vm = pcs.Matrix(i32){ .data = vdata, .log_rows = ish.log_rows, .log_cols = ish.log_cols, .rows_used = ish.rows_used };
    var vcom = try pcs.commit(i32, a, pool, &itw, vm, pi.log_blowup);
    defer vcom.deinit(a);
    levels.items[li].inner_root = vcom.root();
    tr.mixDigest(vcom.root());

    const rho = try a.alloc(QM31, ish.log_g);
    defer a.free(rho);
    tr.drawN(rho);
    const lambda = try f.eqTable(a, rho, QM31.one());
    defer a.free(lambda);

    const uq = try openColumns(a, tr, p, com, &levels.items[li]);
    defer a.free(uq);

    // y_j = <sum_g lambda_g a_g, col_j>
    const ru = com.rows_used;
    const comb = try a.alloc(QM31, ru);
    defer a.free(comb);
    @memset(comb, QM31.zero());
    for (su.coeffs, 0..) |cf, g| for (comb, cf[0..ru]) |*o, c| {
        o.* = o.add(c.mul(lambda[g]));
    };
    const ys = try a.alloc(QM31, uq.len);
    defer a.free(ys);
    for (uq, 0..) |_, q| {
        var acc = QM31.zero();
        for (comb, levels.items[li].col_values[q * ru ..][0..ru]) |c, v| acc = acc.add(c.mulM31(v));
        ys[q] = acc;
    }
    tr.mixFelts(ys);
    const n_eval = countEval(groups);
    const gp = try a.alloc(QM31, n_eval + uq.len);
    defer a.free(gp);
    tr.drawN(gp);

    // W = sum_eval gp_e (e_g (x) eq(z_col_g)) + lambda (x) (sum_j gp_j T_j)
    const S = try querySum(a, pool, com.logExt(), log_c, uq, gp[n_eval..]);
    defer a.free(S);
    var claim = QM31.zero();
    for (ys, gp[n_eval..]) |y, g| claim = claim.add(g.mul(y));
    const k0 = params.nProx(with_proximity);
    // per U row: optional eq(z_col) table scaled by its gamma'
    const eq_rows = try a.alloc(?[]QM31, G);
    @memset(eq_rows, null);
    defer {
        for (eq_rows) |e| if (e) |x| a.free(x);
        a.free(eq_rows);
    }
    {
        var ei: usize = 0;
        for (groups, 0..) |g, gi| {
            if (g.claims.len == 0) continue;
            const zc = g.claims[0].point[com.log_rows..];
            eq_rows[k0 + gi] = try f.eqTablePar(a, pool, zc, gp[ei]);
            claim = claim.add(gp[ei].mul(evalTarget(g, su.gammas[gi])));
            ei += 1;
        }
    }
    const W = try a.alloc(QM31, G * C);
    defer a.free(W);
    const Uf = try a.alloc(QM31, G * C);
    defer a.free(Uf);
    {
        const WCtx = struct { W: []QM31, Uf: []QM31, S: []const QM31, lambda: []const QM31, eq_rows: []const ?[]QM31, rows: []const []QM31, C: usize };
        const wctx = WCtx{ .W = W, .Uf = Uf, .S = S, .lambda = lambda, .eq_rows = eq_rows, .rows = rows, .C = C };
        const CH = 8192;
        const n_ch = (G * C + CH - 1) / CH;
        pool.parallelFor(n_ch, 1, &wctx, struct {
            fn run(c: *const WCtx, s0: usize, e0: usize) void {
                for (s0..e0) |ch| {
                    const ia = ch * CH;
                    const ib = @min(c.W.len, ia + CH);
                    var i = ia;
                    while (i < ib) {
                        const g = i / c.C;
                        const k_lo = i % c.C;
                        const k_hi = @min(c.C, k_lo + (ib - i));
                        const n = k_hi - k_lo;
                        const lam = c.lambda[g];
                        const wd = c.W[i..][0..n];
                        for (wd, c.S[k_lo..k_hi]) |*d, sv| d.* = sv.mul(lam);
                        if (c.eq_rows[g]) |eqr| for (wd, eqr[k_lo..k_hi]) |*d, e| {
                            d.* = d.add(e);
                        };
                        const ud = c.Uf[i..][0..n];
                        if (g < c.rows.len) @memcpy(ud, c.rows[g][k_lo..k_hi]) else @memset(ud, QM31.zero());
                        i += n;
                    }
                }
            }
        }.run);
    }
    // full length: W is nonzero on the padded (zero) rows of U, and the
    // verifier evaluates the untruncated W~.
    const res = try sc.proveActive(2, &T_PROD2, a, pool, tr, claim, .{ Uf, W }, G * C);
    defer a.free(res.point);
    defer a.free(res.finals);
    levels.items[li].sumcheck = res.proof;

    // limb claims: V~(r_g, c, r_k)
    const r_g = res.point[0..ish.log_g];
    const r_k = res.point[ish.log_g..];
    var pts: [4][]QM31 = undefined;
    for (&pts, 0..) |*pt, c| {
        pt.* = try a.alloc(QM31, ish.log_total);
        @memcpy(pt.*[0..ish.log_g], r_g);
        bitsPoint(pt.*[ish.log_g..][0..2], c);
        @memcpy(pt.*[ish.log_g + 2 ..], r_k);
    }
    defer for (pts) |pt| a.free(pt);
    var lc: [4]Claim = undefined;
    levels.items[li].limb_vals = try limbMles(a, pool, rows, res.point, ish.log_g);
    for (0..4) |c| lc[c] = .{ .point = pts[c], .value = levels.items[li].limb_vals[c] };
    tr.mixFelts(&levels.items[li].limb_vals);
    const ngroups = [_]Group{.{ .claims = &lc }};
    try openRec(i32, a, pool, tr, params, lvl + 1, &vcom, vm, &ngroups, true, levels);
}

const T_PROD2 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }};

fn countEval(groups: []const Group) usize {
    var n: usize = 0;
    for (groups) |g| n += @intFromBool(g.claims.len > 0);
    return n;
}

/// MLEs of the four limbs of the stacked rows (G' x C, zero padded) at point,
/// in one parallel pass.
fn limbMles(a: std.mem.Allocator, pool: *f.Pool, rows: []const []const QM31, point: []const QM31, log_g: u32) ![4]QM31 {
    const C = rows[0].len;
    const eq_g = try f.eqTable(a, point[0..log_g], QM31.one());
    defer a.free(eq_g);
    const eq_k = try f.eqTablePar(a, pool, point[log_g..], QM31.one());
    defer a.free(eq_k);
    const CH = 4096;
    const n_ch = (C + CH - 1) / CH;
    const part = try a.alloc([4]QM31, n_ch);
    defer a.free(part);
    const Ctx = struct { rows: []const []const QM31, eq_g: []const QM31, eq_k: []const QM31, part: [][4]QM31, C: usize };
    const ctx = Ctx{ .rows = rows, .eq_g = eq_g, .eq_k = eq_k, .part = part, .C = C };
    pool.parallelFor(n_ch, 1, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |ch| {
                const k0 = ch * CH;
                const k1 = @min(c.C, k0 + CH);
                var acc = [_]QM31{QM31.zero()} ** 4;
                for (c.rows, 0..) |r, g| {
                    var sg = [_]QM31{QM31.zero()} ** 4;
                    for (r[k0..k1], c.eq_k[k0..k1]) |v, ek| {
                        const l = f.limbs(v);
                        inline for (0..4) |li| sg[li] = sg[li].add(ek.mulM31(M31.fromU32Unchecked(l[li])));
                    }
                    inline for (0..4) |li| acc[li] = acc[li].add(sg[li].mul(c.eq_g[g]));
                }
                c.part[ch] = acc;
            }
        }
    }.run);
    var out = [_]QM31{QM31.zero()} ** 4;
    for (part) |p| inline for (0..4) |li| {
        out[li] = out[li].add(p[li]);
    };
    return out;
}

/// S[k] = sum_q gp[q] T_{j_q}[k] where T_j is the circle-basis tensor at j.
fn querySum(a: std.mem.Allocator, pool: *f.Pool, log_ext: u32, log_c: u32, js: []const usize, gp: []const QM31) ![]QM31 {
    const C = @as(usize, 1) << @intCast(log_c);
    const S = try a.alloc(QM31, C);
    @memset(S, QM31.zero());
    const nq = js.len;
    const llo: u32 = @min(log_c, 10);
    const lhi = log_c - llo;
    const LO = @as(usize, 1) << @intCast(llo);
    const HI = @as(usize, 1) << @intCast(lhi);
    // per query: hi table scaled by gamma (QM31), lo table (M31)
    const his = try a.alloc(QM31, nq * HI);
    defer a.free(his);
    const los = try a.alloc(M31, nq * LO);
    defer a.free(los);
    const fac = try a.alloc(M31, log_c);
    defer a.free(fac);
    for (js, 0..) |j, q| {
        circleFactors(log_ext, j, log_c, fac);
        const th = try tensorTable(a, fac[0..lhi]);
        defer a.free(th);
        const tl = try tensorTable(a, fac[lhi..]);
        defer a.free(tl);
        for (th, his[q * HI ..][0..HI]) |h, *o| o.* = gp[q].mulM31(h);
        @memcpy(los[q * LO ..][0..LO], tl);
    }
    const Ctx = struct { S: []QM31, his: []const QM31, los: []const M31, nq: usize, HI: usize, LO: usize };
    const ctx = Ctx{ .S = S, .his = his, .los = los, .nq = nq, .HI = HI, .LO = LO };
    pool.parallelFor(HI, 1, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |hi| {
                const dst = c.S[hi * c.LO ..][0..c.LO];
                for (0..c.nq) |q| {
                    const h = c.his[q * c.HI + hi];
                    for (dst, c.los[q * c.LO ..][0..c.LO]) |*d, l| d.* = d.add(h.mulM31(l));
                }
            }
        }
    }.run);
    return S;
}

/// combineRows for any table element type (i8 weights, i32 witness / M31 limbs).
fn combineRowsAny(comptime T: type, a: std.mem.Allocator, pool: *f.Pool, m: pcs.Matrix(T), coeffs: []const []const QM31) ![][]QM31 {
    return pcs.combineRows(T, a, pool, m, coeffs, if (@bitSizeOf(T) <= 8) 7 else 30);
}

// ---------------------------------------------------------------------------
// Verifier.

pub fn verify(
    a: std.mem.Allocator,
    tr: *Transcript,
    params: Params,
    shape: Shape,
    root_h: Hash,
    groups: []const Group,
    with_proximity: bool,
    proof: Proof,
) !void {
    if (proof.levels.len != params.depth + 1) return error.OpeningShape;
    if (shape.log_blowup != params.outer.log_blowup) return error.OpeningShape;
    try verifyRec(a, tr, params, 0, shape, root_h, groups, with_proximity, proof);
}

fn checkColumns(a: std.mem.Allocator, tr: *Transcript, p: pcs.Params, log_ext: u32, ru: usize, root_h: Hash, lp: LevelProof) ![]usize {
    if (!tr.verifyPow(p.pow_bits, lp.pow_nonce)) return error.OpeningPow;
    const idx = try a.alloc(usize, p.n_queries);
    defer a.free(idx);
    tr.drawIndices(log_ext, idx);
    const uq = try sortedUnique(a, idx);
    errdefer a.free(uq);
    if (lp.col_values.len != uq.len * ru) return error.OpeningShape;
    const hs = try a.alloc(Hash, uq.len);
    defer a.free(hs);
    for (hs, 0..) |*h, q| h.* = pcs.hashColumn(lp.col_values[q * ru ..][0..ru]);
    if (!try verifyMultiproof(a, root_h, log_ext, uq, hs, lp.decommit)) return error.OpeningMerkle;
    return uq;
}

fn verifyRec(
    a: std.mem.Allocator,
    tr: *Transcript,
    params: Params,
    lvl: usize,
    shape: Shape,
    root_h: Hash,
    groups: []const Group,
    with_proximity: bool,
    proof: Proof,
) !void {
    const p = params.level(lvl);
    const lp = proof.levels[lvl];
    const R = @as(usize, 1) << @intCast(shape.log_rows);
    const RU = shape.rows_used orelse R;
    if (RU > R or RU == 0) return error.OpeningShape;
    const log_c = shape.log_cols;
    const C = @as(usize, 1) << @intCast(log_c);
    const log_ext = log_c + p.log_blowup;
    for (groups) |g| for (g.claims) |c| {
        if (c.point.len != shape.log_rows + shape.log_cols) return error.OpeningShape;
        for (c.point[shape.log_rows..], g.claims[0].point[shape.log_rows..]) |x, y| if (!x.eql(y)) return error.OpeningGroupMismatch;
    };
    var su = try setup(a, tr, shape.log_rows, groups, params.nProx(with_proximity));
    defer su.deinit(a);
    const n_rows = su.coeffs.len;
    const k0 = params.nProx(with_proximity);
    const fac = try a.alloc(M31, log_c);
    defer a.free(fac);

    if (lvl == params.depth) {
        if (lp.rows.len != n_rows) return error.OpeningShape;
        for (lp.rows) |r| {
            if (r.len != C) return error.OpeningShape;
            tr.mixFelts(r);
        }
        for (groups, 0..) |g, gi| {
            if (g.claims.len == 0) continue;
            const v = try f.mleEval(a, lp.rows[k0 + gi], g.claims[0].point[shape.log_rows..]);
            if (!v.eql(evalTarget(g, su.gammas[gi]))) return error.OpeningEvalMismatch;
        }
        const uq = try checkColumns(a, tr, p, log_ext, RU, root_h, lp);
        defer a.free(uq);
        for (uq, 0..) |j, q| {
            circleFactors(log_ext, j, log_c, fac);
            const col = lp.col_values[q * RU ..][0..RU];
            for (su.coeffs, lp.rows) |cf, r| {
                var acc = QM31.zero();
                for (cf[0..RU], col) |c, v| acc = acc.add(c.mulM31(v));
                if (!acc.eql(try evalCoeffs(a, r, fac))) return error.OpeningColumnMismatch;
            }
        }
        return;
    }

    if (lp.rows.len != 0) return error.OpeningShape;
    const sub_depth = params.depth - @as(u32, @intCast(lvl)) - 1;
    const best = bestInner(params, lvl + 1, n_rows, log_c, sub_depth);
    const ish = innerShape(n_rows, log_c, best.log_cols);
    tr.mixDigest(lp.inner_root);
    const rho = try a.alloc(QM31, ish.log_g);
    defer a.free(rho);
    tr.drawN(rho);
    const lambda = try f.eqTable(a, rho, QM31.one());
    defer a.free(lambda);
    const uq = try checkColumns(a, tr, p, log_ext, RU, root_h, lp);
    defer a.free(uq);
    const comb = try a.alloc(QM31, RU);
    defer a.free(comb);
    @memset(comb, QM31.zero());
    for (su.coeffs, 0..) |cf, g| for (comb, cf[0..RU]) |*o, c| {
        o.* = o.add(c.mul(lambda[g]));
    };
    const ys = try a.alloc(QM31, uq.len);
    defer a.free(ys);
    for (uq, 0..) |_, q| {
        var acc = QM31.zero();
        for (comb, lp.col_values[q * RU ..][0..RU]) |c, v| acc = acc.add(c.mulM31(v));
        ys[q] = acc;
    }
    tr.mixFelts(ys);
    const n_eval = countEval(groups);
    const gp = try a.alloc(QM31, n_eval + uq.len);
    defer a.free(gp);
    tr.drawN(gp);
    var claim = QM31.zero();
    for (ys, gp[n_eval..]) |y, g| claim = claim.add(g.mul(y));
    {
        var ei: usize = 0;
        for (groups, 0..) |g, gi| {
            if (g.claims.len == 0) continue;
            claim = claim.add(gp[ei].mul(evalTarget(g, su.gammas[gi])));
            ei += 1;
        }
    }
    const vr = try sc.verify(a, tr, claim, ish.log_g + log_c, 2, lp.sumcheck);
    defer a.free(vr.point);
    const r_g = vr.point[0..ish.log_g];
    const r_k = vr.point[ish.log_g..];
    // W~(r)
    var w_at = QM31.zero();
    {
        var ei: usize = 0;
        const gbits = try a.alloc(QM31, ish.log_g);
        defer a.free(gbits);
        for (groups, 0..) |g, gi| {
            if (g.claims.len == 0) continue;
            bitsPoint(gbits, k0 + gi);
            const e = f.eqEval(r_g, gbits).mul(f.eqEval(r_k, g.claims[0].point[shape.log_rows..]));
            w_at = w_at.add(gp[ei].mul(e));
            ei += 1;
        }
        var qs = QM31.zero();
        for (uq, 0..) |j, q| {
            circleFactors(log_ext, j, log_c, fac);
            qs = qs.add(gp[n_eval + q].mul(tensorEvalAt(fac, r_k)));
        }
        w_at = w_at.add(f.eqEval(r_g, rho).mul(qs));
    }
    var u_at = QM31.zero();
    for (lp.limb_vals, 0..) |v, c| u_at = u_at.add(basisElem(c).mul(v));
    if (!vr.final_claim.eql(u_at.mul(w_at))) return error.OpeningSumcheck;
    tr.mixFelts(&lp.limb_vals);

    var pts: [4][]QM31 = undefined;
    for (&pts, 0..) |*pt, c| {
        pt.* = try a.alloc(QM31, ish.log_total);
        @memcpy(pt.*[0..ish.log_g], r_g);
        bitsPoint(pt.*[ish.log_g..][0..2], c);
        @memcpy(pt.*[ish.log_g + 2 ..], r_k);
    }
    defer for (pts) |pt| a.free(pt);
    var lc: [4]Claim = undefined;
    for (0..4) |c| lc[c] = .{ .point = pts[c], .value = lp.limb_vals[c] };
    const ngroups = [_]Group{.{ .claims = &lc }};
    const pi = params.level(lvl + 1);
    const ishape = Shape{ .log_rows = ish.log_rows, .log_cols = ish.log_cols, .log_blowup = pi.log_blowup, .rows_used = ish.rows_used };
    try verifyRec(a, tr, params, lvl + 1, ishape, lp.inner_root, &ngroups, true, proof);
}

/// Groups claims by identical column part of their point (order preserving).
pub fn groupByColumn(a: std.mem.Allocator, claims: []const Claim, log_rows: u32) ![]Group {
    var groups: std.ArrayList(std.ArrayList(Claim)) = .empty;
    defer groups.deinit(a);
    outer: for (claims) |c| {
        for (groups.items) |*g| {
            const z = g.items[0].point[log_rows..];
            var same = true;
            for (c.point[log_rows..], z) |x, y| {
                if (!x.eql(y)) {
                    same = false;
                    break;
                }
            }
            if (same) {
                try g.append(a, c);
                continue :outer;
            }
        }
        var ng: std.ArrayList(Claim) = .empty;
        try ng.append(a, c);
        try groups.append(a, ng);
    }
    const out = try a.alloc(Group, groups.items.len);
    for (groups.items, 0..) |*g, i| out[i] = .{ .claims = try g.toOwnedSlice(a) };
    return out;
}

pub fn freeGroups(a: std.mem.Allocator, groups: []Group) void {
    for (groups) |g| a.free(g.claims);
    a.free(groups);
}

// ---------------------------------------------------------------------------
// Tests.

test "circle factors reproduce the stwo circle-FFT encoding" {
    const a = std.testing.allocator;
    const log_c = 5;
    const lb = 2;
    var tw = try pcs.Twiddles.init(a, log_c + lb);
    defer tw.deinit(a);
    const E = @as(usize, 1) << (log_c + lb);
    const buf = try a.alloc(M31, E);
    defer a.free(buf);
    var prng = std.Random.DefaultPrng.init(3);
    var coeffs: [1 << log_c]QM31 = undefined;
    for (&coeffs, 0..) |*c, i| {
        buf[i] = M31.fromCanonical(prng.random().intRangeLessThan(u32, 0, f.P));
        c.* = QM31.fromBase(buf[i]);
    }
    tw.encode(buf, 1 << log_c);
    var fac: [log_c]M31 = undefined;
    for (0..E) |j| {
        circleFactors(log_c + lb, j, log_c, &fac);
        const v = try evalCoeffs(a, &coeffs, &fac);
        try std.testing.expect(v.eql(QM31.fromBase(buf[j])));
        // tensor table dot product agrees
        const tt = try tensorTable(a, &fac);
        defer a.free(tt);
        var acc = QM31.zero();
        for (coeffs, tt) |c, t| acc = acc.add(c.mulM31(t));
        try std.testing.expect(acc.eql(v));
    }
    // MLE of the tensor table at a random point
    var r: [log_c]QM31 = undefined;
    for (&r, 0..) |*x, i| x.* = QM31.fromU32Unchecked(@intCast(i * 13 + 5), 7, @intCast(i), 1);
    circleFactors(log_c + lb, 9, log_c, &fac);
    const tt = try tensorTable(a, &fac);
    defer a.free(tt);
    var tq: [1 << log_c]QM31 = undefined;
    for (&tq, tt) |*o, t| o.* = QM31.fromBase(t);
    try std.testing.expect((try f.mleEval(a, &tq, &r)).eql(tensorEvalAt(&fac, &r)));
}

test "merkle multiproof roundtrip and rejection" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const lc = 5;
    var tw = try pcs.Twiddles.init(a, lc + 1);
    defer tw.deinit(a);
    var data: [4 << lc]i8 = undefined;
    for (&data, 0..) |*d, i| d.* = @intCast(@as(i32, @intCast(i % 200)) - 100);
    const m = pcs.Matrix(i8){ .data = &data, .log_rows = 2, .log_cols = lc };
    var com = try pcs.commit(i8, a, &pool, &tw, m, 1);
    defer com.deinit(a);
    const idx = [_]usize{ 3, 2, 17, 63, 40, 41, 17 };
    const uq = try sortedUnique(a, &idx);
    defer a.free(uq);
    try std.testing.expectEqual(@as(usize, 6), uq.len);
    const sibs = try multiproof(a, com.tree, uq);
    defer a.free(sibs);
    const hs = try a.alloc(Hash, uq.len);
    defer a.free(hs);
    for (uq, hs) |j, *h| h.* = pcs.hashColumn(com.column(j));
    try std.testing.expect(try verifyMultiproof(a, com.root(), lc + 1, uq, hs, sibs));
    try std.testing.expect(sibs.len < uq.len * (lc + 1));
    hs[2][0] ^= 1;
    try std.testing.expect(!try verifyMultiproof(a, com.root(), lc + 1, uq, hs, sibs));
    hs[2][0] ^= 1;
    try std.testing.expect(!try verifyMultiproof(a, com.root(), lc + 1, uq, hs, sibs[0 .. sibs.len - 1]));
    // wrong position
    var uq2 = try a.dupe(usize, uq);
    defer a.free(uq2);
    uq2[0] = 4;
    try std.testing.expect(!try verifyMultiproof(a, com.root(), lc + 1, uq2, hs, sibs));
}

fn testTable(a: std.mem.Allocator, lr: u32, lc: u32, seed: u64) ![]i8 {
    const data = try a.alloc(i8, @as(usize, 1) << @intCast(lr + lc));
    var prng = std.Random.DefaultPrng.init(seed);
    for (data) |*d| d.* = prng.random().int(i8);
    return data;
}

fn runRoundtrip(depth: u32) !void {
    try runRoundtripProx(depth, 1);
}

fn runRoundtripProx(depth: u32, prox_rows: u32) !void {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const lr = 3;
    const lc = 9;
    const R = 1 << lr;
    const C = 1 << lc;
    const data = try testTable(a, lr, lc, 11);
    defer a.free(data);
    const ru: usize = R - 2; // last two rows zero and uncommitted
    @memset(data[ru * C ..], 0);
    const m = pcs.Matrix(i8){ .data = data, .log_rows = lr, .log_cols = lc, .rows_used = ru };
    const params = Params{
        .outer = .{ .log_blowup = 2, .n_queries = 24, .pow_bits = 3 },
        .inner = .{ .log_blowup = 3, .n_queries = 16, .pow_bits = 2 },
        .depth = depth,
        .prox_rows = prox_rows,
    };
    var tw = try pcs.Twiddles.init(a, lc + 2);
    defer tw.deinit(a);
    var com = try pcs.commit(i8, a, &pool, &tw, m, 2);
    defer com.deinit(a);
    var pts: [3][lr + lc]QM31 = undefined;
    for (0..3) |c| for (0..lr + lc) |i| {
        pts[c][i] = QM31.fromU32Unchecked(@intCast(c * 31 + i * 7 + 1), @intCast(i), 3, @intCast(c));
    };
    for (0..lc) |i| pts[1][lr + i] = pts[0][lr + i];
    const ints = try a.alloc(i32, R * C);
    defer a.free(ints);
    for (data, ints) |d, *x| x.* = d;
    var vals: [3]QM31 = undefined;
    for (0..3) |c| vals[c] = try f.mleEvalI32(a, ints, &pts[c]);
    const claims = [_]Claim{ .{ .point = &pts[0], .value = vals[0] }, .{ .point = &pts[1], .value = vals[1] }, .{ .point = &pts[2], .value = vals[2] } };
    const groups = try groupByColumn(a, &claims, lr);
    defer freeGroups(a, groups);
    try std.testing.expectEqual(@as(usize, 2), groups.len);
    const shape = Shape{ .log_rows = lr, .log_cols = lc, .log_blowup = 2, .rows_used = ru };

    for ([_]bool{ true, false }) |prox| {
        var tp = Transcript.initDomain("pcs2");
        var proof = try open(i8, a, &pool, &tp, params, &com, m, groups, prox);
        defer proof.deinit(a);
        try std.testing.expectEqual(@as(usize, depth + 1), proof.levels.len);
        var tv = Transcript.initDomain("pcs2");
        try verify(a, &tv, params, shape, com.root(), groups, prox, proof);
        // prover and verifier transcripts end in the same state
        try std.testing.expect(tp.draw().eql(tv.draw()));

        // wrong claimed value
        const bad = [_]Claim{.{ .point = &pts[2], .value = vals[2].add(QM31.one()) }};
        const groups_bad = [_]Group{ groups[0], .{ .claims = &bad } };
        var tv2 = Transcript.initDomain("pcs2");
        try std.testing.expect(std.meta.isError(verify(a, &tv2, params, shape, com.root(), &groups_bad, prox, proof)));
        // wrong root
        var root2 = com.root();
        root2[5] ^= 1;
        var tv3 = Transcript.initDomain("pcs2");
        try std.testing.expect(std.meta.isError(verify(a, &tv3, params, shape, root2, groups, prox, proof)));
        // tamper every component of every level
        for (proof.levels, 0..) |*lp, li| {
            {
                lp.col_values[1] = lp.col_values[1].add(M31.one());
                var t = Transcript.initDomain("pcs2");
                try std.testing.expect(std.meta.isError(verify(a, &t, params, shape, com.root(), groups, prox, proof)));
                lp.col_values[1] = lp.col_values[1].sub(M31.one());
            }
            {
                lp.decommit[0][0] ^= 1;
                var t = Transcript.initDomain("pcs2");
                try std.testing.expect(std.meta.isError(verify(a, &t, params, shape, com.root(), groups, prox, proof)));
                lp.decommit[0][0] ^= 1;
            }
            if (li + 1 == proof.levels.len) {
                const r = lp.rows[lp.rows.len - 1];
                r[3] = r[3].add(QM31.one());
                var t = Transcript.initDomain("pcs2");
                try std.testing.expect(std.meta.isError(verify(a, &t, params, shape, com.root(), groups, prox, proof)));
                r[3] = r[3].sub(QM31.one());
            } else {
                lp.limb_vals[2] = lp.limb_vals[2].add(QM31.one());
                var t = Transcript.initDomain("pcs2");
                try std.testing.expect(std.meta.isError(verify(a, &t, params, shape, com.root(), groups, prox, proof)));
                lp.limb_vals[2] = lp.limb_vals[2].sub(QM31.one());
                lp.inner_root[0] ^= 1;
                var t2 = Transcript.initDomain("pcs2");
                try std.testing.expect(std.meta.isError(verify(a, &t2, params, shape, com.root(), groups, prox, proof)));
                lp.inner_root[0] ^= 1;
                lp.sumcheck.rounds[0].evals[0] = lp.sumcheck.rounds[0].evals[0].add(QM31.one());
                var t3 = Transcript.initDomain("pcs2");
                try std.testing.expect(std.meta.isError(verify(a, &t3, params, shape, com.root(), groups, prox, proof)));
                lp.sumcheck.rounds[0].evals[0] = lp.sumcheck.rounds[0].evals[0].sub(QM31.one());
            }
            lp.pow_nonce +%= 1;
            var t = Transcript.initDomain("pcs2");
            try std.testing.expect(std.meta.isError(verify(a, &t, params, shape, com.root(), groups, prox, proof)));
            lp.pow_nonce -%= 1;
        }
        // untampered proof still verifies
        var tv4 = Transcript.initDomain("pcs2");
        try verify(a, &tv4, params, shape, com.root(), groups, prox, proof);
    }
}

test "pcs2 depth 0 (plain Ligero + multiproof) roundtrip and tampering" {
    try runRoundtrip(0);
}

test "pcs2 depth 1 roundtrip and tampering" {
    try runRoundtrip(1);
}

test "pcs2 depth 2 roundtrip and tampering" {
    try runRoundtrip(2);
}

test "pcs2 with two proximity rows (depth 0 and 2)" {
    try runRoundtripProx(0, 2);
    try runRoundtripProx(2, 2);
}

test "pcs2 depth 3 roundtrip and tampering" {
    try runRoundtrip(3);
}

test "pcs2 rejects a committed table that is not a codeword" {
    // Corrupt a fraction of the encoded table after commitment (so the Merkle
    // root binds a non-codeword); the proximity test must reject with high
    // probability at depth 1.
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const lr = 3;
    const lc = 8;
    const data = try testTable(a, lr, lc, 5);
    defer a.free(data);
    const m = pcs.Matrix(i8){ .data = data, .log_rows = lr, .log_cols = lc };
    var tw = try pcs.Twiddles.init(a, lc + 2);
    defer tw.deinit(a);
    var com = try pcs.commit(i8, a, &pool, &tw, m, 2);
    defer com.deinit(a);
    // corrupt half the encoded columns of row 0 (beyond unique decoding)
    const R = com.rows_used;
    var j: usize = 0;
    while (j < (com.enc.len / R)) : (j += 2) com.enc[j * R] = com.enc[j * R].add(M31.one());
    com.tree.deinit(a);
    com.tree = try rebuildTree(a, &pool, com.enc, R, com.enc.len / R);
    const params = Params{ .outer = .{ .log_blowup = 2, .n_queries = 24, .pow_bits = 0 }, .inner = .{ .log_blowup = 2, .n_queries = 16, .pow_bits = 0 }, .depth = 1 };
    var tp = Transcript.initDomain("prox");
    var proof = try open(i8, a, &pool, &tp, params, &com, m, &.{}, true);
    defer proof.deinit(a);
    var tv = Transcript.initDomain("prox");
    try std.testing.expect(std.meta.isError(verify(a, &tv, params, .{ .log_rows = lr, .log_cols = lc, .log_blowup = 2 }, com.root(), &.{}, true, proof)));
}

fn rebuildTree(a: std.mem.Allocator, pool: *f.Pool, enc: []const M31, R: usize, E: usize) !pcs.Merkle {
    _ = pool;
    const nodes = try a.alloc(Hash, 2 * E);
    for (0..E) |j| nodes[E + j] = pcs.hashColumn(enc[j * R .. (j + 1) * R]);
    var i = E - 1;
    while (i >= 1) : (i -= 1) nodes[i] = pcs.hashNode(nodes[2 * i], nodes[2 * i + 1]);
    return .{ .nodes = nodes, .n_leaves = E };
}

test "size model prefers wide outer tables" {
    const params = Params{ .outer = .{ .log_blowup = 2, .n_queries = 64, .pow_bits = 20 }, .depth = 1 };
    const b = bestOuter(params, 27, 100_663_296, 3, false, 26);
    try std.testing.expect(b.log_cols >= 16);
    const flat = Params{ .outer = params.outer, .depth = 0 };
    const b0 = bestOuter(flat, 27, 100_663_296, 3, false, 26);
    try std.testing.expect(b.bytes < b0.bytes / 2);
}
