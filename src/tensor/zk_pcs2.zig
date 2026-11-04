//! Hiding recursive tensor PCS: the zk_pcs.zig commitments and masked
//! combination rows, opened with pcs2's committed combined rows.
//!
//! Outer level (the hiding tables of zk_pcs.zig: masked encoding with `slots`
//! random coefficients, salted leaves, 4 mask rows per combined row):
//!
//!   1. the caller mixes the claim values and mus and draws the combination
//!      coefficients exactly as for a flat hiding opening (`zkp.drawCoeffs`),
//!      then computes the combined rows u_o (length C + S, slot part included;
//!      every u_o carries c * sum_k e_k M_k of its own mask rows);
//!   2. instead of sending the u_o, the prover commits V[g][c][k] = limb_c(u_g[k])
//!      (rows zero-padded to G' = 2^ceil(log G) and to a 2C-coefficient
//!      message) with a plain `pcs.commit` (inner parameters);
//!   3. rho -> lambda = eq(rho, .), PoW, t query positions shared by all outer
//!      tables (lifetime budgets are charged before anything is released); the
//!      prover opens the salted outer columns with one Merkle multiproof per
//!      table, and the verifier computes y_j = <sum_o lambda_o A_o, col_j>;
//!   4. claims on U: the eval checks <u_g[0..C), b_g> = sum gamma v + gamma_mu mu_g
//!      and the head-restricted encodings sum_g lambda_g Enc_head(u_g)[j] = y_j
//!      (Enc_head uses only the C + S coefficients the outer code has, so a
//!      prover gains nothing from the zero-padding tail); one degree-2
//!      sumcheck over the G' x 2C cube reduces them to U~(r), the four limb
//!      MLEs are sent and become one claim group of the next level;
//!   5. levels >= 1 are plain (non-hiding) pcs2 levels (`pcs2.openRec`).
//!
//! Zero knowledge (design/tensor-frontend/zk.md, §3.5): everything revealed
//! from step 2 on is a function of (U, fresh inner randomness, public coins),
//! and Lemma 2 of the flat hiding PCS already simulates (mu, U, outer columns)
//! jointly. So the inner levels need no masks, slots or salts of their own and
//! no opening budget; only the outer tables' budgets (slots/2 columns) apply.
//! Soundness: pcs2's committed-row argument (size.md §4.1) over the stacked
//! outer tables, with the code of message length C + S.
const std = @import("std");
const f = @import("field.zig");
const pcs = @import("pcs.zig");
const pcs2 = @import("pcs2.zig");
const zkp = @import("zk_pcs.zig");
const sc = @import("sumcheck.zig");
const accel = @import("accel.zig");
const Transcript = @import("transcript.zig").Transcript;

const M31 = f.M31;
const QM31 = f.QM31;
const Hash = [32]u8;
const SALT = zkp.SALT;

pub const TableCols = struct {
    /// opened columns at the sorted unique query positions (n_rows values each)
    values: []M31,
    salts: [][SALT]u8,
    /// Merkle multiproof siblings
    decommit: []Hash,
};

pub const Opening = struct {
    mus: []QM31,
    pow_nonce: u64,
    tables: []TableCols,
    inner_root: Hash,
    sumcheck: sc.Proof,
    limb_vals: [4]QM31,
    /// levels[0] is an empty placeholder (the outer level lives above);
    /// levels[1..] are the plain pcs2 levels of the committed rows.
    inner: pcs2.Proof,

    pub fn deinit(self: *Opening, a: std.mem.Allocator) void {
        a.free(self.mus);
        for (self.tables) |t| {
            a.free(t.values);
            a.free(t.salts);
            a.free(t.decommit);
        }
        a.free(self.tables);
        self.sumcheck.deinit(a);
        self.inner.deinit(a);
    }

    /// Bytes per part: [outer columns + salts, outer multiproof, outer rest, level 1, level 2, ...].
    pub fn levelSizes(self: Opening, out: []usize) []usize {
        out[0] = 0;
        out[1] = 0;
        for (self.tables) |t| {
            out[0] += t.values.len * 4 + t.salts.len * SALT;
            out[1] += t.decommit.len * 32;
        }
        out[2] = 8 + self.mus.len * 16 + 32 + self.sumcheck.byteSize() + 4 * 16;
        const nl = self.inner.levels.len;
        for (self.inner.levels[1..], 1..) |l, i| out[2 + i] = l.byteSize(i + 1 == nl);
        return out[0 .. 2 + nl];
    }

    pub fn byteSize(self: Opening) usize {
        var s: usize = 8 + self.mus.len * 16 + 32 + self.sumcheck.byteSize() + 4 * 16;
        for (self.tables) |t| s += t.values.len * 4 + t.salts.len * SALT + t.decommit.len * 32;
        const nl = self.inner.levels.len;
        for (self.inner.levels[1..], 1..) |l, i| s += l.byteSize(i + 1 == nl);
        return s;
    }
};

/// Inner-level parameters with the outer level's parameters in `outer` (used by
/// pcs2's shape search only).
fn innerParams(outer: pcs.Params, p2: pcs2.Params) pcs2.Params {
    var pp = p2;
    pp.outer = outer;
    return pp;
}

/// Shape of the committed-row table for `n_out` combined rows of a table with 2^lc columns.
pub fn innerShapeFor(outer: pcs.Params, p2: pcs2.Params, n_out: usize, lc: u32) pcs2.InnerShape {
    const pp = innerParams(outer, p2);
    const best = pcs2.bestInner(pp, 1, n_out, lc + 1, p2.depth - 1);
    return pcs2.innerShape(n_out, lc + 1, best.log_cols);
}

/// Predicted opening bytes of a hiding table (rows committed rows incl. masks,
/// 2^lc columns) opened with `n_out` combined rows: the outer level plus the
/// pcs2 levels below (pcs2's size model). Deterministic in public sizes.
pub fn predictBytes(outer: pcs.Params, p2: pcs2.Params, n_rows: usize, lc: u32, n_out: usize) f64 {
    const pp = innerParams(outer, p2);
    const t: f64 = @floatFromInt(outer.n_queries);
    const log_ext: f64 = @floatFromInt(lc + outer.log_blowup);
    const sib_levels = @max(1.0, log_ext - std.math.log2(t) + 1.0);
    const best = pcs2.bestInner(pp, 1, n_out, lc + 1, p2.depth - 1);
    const lg: f64 = @floatFromInt(std.math.log2_int_ceil(usize, @max(n_out, 2)));
    return 8 + t * @as(f64, @floatFromInt(n_rows)) * 4 + t * (SALT + sib_levels * 32) + 32 + 64 + (lg + @as(f64, @floatFromInt(lc + 1))) * 32 + best.bytes;
}

fn freeOne(t: TableCols, a: std.mem.Allocator) void {
    a.free(t.values);
    a.free(t.salts);
    a.free(t.decommit);
}

inline fn freeVar(fv: M31, r: QM31) QM31 {
    return QM31.one().add(r.mulM31(fv.sub(M31.one())));
}

/// MLE at r (MSB-first, len lc + 1) of the circle-basis tensor with factors
/// `fac` restricted to the head [0, C + S) of a 2C-coefficient message
/// (zero on the tail [C + S, 2C)), with S = 2^log_s <= C.
pub fn headEval(fac: []const M31, r: []const QM31, log_s: u32) QM31 {
    const n = fac.len;
    std.debug.assert(r.len == n and log_s + 1 <= n);
    // block [0, C): top bit 0, all lower bits free
    var lo = QM31.one().sub(r[0]);
    for (1..n) |v| lo = lo.mul(freeVar(fac[v], r[v]));
    // block [C, C + S): top bit 1, middle bits 0, low log_s bits free
    var hi = r[0].mulM31(fac[0]);
    for (1..n - log_s) |v| hi = hi.mul(QM31.one().sub(r[v]));
    for (n - log_s..n) |v| hi = hi.mul(freeVar(fac[v], r[v]));
    return lo.add(hi);
}

fn evalTarget(g: zkp.Group, gammas: []const QM31, mu: QM31) QM31 {
    var rhs = QM31.zero();
    for (g.claims, 0..) |c, ci| rhs = rhs.add(gammas[ci].mul(c.value));
    return rhs.add(gammas[g.claims.len].mul(mu));
}

fn limbPoints(a: std.mem.Allocator, ish: pcs2.InnerShape, point: []const QM31) ![4][]QM31 {
    var pts: [4][]QM31 = undefined;
    for (&pts, 0..) |*pt, c| {
        pt.* = try a.alloc(QM31, ish.log_total);
        @memcpy(pt.*[0..ish.log_g], point[0..ish.log_g]);
        pt.*[ish.log_g] = if (c >> 1 == 1) QM31.one() else QM31.zero();
        pt.*[ish.log_g + 1] = if (c & 1 == 1) QM31.one() else QM31.zero();
        @memcpy(pt.*[ish.log_g + 2 ..], point[ish.log_g..]);
    }
    return pts;
}

fn bitsEq(r: []const QM31, v: usize) QM31 {
    const n = r.len;
    var acc = QM31.one();
    for (0..n) |k| {
        const bit = (v >> @intCast(n - 1 - k)) & 1 == 1;
        acc = acc.mul(if (bit) r[k] else QM31.one().sub(r[k]));
    }
    return acc;
}

/// y_q = sum_o lambda_o sum_t <coeffs[o][t], col_t(q)> (both sides).
fn querySums(a: std.mem.Allocator, co: *const zkp.Coeffs, lambda: []const QM31, tables: []const TableCols, n_rows: []const usize, n_q: usize) ![]QM31 {
    const ys = try a.alloc(QM31, n_q);
    @memset(ys, QM31.zero());
    for (tables, n_rows, 0..) |t, R, ti| {
        const comb = try a.alloc(QM31, R);
        defer a.free(comb);
        @memset(comb, QM31.zero());
        for (co.v, 0..) |o, oi| for (comb, o[ti]) |*x, c| {
            x.* = x.*.add(c.mul(lambda[oi]));
        };
        for (0..n_q) |q| {
            var acc = QM31.zero();
            for (comb, t.values[q * R ..][0..R]) |c, v| acc = acc.add(c.mulM31(v));
            ys[q] = ys[q].add(acc);
        }
    }
    return ys;
}

/// Prover. Call after `zkp.drawCoeffs(tr, shapes, groups, mus, prox)` and
/// combining the rows (`rows[o]` = sum over tables of `zkp.combine`, len C + S).
/// Takes ownership of `mus` and `rows` (also on error).
pub fn finish(
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    outer: pcs.Params,
    p2: pcs2.Params,
    coms: []const *const zkp.Commitment,
    co: *const zkp.Coeffs,
    groups: []const zkp.Group,
    k0: usize,
    mus: []QM31,
    rows: [][]QM31,
    /// optional device for the committed-row commitment (plain pcs.commit; identical output)
    acc: ?*const accel.Accel,
) !Opening {
    defer {
        for (rows) |r| a.free(r);
        a.free(rows);
    }
    errdefer a.free(mus);
    if (p2.depth == 0 or coms.len == 0) return error.OpeningShape;
    const sh = coms[0].shape;
    const C = sh.nCols();
    const S: usize = sh.slots;
    const lc = sh.log_cols;
    const log_m = lc + 1;
    const Cm = 2 * C;
    const log_ext = sh.logExt();
    if (S > C or !std.math.isPowerOfTwo(S)) return error.OpeningShape;
    const n_out = rows.len;
    for (rows) |r| std.debug.assert(r.len == C + S);
    std.debug.assert(co.v.len == n_out and mus.len == groups.len and k0 + groups.len == n_out);
    const pp = innerParams(outer, p2);
    const ish = innerShapeFor(outer, p2, n_out, lc);
    const G = @as(usize, 1) << @intCast(ish.log_g);

    // commit V[g][c][k] = limb_c(u_g[k])
    const vdata = try a.alloc(i32, @as(usize, 1) << @intCast(ish.log_total));
    defer a.free(vdata);
    @memset(vdata, 0);
    {
        const VCtx = struct { rows: []const []const QM31, v: []i32, Cm: usize };
        const vctx = VCtx{ .rows = rows, .v = vdata, .Cm = Cm };
        pool.parallelFor(n_out * 4, 1, &vctx, struct {
            fn run(c: *const VCtx, s: usize, e: usize) void {
                for (s..e) |gc| {
                    const dst = c.v[gc * c.Cm ..][0..c.Cm];
                    for (c.rows[gc / 4], dst[0..c.rows[gc / 4].len]) |val, *d| d.* = @intCast(f.limbs(val)[gc % 4]);
                }
            }
        }.run);
    }
    const pi = pp.level(1);
    var itw = try pcs.Twiddles.init(a, ish.log_cols + pi.log_blowup);
    defer itw.deinit(a);
    const vm = pcs.Matrix(i32){ .data = vdata, .log_rows = ish.log_rows, .log_cols = ish.log_cols, .rows_used = ish.rows_used };
    var vcom = try accel.commit(acc, i32, a, pool, &itw, vm, pi.log_blowup);
    defer vcom.deinit(a);
    tr.mixDigest(vcom.root());

    const rho = try a.alloc(QM31, ish.log_g);
    defer a.free(rho);
    tr.drawN(rho);
    const lambda = try f.eqTable(a, rho, QM31.one());
    defer a.free(lambda);

    // outer queries (budget charged before anything is released)
    const nonce = tr.grind(outer.pow_bits);
    const idx = try a.alloc(usize, outer.n_queries);
    defer a.free(idx);
    tr.drawIndices(log_ext, idx);
    for (coms) |c| if (c.budget) |b| try b.charge(idx);
    const uq = try pcs2.sortedUnique(a, idx);
    defer a.free(uq);
    const tables = try a.alloc(TableCols, coms.len);
    var n_tab: usize = 0;
    errdefer {
        for (tables[0..n_tab]) |t| freeOne(t, a);
        a.free(tables);
    }
    const n_rows = try a.alloc(usize, coms.len);
    defer a.free(n_rows);
    for (coms, 0..) |c, ti| {
        if (c.shape.logExt() != log_ext or c.shape.nCols() != C or c.shape.slots != S) return error.OpeningShape;
        const R = c.shape.n_rows;
        n_rows[ti] = R;
        const vals = try a.alloc(M31, uq.len * R);
        errdefer a.free(vals);
        const salts = try a.alloc([SALT]u8, uq.len);
        errdefer a.free(salts);
        for (uq, 0..) |j, q| {
            @memcpy(vals[q * R ..][0..R], c.column(j));
            salts[q] = c.salts[j];
        }
        tables[ti] = .{ .values = vals, .salts = salts, .decommit = try pcs2.multiproof(a, c.tree, uq) };
        n_tab += 1;
    }
    const ys = try querySums(a, co, lambda, tables, n_rows, uq.len);
    defer a.free(ys);
    tr.mixFelts(ys);
    const n_eval = groups.len;
    const gp = try a.alloc(QM31, n_eval + uq.len);
    defer a.free(gp);
    tr.drawN(gp);

    // W = lambda (x) head(sum_q gp_q T_jq) + sum_e gp_e (e_{k0+e} (x) [b_e ; 0])
    const Sv = try pcs2.querySum(a, pool, log_ext, log_m, uq, gp[n_eval..]);
    defer a.free(Sv);
    @memset(Sv[C + S ..], QM31.zero());
    var claim = QM31.zero();
    for (ys, gp[n_eval..]) |y, g| claim = claim.add(g.mul(y));
    for (groups, 0..) |g, gi| claim = claim.add(gp[gi].mul(evalTarget(g, co.gammas[gi], mus[gi])));
    const W = try a.alloc(QM31, G * Cm);
    defer a.free(W);
    const Uf = try a.alloc(QM31, G * Cm);
    defer a.free(Uf);
    {
        const WCtx = struct { W: []QM31, Uf: []QM31, S: []const QM31, lambda: []const QM31, groups: []const zkp.Group, gp: []const QM31, rows: []const []const QM31, k0: usize, C: usize, Cm: usize };
        const wctx = WCtx{ .W = W, .Uf = Uf, .S = Sv, .lambda = lambda, .groups = groups, .gp = gp, .rows = rows, .k0 = k0, .C = C, .Cm = Cm };
        const CH = 8192;
        const per = (Cm + CH - 1) / CH;
        pool.parallelFor(G * per, 1, &wctx, struct {
            fn run(c: *const WCtx, s0: usize, e0: usize) void {
                for (s0..e0) |ch| {
                    const g = ch / ((c.Cm + CH - 1) / CH);
                    const k_lo = (ch % ((c.Cm + CH - 1) / CH)) * CH;
                    const k_hi = @min(c.Cm, k_lo + CH);
                    const wd = c.W[g * c.Cm ..][k_lo..k_hi];
                    for (wd, c.S[k_lo..k_hi]) |*d, sv| d.* = sv.mul(c.lambda[g]);
                    if (g >= c.k0 and g - c.k0 < c.groups.len and k_lo < c.C) {
                        const gi = g - c.k0;
                        const kb = @min(k_hi, c.C);
                        for (wd[0 .. kb - k_lo], c.groups[gi].col[k_lo..kb]) |*d, b| d.* = d.add(c.gp[gi].mul(b));
                    }
                    const ud = c.Uf[g * c.Cm ..][k_lo..k_hi];
                    @memset(ud, QM31.zero());
                    if (g < c.rows.len) {
                        const r = c.rows[g];
                        if (k_lo < r.len) {
                            const kb = @min(k_hi, r.len);
                            @memcpy(ud[0 .. kb - k_lo], r[k_lo..kb]);
                        }
                    }
                }
            }
        }.run);
    }
    const res = try sc.proveActive(2, &pcs2.T_PROD2, a, pool, tr, claim, .{ Uf, W }, G * Cm);
    defer a.free(res.point);
    defer a.free(res.finals);
    var sumcheck = res.proof;
    errdefer sumcheck.deinit(a);
    const limb_vals = try limbMles(a, pool, rows, res.point, ish.log_g);
    tr.mixFelts(&limb_vals);

    // next level: the four limb claims form one group of the committed-row table
    const pts = try limbPoints(a, ish, res.point);
    defer for (pts) |pt| a.free(pt);
    var lcl: [4]pcs2.Claim = undefined;
    for (0..4) |c| lcl[c] = .{ .point = pts[c], .value = limb_vals[c] };
    const ngroups = [_]pcs2.Group{.{ .claims = &lcl }};
    var levels: std.ArrayList(pcs2.LevelProof) = .empty;
    errdefer {
        for (levels.items) |*l| l.deinit(a);
        levels.deinit(a);
    }
    try levels.append(a, .{});
    try pcs2.openRec(i32, a, pool, tr, pp, 1, &vcom, vm, &ngroups, true, &levels);
    return .{
        .mus = mus,
        .pow_nonce = nonce,
        .tables = tables,
        .inner_root = vcom.root(),
        .sumcheck = sumcheck,
        .limb_vals = limb_vals,
        .inner = .{ .levels = try levels.toOwnedSlice(a) },
    };
}

/// Limb MLEs V~(r_g, c, r_k) of rows shorter than the 2^(point.len - log_g) message (zero tail).
fn limbMles(a: std.mem.Allocator, pool: *f.Pool, rows: []const []const QM31, point: []const QM31, log_g: u32) ![4]QM31 {
    const eq_g = try f.eqTable(a, point[0..log_g], QM31.one());
    defer a.free(eq_g);
    const eq_k = try f.eqTablePar(a, pool, point[log_g..], QM31.one());
    defer a.free(eq_k);
    const L = rows[0].len;
    std.debug.assert(L <= eq_k.len);
    const CH = 4096;
    const n_ch = (L + CH - 1) / CH;
    const part = try a.alloc([4]QM31, n_ch);
    defer a.free(part);
    const Ctx = struct { rows: []const []const QM31, eq_g: []const QM31, eq_k: []const QM31, part: [][4]QM31, L: usize };
    const ctx = Ctx{ .rows = rows, .eq_g = eq_g, .eq_k = eq_k, .part = part, .L = L };
    pool.parallelFor(n_ch, 1, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |ch| {
                const k0 = ch * CH;
                const k1 = @min(c.L, k0 + CH);
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

/// Verifier (mirrors `zkp.verifyOpening`'s interface).
pub fn verify(
    a: std.mem.Allocator,
    tr: *Transcript,
    outer: pcs.Params,
    p2: pcs2.Params,
    shapes: []const zkp.Shape,
    roots: []const Hash,
    groups: []const zkp.Group,
    prox: ?zkp.MaskRef,
    proof: Opening,
) !void {
    if (p2.depth == 0) return error.OpeningShape;
    if (shapes.len == 0 or roots.len != shapes.len or proof.tables.len != shapes.len) return error.OpeningShape;
    if (proof.mus.len != groups.len) return error.OpeningShape;
    if (proof.inner.levels.len != p2.depth + 1) return error.OpeningShape;
    {
        const l0 = proof.inner.levels[0];
        if (l0.col_values.len != 0 or l0.decommit.len != 0 or l0.rows.len != 0 or l0.sumcheck.rounds.len != 0) return error.OpeningShape;
    }
    const C = shapes[0].nCols();
    const S: usize = shapes[0].slots;
    const lc = shapes[0].log_cols;
    const log_m = lc + 1;
    const log_ext = shapes[0].logExt();
    if (S > C or !std.math.isPowerOfTwo(S)) return error.OpeningShape;
    for (shapes) |s| if (s.logExt() != log_ext or s.nCols() != C or s.slots != S or !s.rateOk()) return error.OpeningShape;
    for (groups) |g| {
        if (g.col.len != C) return error.OpeningShape;
        for (g.claims) |c| {
            if (c.rows.len != shapes.len) return error.OpeningShape;
            for (c.rows, shapes) |r, s| if (r.len != 0 and r.len < s.n_rows) return error.OpeningShape;
        }
    }
    var co = try zkp.drawCoeffs(a, tr, shapes, groups, proof.mus, prox);
    defer co.deinit(a);
    const n_out = co.v.len;
    const k0: usize = @intFromBool(prox != null);
    const pp = innerParams(outer, p2);
    const ish = innerShapeFor(outer, p2, n_out, lc);
    tr.mixDigest(proof.inner_root);
    const rho = try a.alloc(QM31, ish.log_g);
    defer a.free(rho);
    tr.drawN(rho);
    const lambda = try f.eqTable(a, rho, QM31.one());
    defer a.free(lambda);
    if (!tr.verifyPow(outer.pow_bits, proof.pow_nonce)) return error.OpeningPow;
    const idx = try a.alloc(usize, outer.n_queries);
    defer a.free(idx);
    tr.drawIndices(log_ext, idx);
    const uq = try pcs2.sortedUnique(a, idx);
    defer a.free(uq);
    const n_rows = try a.alloc(usize, shapes.len);
    defer a.free(n_rows);
    const hs = try a.alloc(Hash, uq.len);
    defer a.free(hs);
    for (proof.tables, shapes, roots, 0..) |t, s, rt, ti| {
        const R = s.n_rows;
        n_rows[ti] = R;
        if (t.values.len != uq.len * R or t.salts.len != uq.len) return error.OpeningShape;
        for (hs, 0..) |*h, q| h.* = zkp.leafHash(t.values[q * R ..][0..R], &t.salts[q]);
        if (!try pcs2.verifyMultiproof(a, rt, log_ext, uq, hs, t.decommit)) return error.OpeningMerkle;
    }
    const ys = try querySums(a, &co, lambda, proof.tables, n_rows, uq.len);
    defer a.free(ys);
    tr.mixFelts(ys);
    const n_eval = groups.len;
    const gp = try a.alloc(QM31, n_eval + uq.len);
    defer a.free(gp);
    tr.drawN(gp);
    var claim = QM31.zero();
    for (ys, gp[n_eval..]) |y, g| claim = claim.add(g.mul(y));
    for (groups, 0..) |g, gi| claim = claim.add(gp[gi].mul(evalTarget(g, co.gammas[gi], proof.mus[gi])));
    const vr = try sc.verify(a, tr, claim, ish.log_g + log_m, 2, proof.sumcheck);
    defer a.free(vr.point);
    const r_g = vr.point[0..ish.log_g];
    const r_k = vr.point[ish.log_g..];
    // W~(r)
    var w_at = QM31.zero();
    for (groups, 0..) |g, gi| {
        const bv = try f.mleEval(a, g.col, r_k[1..]);
        w_at = w_at.add(gp[gi].mul(bitsEq(r_g, k0 + gi)).mul(QM31.one().sub(r_k[0])).mul(bv));
    }
    {
        const fac = try a.alloc(M31, log_m);
        defer a.free(fac);
        const log_s: u32 = @intCast(std.math.log2_int(usize, S));
        var qs = QM31.zero();
        for (uq, 0..) |j, q| {
            pcs2.circleFactors(log_ext, j, log_m, fac);
            qs = qs.add(gp[n_eval + q].mul(headEval(fac, r_k, log_s)));
        }
        w_at = w_at.add(f.eqEval(r_g, rho).mul(qs));
    }
    var u_at = QM31.zero();
    for (proof.limb_vals, 0..) |v, c| u_at = u_at.add(zkp.basis(c).mul(v));
    if (!vr.final_claim.eql(u_at.mul(w_at))) return error.OpeningSumcheck;
    tr.mixFelts(&proof.limb_vals);

    const pts = try limbPoints(a, ish, vr.point);
    defer for (pts) |pt| a.free(pt);
    var lcl: [4]pcs2.Claim = undefined;
    for (0..4) |c| lcl[c] = .{ .point = pts[c], .value = proof.limb_vals[c] };
    const ngroups = [_]pcs2.Group{.{ .claims = &lcl }};
    const pi = pp.level(1);
    const ishape = pcs2.Shape{ .log_rows = ish.log_rows, .log_cols = ish.log_cols, .log_blowup = pi.log_blowup, .rows_used = ish.rows_used };
    try pcs2.verifyRec(a, tr, pp, 1, ishape, proof.inner_root, &ngroups, true, proof.inner);
}

// ---------------------------------------------------------------------------
// Tests.

test "head-restricted circle tensor MLE matches brute force" {
    const a = std.testing.allocator;
    const lc = 5;
    const lb = 2;
    for ([_]u32{ 1, 3, 5 }) |log_s| {
        for ([_]usize{ 0, 7, 77 }) |j| {
            var fac: [lc + 1]M31 = undefined;
            pcs2.circleFactors(lc + lb, j, lc + 1, &fac);
            const tt = try pcs2.tensorTable(a, &fac);
            defer a.free(tt);
            const C = 1 << lc;
            const S = @as(usize, 1) << @intCast(log_s);
            var tq: [2 * C]QM31 = undefined;
            for (&tq, tt, 0..) |*o, t, k| o.* = if (k < C + S) QM31.fromBase(t) else QM31.zero();
            var r: [lc + 1]QM31 = undefined;
            for (&r, 0..) |*x, i| x.* = QM31.fromU32Unchecked(@intCast(i * 17 + j + 3), 5, @intCast(i), 9);
            try std.testing.expect((try f.mleEval(a, &tq, &r)).eql(headEval(&fac, &r, log_s)));
        }
    }
}

test "masked encoding of C + S coefficients is the 2C-coefficient circle tensor" {
    const a = std.testing.allocator;
    const lc = 5;
    const lb = 2;
    const C = 1 << lc;
    const S = 8;
    var tw = try pcs.Twiddles.init(a, lc + lb);
    defer tw.deinit(a);
    const E = @as(usize, 1) << (lc + lb);
    const buf = try a.alloc(M31, E);
    defer a.free(buf);
    var prng = std.Random.DefaultPrng.init(5);
    var coeffs: [2 * C]QM31 = [_]QM31{QM31.zero()} ** (2 * C);
    for (0..C + S) |i| {
        buf[i] = M31.fromCanonical(prng.random().intRangeLessThan(u32, 0, f.P));
        coeffs[i] = QM31.fromBase(buf[i]);
    }
    tw.encode(buf, C + S);
    var fac: [lc + 1]M31 = undefined;
    for (0..E) |j| {
        pcs2.circleFactors(lc + lb, j, lc + 1, &fac);
        try std.testing.expect((try pcs2.evalCoeffs(a, &coeffs, &fac)).eql(QM31.fromBase(buf[j])));
    }
}

fn testTable(a: std.mem.Allocator, lr: u32, lc: u32, seed: u64, zero: bool) ![]i32 {
    const n = @as(usize, 1) << @intCast(lr + lc);
    const d = try a.alloc(i32, n);
    var prng = std.Random.DefaultPrng.init(seed);
    for (d) |*x| x.* = if (zero) 0 else prng.random().intRangeAtMost(i32, -1000, 1000);
    return d;
}

const Fixture = struct {
    d0: []i32,
    d1: []i32,
    ex: []M31,
    m0: pcs.Matrix(i32),
    m1: pcs.Matrix(i32),
    c0: zkp.Commitment,
    c1: zkp.Commitment,
    b: []QM31,
    r0: []QM31,
    r1: []QM31,
    rows_view: [2][]const QM31,
    claims: [1]zkp.Claim,
    groups: [1]zkp.Group,

    const lc = 6;
    const lb = 2;
    const C = 1 << lc;

    fn init(self: *Fixture, a: std.mem.Allocator, pool: *f.Pool, rng: *zkp.Rng, slots: u32, zero_data: bool) !void {
        var tw = try pcs.Twiddles.init(a, lc + lb);
        defer tw.deinit(a);
        // table 0: 16 rows; rows 8..11 proximity masks, 12..15 group masks (random)
        self.d0 = try testTable(a, 4, lc, 3, false);
        if (zero_data) @memset(self.d0[0 .. 8 * C], 0);
        self.m0 = .{ .data = self.d0, .log_rows = 4, .log_cols = lc };
        // table 1: 4 data rows + 2 extra M31 rows
        self.d1 = try testTable(a, 2, lc, 4, zero_data);
        self.m1 = .{ .data = self.d1, .log_rows = 2, .log_cols = lc };
        self.ex = try a.alloc(M31, 2 * C);
        if (zero_data) @memset(self.ex, M31.zero()) else rng.fillM31(self.ex);
        self.c0 = try zkp.commit(i32, a, pool, &tw, rng, self.m0, &.{}, slots, lb);
        self.c1 = try zkp.commit(i32, a, pool, &tw, rng, self.m1, self.ex, slots, lb);
        self.b = try a.alloc(QM31, C);
        for (self.b, 0..) |*x, i| x.* = QM31.fromU32Unchecked(@intCast(i + 3), 7, @intCast(i * i), 1);
        self.r0 = try a.alloc(QM31, 16);
        @memset(self.r0, QM31.zero());
        self.r1 = try a.alloc(QM31, 6);
        @memset(self.r1, QM31.zero());
        for (0..4) |i| self.r0[i] = QM31.fromU32Unchecked(@intCast(i + 1), 2, 3, 4);
        self.r1[5] = QM31.fromU32Unchecked(9, 9, 9, 9);
        var value = QM31.zero();
        for (0..4) |i| for (0..C) |j| {
            value = value.add(self.r0[i].mul(self.b[j]).mulM31(f.fromI32(self.d0[i * C + j])));
        };
        for (0..C) |j| value = value.add(self.r1[5].mul(self.b[j]).mulM31(self.ex[C + j]));
        self.rows_view = .{ self.r0, self.r1 };
        self.claims = .{.{ .rows = &self.rows_view, .value = value }};
        self.groups = .{.{ .col = self.b, .claims = &self.claims, .mask = .{ .table = 0, .row = 12 } }};
    }

    fn deinit(self: *Fixture, a: std.mem.Allocator) void {
        a.free(self.d0);
        a.free(self.d1);
        a.free(self.ex);
        self.c0.deinit(a);
        self.c1.deinit(a);
        a.free(self.b);
        a.free(self.r0);
        a.free(self.r1);
    }

    fn shapes(self: *const Fixture) [2]zkp.Shape {
        return .{ self.c0.shape, self.c1.shape };
    }
    fn roots(self: *const Fixture) [2]Hash {
        return .{ self.c0.root(), self.c1.root() };
    }

    fn prove(self: *Fixture, a: std.mem.Allocator, pool: *f.Pool, outer: pcs.Params, p2: pcs2.Params) !Opening {
        return self.proveTag(a, pool, outer, p2, 0);
    }

    fn proveTag(self: *Fixture, a: std.mem.Allocator, pool: *f.Pool, outer: pcs.Params, p2: pcs2.Params, tag: u64) !Opening {
        var tp = Transcript.initDomain("zkpcs2");
        tp.mixU64(tag);
        const mus = try a.alloc(QM31, 1);
        mus[0] = zkp.maskValue(i32, self.m0, 12, self.b);
        const sh = self.shapes();
        var co = try zkp.drawCoeffs(a, &tp, &sh, &self.groups, mus, .{ .table = 0, .row = 8 });
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
            const ua = try zkp.combine(i32, a, pool, &self.c0, self.m0, &.{}, cv0);
            defer a.free(ua);
            const ub = try zkp.combine(i32, a, pool, &self.c1, self.m1, self.ex, cv1);
            defer {
                for (ub) |r| a.free(r);
                a.free(ub);
            }
            for (0..n_out) |o| {
                for (ua[o], ub[o]) |*x, y| x.* = x.*.add(y);
                rows[o] = ua[o];
            }
        }
        const coms = [_]*const zkp.Commitment{ &self.c0, &self.c1 };
        return finish(a, pool, &tp, outer, p2, &coms, &co, &self.groups, 1, mus, rows, null);
    }

    fn check(self: *Fixture, a: std.mem.Allocator, outer: pcs.Params, p2: pcs2.Params, groups: []const zkp.Group, proof: Opening) !void {
        var tv = Transcript.initDomain("zkpcs2");
        tv.mixU64(0);
        const sh = self.shapes();
        const rt = self.roots();
        return verify(a, &tv, outer, p2, &sh, &rt, groups, .{ .table = 0, .row = 8 }, proof);
    }
};

fn testParams(depth: u32) struct { outer: pcs.Params, p2: pcs2.Params } {
    return .{
        .outer = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 2 },
        .p2 = .{ .inner = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 }, .depth = depth, .inner_work_shift = 0 },
    };
}

fn expectReject(fx: *Fixture, a: std.mem.Allocator, outer: pcs.Params, p2: pcs2.Params, proof: Opening) !void {
    try std.testing.expect(std.meta.isError(fx.check(a, outer, p2, &fx.groups, proof)));
}

test "zk pcs2: hiding recursive opening verifies and rejects tampering (depth 1, 2)" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 3);
    defer pool.deinit();
    for ([_]u32{ 1, 2 }) |depth| {
        const pr = testParams(depth);
        var rng = zkp.Rng.initSeed([_]u8{@intCast(depth)} ** 32);
        var fx: Fixture = undefined;
        try fx.init(a, &pool, &rng, zkp.slotsFor(pr.outer.n_queries), false);
        defer fx.deinit(a);
        var proof = try fx.prove(a, &pool, pr.outer, pr.p2);
        defer proof.deinit(a);
        try std.testing.expectEqual(@as(usize, depth + 1), proof.inner.levels.len);
        try fx.check(a, pr.outer, pr.p2, &fx.groups, proof);
        // wrong claim value
        {
            const bad = [_]zkp.Claim{.{ .rows = &fx.rows_view, .value = fx.claims[0].value.add(QM31.one()) }};
            const gb = [_]zkp.Group{.{ .col = fx.b, .claims = &bad, .mask = .{ .table = 0, .row = 12 } }};
            try std.testing.expect(std.meta.isError(fx.check(a, pr.outer, pr.p2, &gb, proof)));
        }
        // wrong depth
        {
            var p3 = pr.p2;
            p3.depth = depth + 1;
            try std.testing.expect(std.meta.isError(fx.check(a, pr.outer, p3, &fx.groups, proof)));
        }
        proof.mus[0] = proof.mus[0].add(QM31.one());
        try expectReject(&fx, a, pr.outer, pr.p2, proof);
        proof.mus[0] = proof.mus[0].sub(QM31.one());
        for (0..2) |ti| {
            proof.tables[ti].salts[1][0] ^= 1;
            try expectReject(&fx, a, pr.outer, pr.p2, proof);
            proof.tables[ti].salts[1][0] ^= 1;
            proof.tables[ti].values[3] = proof.tables[ti].values[3].add(M31.one());
            try expectReject(&fx, a, pr.outer, pr.p2, proof);
            proof.tables[ti].values[3] = proof.tables[ti].values[3].sub(M31.one());
            proof.tables[ti].decommit[0][0] ^= 1;
            try expectReject(&fx, a, pr.outer, pr.p2, proof);
            proof.tables[ti].decommit[0][0] ^= 1;
        }
        proof.inner_root[0] ^= 1;
        try expectReject(&fx, a, pr.outer, pr.p2, proof);
        proof.inner_root[0] ^= 1;
        proof.sumcheck.rounds[2].evals[0] = proof.sumcheck.rounds[2].evals[0].add(QM31.one());
        try expectReject(&fx, a, pr.outer, pr.p2, proof);
        proof.sumcheck.rounds[2].evals[0] = proof.sumcheck.rounds[2].evals[0].sub(QM31.one());
        proof.limb_vals[1] = proof.limb_vals[1].add(QM31.one());
        try expectReject(&fx, a, pr.outer, pr.p2, proof);
        proof.limb_vals[1] = proof.limb_vals[1].sub(QM31.one());
        proof.pow_nonce +%= 1;
        try expectReject(&fx, a, pr.outer, pr.p2, proof);
        proof.pow_nonce -%= 1;
        // inner levels
        for (proof.inner.levels[1..], 1..) |*lp, li| {
            lp.col_values[0] = lp.col_values[0].add(M31.one());
            try expectReject(&fx, a, pr.outer, pr.p2, proof);
            lp.col_values[0] = lp.col_values[0].sub(M31.one());
            if (li + 1 == proof.inner.levels.len) {
                lp.rows[0][1] = lp.rows[0][1].add(QM31.one());
                try expectReject(&fx, a, pr.outer, pr.p2, proof);
                lp.rows[0][1] = lp.rows[0][1].sub(QM31.one());
            } else {
                lp.limb_vals[0] = lp.limb_vals[0].add(QM31.one());
                try expectReject(&fx, a, pr.outer, pr.p2, proof);
                lp.limb_vals[0] = lp.limb_vals[0].sub(QM31.one());
            }
        }
        // a non-empty placeholder level is rejected
        proof.inner.levels[0].rows = proof.inner.levels[proof.inner.levels.len - 1].rows;
        try expectReject(&fx, a, pr.outer, pr.p2, proof);
        proof.inner.levels[0].rows = &.{};
        // untampered still verifies
        try fx.check(a, pr.outer, pr.p2, &fx.groups, proof);
    }
}

test "zk pcs2: a corrupted committed table is rejected" {
    // Corrupt half the encoded columns of a data row after commitment (Merkle
    // rebuilt with the same salts): the proximity / consistency checks reject.
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const pr = testParams(1);
    var outer = pr.outer;
    outer.n_queries = 16;
    var rng = zkp.Rng.initSeed([_]u8{9} ** 32);
    var fx: Fixture = undefined;
    try fx.init(a, &pool, &rng, zkp.slotsFor(outer.n_queries), false);
    defer fx.deinit(a);
    const R = fx.c0.shape.n_rows;
    const E = fx.c0.enc.len / R;
    var j: usize = 0;
    while (j < E) : (j += 2) fx.c0.enc[j * R + 1] = fx.c0.enc[j * R + 1].add(M31.one());
    for (0..E) |k| fx.c0.tree.nodes[E + k] = zkp.leafHash(fx.c0.column(k), &fx.c0.salts[k]);
    var i = E - 1;
    while (i >= 1) : (i -= 1) fx.c0.tree.nodes[i] = pcs.hashNode(fx.c0.tree.nodes[2 * i], fx.c0.tree.nodes[2 * i + 1]);
    var proof = try fx.prove(a, &pool, outer, pr.p2);
    defer proof.deinit(a);
    try std.testing.expect(std.meta.isError(fx.check(a, outer, pr.p2, &fx.groups, proof)));
}

test "zk pcs2: lifetime budget is charged and enforced" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const pr = testParams(1);
    var rng = zkp.Rng.initSeed([_]u8{4} ** 32);
    var fx: Fixture = undefined;
    // slots 16 -> budget 8 = one opening of 8 queries
    try fx.init(a, &pool, &rng, 16, false);
    defer fx.deinit(a);
    try fx.c1.enableBudget(a);
    var p1 = try fx.prove(a, &pool, pr.outer, pr.p2);
    defer p1.deinit(a);
    try std.testing.expect(fx.c1.budget.?.count >= 1 and fx.c1.budget.?.count <= 8);
    // a second opening at fresh positions exceeds the budget (with overwhelming probability)
    var n_fail: usize = 0;
    for (1..4) |tag| {
        if (fx.proveTag(a, &pool, pr.outer, pr.p2, tag)) |p| {
            var pp = p;
            pp.deinit(a);
        } else |e| {
            try std.testing.expectEqual(error.OpeningBudgetExceeded, e);
            n_fail += 1;
        }
    }
    try std.testing.expect(n_fail >= 1);
    try std.testing.expect(fx.c1.budget.?.count <= 8);
}

/// Top-bit ratio and zero count of a set of M31 values.
fn uniformStats(vals: []const M31) struct { top: f64, zeros: usize } {
    var top: usize = 0;
    var zeros: usize = 0;
    for (vals) |v| {
        top += @intFromBool(v.v >= (1 << 30));
        zeros += @intFromBool(v.v == 0);
    }
    return .{ .top = @as(f64, @floatFromInt(top)) / @as(f64, @floatFromInt(vals.len)), .zeros = zeros };
}

fn appendQ(list: *std.ArrayList(M31), a: std.mem.Allocator, q: QM31) !void {
    const l = f.limbs(q);
    for (l) |x| try list.append(a, M31.fromU32Unchecked(x));
}

test "zk pcs2 statistical sanity: zero data gives uniform-looking reveals at every level" {
    // With all data rows zero (masks random), every revealed value of the
    // recursive opening (outer columns, inner sumcheck messages, limb values,
    // inner columns, final rows) is a function of the masked combined rows and
    // must look uniform. Without the outer masks they would all be zero.
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const pr = testParams(2);
    var vals: std.ArrayList(M31) = .empty;
    defer vals.deinit(a);
    for (0..6) |trial| {
        var rng = zkp.Rng.initSeed([_]u8{@intCast(40 + trial)} ** 32);
        var fx: Fixture = undefined;
        try fx.init(a, &pool, &rng, zkp.slotsFor(pr.outer.n_queries), true);
        defer fx.deinit(a);
        var proof = try fx.prove(a, &pool, pr.outer, pr.p2);
        defer proof.deinit(a);
        try fx.check(a, pr.outer, pr.p2, &fx.groups, proof);
        // outer data rows of table 0 (rows 0..7) are zero; their opened columns must not be
        const R0 = fx.c0.shape.n_rows;
        for (0..proof.tables[0].values.len / R0) |q| try vals.appendSlice(a, proof.tables[0].values[q * R0 ..][0..8]);
        try vals.appendSlice(a, proof.tables[1].values);
        for (proof.sumcheck.rounds) |r| for (r.evals[0..2]) |e| try appendQ(&vals, a, e);
        for (proof.limb_vals) |l| try appendQ(&vals, a, l);
        const ish = innerShapeFor(pr.outer, pr.p2, 2, Fixture.lc);
        const C1 = @as(usize, 1) << @intCast(ish.log_cols);
        const msg = Fixture.C + fx.c0.shape.slots;
        for (proof.inner.levels[1..], 1..) |lp, li| {
            if (li == 1) {
                // rows of the level-1 table that lie entirely in the zero tail [C + S, 2C) of a U row are public zeros
                const R1 = ish.rows_used;
                for (0..lp.col_values.len / R1) |q| for (0..R1) |row| {
                    if ((row * C1) % (2 * Fixture.C) < msg) try vals.append(a, lp.col_values[q * R1 + row]);
                };
            } else try vals.appendSlice(a, lp.col_values);
            for (lp.rows) |row| for (row) |x| try appendQ(&vals, a, x);
            for (lp.sumcheck.rounds) |r| for (r.evals[0..2]) |e| try appendQ(&vals, a, e);
            // (the final level has no limb values)
            if (li + 1 < proof.inner.levels.len) for (lp.limb_vals) |l| try appendQ(&vals, a, l);
        }
    }
    const st = uniformStats(vals.items);
    try std.testing.expect(vals.items.len > 2000);
    try std.testing.expect(@abs(st.top - 0.5) < 0.03);
    try std.testing.expect(st.zeros == 0);
}
