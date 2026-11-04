//! Soundness calculator: sums every error term of a proof configuration.
//!
//! Each term is the probability that one challenge (or one batch of
//! challenges drawn together) is bad, as the soundness argument in
//! design/tensor-frontend/security.md counts it. Field terms are
//! (numerator / |QM31|); query terms are (agreement)^t; rounds preceded by a
//! proof of work carry its bits. The report gives, like FlashProve's
//! accounting ("whole bound with work / without work"):
//!
//!   * sum_with / sum_without   -log2 of the sum of all terms, PoW counted
//!     (each query term divided by 2^pow) or not;
//!   * round_with / round_without  -log2 of the largest single term;
//!   * compiled   FlashProve's compiled level for round_with (the largest L
//!     with 2^-L >= 2^-w + 8.5 * 2^(L - 256));
//!   * rbr_round_with / rbr_round_without / rbr_compiled  the same maxima
//!     with the lambda/query pair of each inner level in its round-by-round
//!     (Markov) form instead of the interactive mean-value form
//!     (security.md 3.3). Every other term is already a per-round bound.
//!
//! Regimes per committed table (security.md section 2-4):
//!   * fresh tables (witness, committed rows) opened with k proximity rows:
//!     unique decoding, delta < (1 - rho)/2, or - with an OOD sample on the
//!     table - the Johnson regime delta = 1 - sqrt(rho)(1 + 1/m); the
//!     calculator picks the better per level;
//!   * the weight table carries an OOD claim fixed by the key (z_ood drawn
//!     after the root and layout, v_ood in the WeightKey), opened in the key
//!     and in every batch (security.md 4.2). Two modes:
//!       - Config.weight_proximity (default): every per-batch weight opening
//!         runs its own proximity test, so it is accounted as a fresh table
//!         with an OOD sample (unique or Johnson, whichever is better), and
//!         so is the key's level 0;
//!       - otherwise: proximity proven once in the weight key at a small
//!         delta_key (unique decoding); per-batch consistency queries pass a
//!         cheating prover with probability <= (rho + delta_key) each.
//!         delta_key is chosen to balance the key and the per-batch terms.
//!     No conjectured figure is ever derived here: every term is a proven
//!     bound for the binding the verifier actually checks.
const std = @import("std");
const f = @import("field.zig");
const pcs = @import("pcs.zig");
const pcs2 = @import("pcs2.zig");
const proto = @import("protocol.zig");
const weight_key = @import("weight_key.zig");

/// log2 |QM31| = 4 log2(2^31 - 1)
pub const LOG2_F: f64 = 4.0 * 30.99999999932819;
const LN2: f64 = std.math.ln2;

pub const Kind = enum { field, logup, prox, ood, lambda, query };

pub const Term = struct {
    name: []const u8,
    kind: Kind,
    /// log2 of one round's error, without proof of work
    log2_err: f64,
    /// PoW bits that precede the round's challenge
    pow: u32 = 0,
    /// how many rounds share this bound (summed in sum_*)
    count: f64 = 1,
    /// round-by-round form of this round, if it differs (lambda / query of
    /// an inner level): log2 error [with work, without work]
    rbr: ?[2]f64 = null,

    fn withWork(self: Term) f64 {
        return self.log2_err - @as(f64, @floatFromInt(self.pow));
    }

    fn rbrWith(self: Term) f64 {
        return if (self.rbr) |r| r[0] else self.withWork();
    }

    fn rbrWithout(self: Term) f64 {
        return if (self.rbr) |r| r[1] else self.log2_err;
    }
};

pub const Summary = struct {
    sum_with: f64,
    sum_without: f64,
    round_with: f64,
    round_without: f64,
    compiled: f64,
    worst: []const u8,
    worst_without: []const u8,
    n_terms: usize,
    rbr_round_with: f64,
    rbr_round_without: f64,
    rbr_compiled: f64,
    rbr_worst: []const u8,
};

/// log2(2^x + 2^y)
fn logAdd(x: f64, y: f64) f64 {
    if (x == -std.math.inf(f64)) return y;
    if (y == -std.math.inf(f64)) return x;
    const m = @max(x, y);
    return m + std.math.log2(std.math.exp2(x - m) + std.math.exp2(y - m));
}

pub const Account = struct {
    a: std.mem.Allocator,
    terms: std.ArrayList(Term) = .empty,
    names: std.ArrayList([]u8) = .empty,

    pub fn init(a: std.mem.Allocator) Account {
        return .{ .a = a };
    }

    pub fn deinit(self: *Account) void {
        for (self.names.items) |n| self.a.free(n);
        self.names.deinit(self.a);
        self.terms.deinit(self.a);
    }

    pub fn add(self: *Account, name: []const u8, kind: Kind, log2_err: f64, pow: u32, count: f64) !void {
        return self.addRbr(name, kind, log2_err, pow, count, null);
    }

    pub fn addRbr(self: *Account, name: []const u8, kind: Kind, log2_err: f64, pow: u32, count: f64, rbr: ?[2]f64) !void {
        if (count <= 0) return;
        const n = try self.a.dupe(u8, name);
        try self.names.append(self.a, n);
        const r: ?[2]f64 = if (rbr) |x| .{ @min(x[0], 0), @min(x[1], 0) } else null;
        try self.terms.append(self.a, .{ .name = n, .kind = kind, .log2_err = @min(log2_err, 0), .pow = pow, .count = count, .rbr = r });
    }

    /// numerator / |F|, `count` times
    pub fn field(self: *Account, name: []const u8, numerator: f64, count: f64) !void {
        if (numerator <= 0) return;
        try self.add(name, .field, std.math.log2(numerator) - LOG2_F, 0, count);
    }

    pub fn addAll(self: *Account, other: Account, prefix: []const u8) !void {
        for (other.terms.items) |t| {
            const n = try std.fmt.allocPrint(self.a, "{s}{s}", .{ prefix, t.name });
            defer self.a.free(n);
            try self.addRbr(n, t.kind, t.log2_err, t.pow, t.count, t.rbr);
        }
    }

    pub fn summary(self: Account) Summary {
        var sw = -std.math.inf(f64);
        var so = -std.math.inf(f64);
        var mw = -std.math.inf(f64);
        var mo = -std.math.inf(f64);
        var worst: []const u8 = "";
        var worst_o: []const u8 = "";
        var rw = -std.math.inf(f64);
        var ro = -std.math.inf(f64);
        var worst_r: []const u8 = "";
        for (self.terms.items) |t| {
            if (t.rbrWith() > rw) {
                rw = t.rbrWith();
                worst_r = t.name;
            }
            ro = @max(ro, t.rbrWithout());
            const lc = std.math.log2(t.count);
            sw = logAdd(sw, t.withWork() + lc);
            so = logAdd(so, t.log2_err + lc);
            if (t.withWork() > mw) {
                mw = t.withWork();
                worst = t.name;
            }
            if (t.log2_err > mo) {
                mo = t.log2_err;
                worst_o = t.name;
            }
        }
        return .{ .sum_with = -sw, .sum_without = -so, .round_with = -mw, .round_without = -mo, .compiled = compiledLevel(-mw, 256), .worst = worst, .worst_without = worst_o, .n_terms = self.terms.items.len, .rbr_round_with = -rw, .rbr_round_without = -ro, .rbr_compiled = compiledLevel(-rw, 256), .rbr_worst = worst_r };
    }

    pub fn writeJson(self: Account, out: anytype, top: usize) !void {
        const s = self.summary();
        try out.print("{{\"sum_with_work\":{d:.2},\"sum_without_work\":{d:.2},\"round_with_work\":{d:.2},\"round_without_work\":{d:.2},\"compiled\":{d:.2},\"worst\":\"{s}\",\"worst_without_work\":\"{s}\",\"terms\":{d},\"rbr_round_with_work\":{d:.2},\"rbr_round_without_work\":{d:.2},\"rbr_compiled\":{d:.2},\"rbr_worst\":\"{s}\",\"largest\":[", .{ s.sum_with, s.sum_without, s.round_with, s.round_without, s.compiled, s.worst, s.worst_without, s.n_terms, s.rbr_round_with, s.rbr_round_without, s.rbr_compiled, s.rbr_worst });
        // the `top` largest terms (with work), each as [name, -log2 err, pow, count]
        const idx = try self.a.alloc(usize, self.terms.items.len);
        defer self.a.free(idx);
        for (idx, 0..) |*x, i| x.* = i;
        const Ctx = struct { t: []const Term };
        std.mem.sort(usize, idx, Ctx{ .t = self.terms.items }, struct {
            fn lt(c: Ctx, x: usize, y: usize) bool {
                const ex = c.t[x].withWork() + std.math.log2(c.t[x].count);
                const ey = c.t[y].withWork() + std.math.log2(c.t[y].count);
                return ex > ey;
            }
        }.lt);
        for (idx[0..@min(top, idx.len)], 0..) |i, k| {
            const t = self.terms.items[i];
            try out.print("{s}[\"{s}\",{d:.2},{d},{d:.0}]", .{ if (k == 0) "" else ",", t.name, -t.log2_err, t.pow, t.count });
        }
        try out.print("]}}", .{});
    }
};

/// FlashProve's compiled level (blocks/numbers/accounting.h): the largest L
/// with 2^-L >= 2^-w + c_h 2^(L - D), c_h = 8.5.
pub fn compiledLevel(w: f64, digest_bits: f64) f64 {
    var lo: f64 = 0;
    var hi: f64 = digest_bits - 1;
    for (0..200) |_| {
        const L = (lo + hi) / 2;
        if (std.math.exp2(-L) >= std.math.exp2(-w) + 8.5 * std.math.exp2(L - digest_bits)) lo = L else hi = L;
    }
    return lo;
}

// ---------------------------------------------------------------------------
// Codes.

pub const Regime = enum { unique, johnson };

pub const Proximity = struct {
    regime: Regime,
    delta: f64,
    /// list size at delta (1 in unique decoding)
    list: f64,
    /// count of bad challenges of (mutual) correlated agreement for one
    /// line through two words; error = count / |F|
    count: f64,
    m: u64 = 0,
};

/// Unique decoding: delta E <= floor((E - C - 1) / 2); count E + 1
/// (BCIKS20 Thm 1.6, plus one for the circle subcode).
pub fn uniqueProx(log_c: u32, log_blowup: u32) Proximity {
    const E: f64 = std.math.exp2(@as(f64, @floatFromInt(log_c + log_blowup)));
    const C: f64 = std.math.exp2(@as(f64, @floatFromInt(log_c)));
    const e = @floor((E - C - 1) / 2);
    return .{ .regime = .unique, .delta = e / E, .list = 1, .count = E + 1 };
}

/// Johnson regime at m: 1 - delta = sqrt(rho)(1 + 1/m), with the count of
/// BCHKS25 Thm 4.6 (M = 1; machine-checked by FlashProve as its Lemma 5.13)
/// plus one list size for the circle subcode, and the Johnson list bound
/// (a - rho)/(a^2 - rho) of the interleaved code.
pub fn johnsonProx(log_c: u32, log_blowup: u32, m: u64) Proximity {
    const n: f64 = std.math.exp2(@as(f64, @floatFromInt(log_c + log_blowup)));
    const rho = std.math.exp2(-@as(f64, @floatFromInt(log_blowup)));
    const root = @sqrt(rho);
    const mf: f64 = @floatFromInt(m);
    const agree = root * (1 + 1 / mf);
    const delta = 1 - agree;
    const M = mf + 0.5;
    const list = @floor((agree - rho) / (agree * agree - rho));
    const count = (2 * std.math.pow(f64, M, 5) + 3 * M * delta * rho) / (3 * rho * root) * n + M / root + list;
    return .{ .regime = .johnson, .delta = delta, .list = list, .count = count, .m = m };
}

// ---------------------------------------------------------------------------
// PCS openings.

pub const Mode = union(enum) {
    /// the table's proximity is tested in this opening (prox rows at level 0)
    fresh,
    /// consistency only, proximity proven earlier at distance delta_key
    consistency: f64,
};

fn log2Binom2(L: f64) f64 {
    return if (L < 2) -std.math.inf(f64) else std.math.log2(L * (L - 1) / 2);
}

/// Terms of one level for a given proximity choice. Returns the level's
/// log2 total (with work) so callers can optimise delta.
fn levelTerms(acc: ?*Account, name: []const u8, li: pcs2.LevelInfo, mode: Mode, px: Proximity, ood_vars: ?u32) !f64 {
    var total = -std.math.inf(f64);
    const p = li.params;
    const t: f64 = @floatFromInt(p.n_queries);
    const rho = std.math.exp2(-@as(f64, @floatFromInt(p.log_blowup)));
    const R: f64 = @floatFromInt(li.rows_used);
    var buf: [128]u8 = undefined;
    const T = struct {
        fn put(ac: ?*Account, tot: *f64, nm: []const u8, kind: Kind, l2: f64, pow: u32, count: f64) !void {
            return putRbr(ac, tot, nm, kind, l2, pow, count, null);
        }
        fn putRbr(ac: ?*Account, tot: *f64, nm: []const u8, kind: Kind, l2: f64, pow: u32, count: f64, rbr: ?[2]f64) !void {
            if (count <= 0 or l2 == -std.math.inf(f64)) return;
            tot.* = logAdd(tot.*, l2 - @as(f64, @floatFromInt(pow)) + std.math.log2(count));
            if (ac) |x| try x.addRbr(nm, kind, l2, pow, count, rbr);
        }
    };
    // claims within a group: independent gamma per claim
    try T.put(acc, &total, try std.fmt.bufPrint(&buf, "{s} gamma", .{name}), .field, -LOG2_F, 0, @floatFromInt(li.n_groups));
    var agree: f64 = undefined;
    switch (mode) {
        .fresh => {
            // all k proximity combinations close while the table has no
            // (mutual) correlated agreement; R rows -> R x (line count)
            const k: f64 = @floatFromInt(li.n_prox);
            if (li.n_prox == 0) return error.NoProximity;
            try T.put(acc, &total, try std.fmt.bufPrint(&buf, "{s} proximity x{d}", .{ name, li.n_prox }), .prox, k * (std.math.log2(R * px.count) - LOG2_F), 0, 1);
            agree = @max(1 - px.delta, rho);
            if (px.regime == .johnson) {
                const nv = ood_vars orelse return error.JohnsonNeedsOod;
                try T.put(acc, &total, try std.fmt.bufPrint(&buf, "{s} OOD collision (list {d:.0})", .{ name, px.list }), .ood, log2Binom2(px.list) + std.math.log2(@as(f64, @floatFromInt(nv))) - LOG2_F, 0, 1);
            }
        },
        .consistency => |dk| agree = rho + dk,
    }
    const log_g: f64 = @floatFromInt(@max(li.log_g, 1));
    var rbr_query: ?[2]f64 = null;
    if (!li.final) {
        // lambda-combination cancels at a position (mean value over t queries)
        const r = lambdaRbr(log_g, t, agree, p.pow_bits);
        rbr_query = r.query;
        try T.putRbr(acc, &total, try std.fmt.bufPrint(&buf, "{s} lambda", .{name}), .lambda, std.math.log2(t * log_g) - LOG2_F, 0, 1, r.lambda);
        // inner batching gamma' and the degree-2 sumcheck over log G' + lc vars
        try T.put(acc, &total, try std.fmt.bufPrint(&buf, "{s} inner batch", .{name}), .field, -LOG2_F, 0, 1);
        try T.put(acc, &total, try std.fmt.bufPrint(&buf, "{s} inner sumcheck", .{name}), .field, 1 - LOG2_F, 0, @floatFromInt(li.log_g + li.log_cols));
    }
    try T.putRbr(acc, &total, try std.fmt.bufPrint(&buf, "{s} queries ({d} at {d:.3})", .{ name, p.n_queries, agree }), .query, t * std.math.log2(agree), p.pow_bits, 1, rbr_query);
    return total;
}

const LambdaRbr = struct { lambda: [2]f64, query: [2]f64 };

/// Round-by-round (Markov) form of a level's lambda/query pair (security.md
/// 3.3): N_rho, the positions outside Z where the lambda-combination
/// vanishes, has mean <= E log G'/|F|, so the lambda round is bad
/// (N_rho >= tau E) with probability <= log G'/(tau |F|); otherwise a query
/// passes with probability <= a + tau. tau is fixed from public parameters;
/// it is chosen separately for the with-work and without-work maxima.
fn lambdaRbr(log_g: f64, t: f64, agree: f64, pow_bits: u32) LambdaRbr {
    var out: LambdaRbr = undefined;
    const pw: f64 = @floatFromInt(pow_bits);
    for ([_]f64{ pw, 0 }, 0..) |work, k| {
        var best = std.math.inf(f64);
        var x: f64 = 1;
        while (x <= 60) : (x += 1.0 / 32.0) {
            // tau = 2^-x
            const lam = std.math.log2(log_g) + x - LOG2_F;
            const q = t * std.math.log2(@min(agree + std.math.exp2(-x), 1)) - work;
            if (@max(lam, q) < best) {
                best = @max(lam, q);
                out.lambda[k] = lam;
                out.query[k] = q;
            }
        }
    }
    return out;
}

/// Best proximity for a fresh level (Johnson only with an OOD sample).
fn bestProx(name: []const u8, li: pcs2.LevelInfo, ood_vars: ?u32) !Proximity {
    var best = uniqueProx(li.log_cols, li.params.log_blowup);
    var best_v = try levelTerms(null, name, li, .fresh, best, ood_vars);
    if (ood_vars != null) {
        var m: u64 = 3;
        while (m <= 1 << 14) : (m = m + 1 + m / 16) {
            const px = johnsonProx(li.log_cols, li.params.log_blowup, m);
            if (px.list < 1) continue;
            const v = try levelTerms(null, name, li, .fresh, px, ood_vars);
            if (v < best_v) {
                best_v = v;
                best = px;
            }
        }
    }
    return best;
}

/// Accounts a whole opening (all levels). `outer_ood`: the level-0 table
/// carries an OOD sample (number of its MLE variables = log_rows+log_cols).
/// Inner tables carry one iff `params.ood`.
pub fn accountOpening(acc: *Account, name: []const u8, infos: []const pcs2.LevelInfo, params_ood: bool, outer_ood: bool, mode0: Mode) !void {
    var buf: [96]u8 = undefined;
    for (infos, 0..) |li, lvl| {
        const nm = try std.fmt.bufPrint(&buf, "{s} L{d}", .{ name, lvl });
        const has_ood = if (lvl == 0) outer_ood else params_ood;
        const ov: ?u32 = if (has_ood) li.log_rows + li.log_cols else null;
        if (lvl == 0 and mode0 == .consistency) {
            _ = try levelTerms(acc, nm, li, mode0, uniqueProx(li.log_cols, li.params.log_blowup), null);
        } else {
            const px = try bestProx(nm, li, ov);
            _ = try levelTerms(acc, nm, li, .fresh, px, ov);
        }
    }
}

/// Level infos of an opening under `cfg` (flat PCS = one final level).
pub fn openingInfos(a: std.mem.Allocator, cfg: proto.Config, shape: pcs.Shape, n_groups: usize, with_proximity: bool) ![]pcs2.LevelInfo {
    if (cfg.two_level) |tl| return pcs2.levelInfos(a, tl, shape, n_groups, with_proximity);
    const out = try a.alloc(pcs2.LevelInfo, 1);
    const R = @as(usize, 1) << @intCast(shape.log_rows);
    const n_prox: usize = @intFromBool(with_proximity);
    out[0] = .{ .log_rows = shape.log_rows, .log_cols = shape.log_cols, .rows_used = shape.rows_used orelse R, .params = cfg.pcs, .n_rows = n_groups + n_prox, .n_prox = n_prox, .n_groups = n_groups, .final = true };
    return out;
}

// ---------------------------------------------------------------------------
// Protocol terms.

fn accountSumcheck(acc: *Account, name: []const u8, p: anytype) !void {
    const n: f64 = @floatFromInt(p.rounds.len);
    try acc.field(name, @floatFromInt(p.deg), n);
    // the claim's own randomness (zero-check point / batching coefficients):
    // a nonzero polynomial of degree <= rounds + 1 at a random point
    try acc.field(name, n + 1, 1);
}

fn accountGkr(acc: *Account, name: []const u8, g: anytype) !void {
    // per layer: instance batching (powers, degree <= 2 * instances) and the
    // num/den combination, the layer sumcheck rounds, the mask fold (degree 1
    // per instance)
    var buf: [96]u8 = undefined;
    for (g.sumcheck_proofs, 0..) |sp, layer| {
        var active: f64 = 0;
        for (g.layer_masks_by_instance) |ms| {
            if (ms.len > 0 and layer >= g.sumcheck_proofs.len - ms.len) active += 1;
        }
        if (active == 0) active = @floatFromInt(g.layer_masks_by_instance.len);
        try acc.field(try std.fmt.bufPrint(&buf, "{s} batching", .{name}), 2 * active + 1, 1);
        for (sp.round_polys) |rp| try acc.field(try std.fmt.bufPrint(&buf, "{s} rounds", .{name}), @floatFromInt(rp.coeffsSlice().len - 1), 1);
        try acc.field(try std.fmt.bufPrint(&buf, "{s} mask fold", .{name}), active, 1);
    }
}

/// LogUp: a key of arity a enters as the denominator alpha - (v_0 + beta
/// v_1 + ... + beta^(a-1) v_(a-1)), a polynomial of total degree g =
/// max(a - 1, 1) in (alpha, beta); distinct keys give distinct, monic-in-
/// alpha (hence coprime) denominators. If the relation's multiset identity
/// fails (some net multiplicity c_s != 0 mod p, which needs D < p), the
/// rational function sum_s c_s / d_s is nonzero, so its numerator over the
/// common denominator - total degree <= (N - 1) g for N <= D distinct keys
/// - vanishes at the draw with probability <= (N - 1) g / |F| (Schwartz-
/// Zippel), and a zero denominator has probability <= N g / |F|. Summed
/// over the relations: < 2 sum_rel g_rel D_rel / |F|.
fn accountLogup(acc: *Account, name: []const u8, fractions: f64, max_arity: u32) !void {
    const g: f64 = @floatFromInt(@max(max_arity, 2) - 1);
    try accountLogupDegree(acc, name, g * fractions);
}

/// As accountLogup, given sum_rel g_rel D_rel directly (per-relation degree).
fn accountLogupDegree(acc: *Account, name: []const u8, degree_fractions: f64) !void {
    try acc.add(name, .logup, std.math.log2(2 * degree_fractions) - LOG2_F, 0, 1);
}

pub const Report = struct {
    request: Account,
    key: ?Account,
    /// request and key terms together (a client checks both)
    total: Account,
    delta_key: f64,
    logup_ok: bool,
    /// per-batch weight openings ran their own proximity test (4.2)
    weight_proximity: bool = false,
    /// the proof opened the weight table at all
    weight_openings: bool = false,

    pub fn deinit(self: *Report) void {
        self.request.deinit();
        if (self.key) |*k| k.deinit();
        self.total.deinit();
    }
};

/// Every term of a request proof (and, if given, of the weight-key proof).
/// Runs the verifier (which must accept) to read the shapes it checked.
pub fn accountProof(a: std.mem.Allocator, cfg: proto.Config, st: proto.Statement, key: proto.WeightKey, proof: *const proto.Proof, key_proof: ?*const weight_key.KeyProof) !Report {
    var info: proto.VerifyInfo = .{};
    try proto.verifyInfo(a, cfg, st, key, proof, &info);
    var req = Account.init(a);
    errdefer req.deinit();
    const P: f64 = @floatFromInt(f.P);

    if (proof.gkr) |*g| {
        // per-relation degree; never above the global-arity bound
        if (info.logup_degree_fractions < info.logup_fractions or info.logup_degree_fractions > @as(f64, @floatFromInt(@max(info.logup_max_arity, 2) - 1)) * info.logup_fractions) return error.LogupAccount;
        try accountLogupDegree(&req, "logup alpha,beta", info.logup_degree_fractions);
        try accountGkr(&req, "gkr", g);
    }
    for (proof.op_sumchecks) |p| try accountSumcheck(&req, "op sumcheck", p);
    for (proof.ext.sumchecks) |p| try accountSumcheck(&req, "ext sumcheck", p);
    try req.field("witness batch gamma", 1, 1);
    try accountSumcheck(&req, "witness batch sumcheck", proof.batch_sumcheck);

    const tl_ood = if (cfg.two_level) |tl| tl.ood else false;
    const winf = try openingInfos(a, cfg, info.witness_shape, info.witness_groups, true);
    defer a.free(winf);
    try accountOpening(&req, "witness", winf, tl_ood, proto.witnessOod(cfg), .fresh);

    // weights: choose delta_key to balance the key's level-0 query term with
    // the per-batch consistency term
    var delta_key: f64 = 0;
    var kacc: ?Account = null;
    errdefer if (kacc) |*k| k.deinit();
    const kcfg = try proto.keyConfig(cfg);
    const wcfg = try proto.weightOpenConfig(cfg);
    const kshape = pcs.Shape{ .log_rows = key.log_rows, .log_cols = key.log_cols, .log_blowup = proto.outerParams(cfg).log_blowup, .rows_used = key.rows_used };
    // key opening: W(rho) and the OOD claim (two column points)
    const kinf = try openingInfos(a, kcfg, kshape, 2, true);
    defer a.free(kinf);
    const wprox = info.weight_proximity;
    const winf2: ?[]pcs2.LevelInfo = if (info.weight_shape) |ws| try openingInfos(a, wcfg, ws, info.weight_groups, wprox) else null;
    defer if (winf2) |x| a.free(x);
    const key_vars = key.log_rows + key.log_cols;
    if (!wprox) {
        const ud = uniqueProx(kinf[0].log_cols, kinf[0].params.log_blowup);
        var best = -std.math.inf(f64);
        var i: usize = 1;
        while (i <= 2000) : (i += 1) {
            const dk = ud.delta * @as(f64, @floatFromInt(i)) / 2000.0;
            var px = ud;
            px.delta = dk;
            const kb = -(try levelTerms(null, "k", kinf[0], .fresh, px, null));
            const wb = if (winf2) |w| -(try levelTerms(null, "w", w[0], .{ .consistency = dk }, ud, null)) else std.math.inf(f64);
            if (@min(kb, wb) > best) {
                best = @min(kb, wb);
                delta_key = dk;
            }
        }
    }
    if (winf2) |w| {
        if (wprox) {
            // own proximity rows + the key's OOD claim: a fresh table with an
            // OOD sample (security.md 4.2)
            try accountOpening(&req, "weights", w, tl_ood, true, .fresh);
        } else {
            try accountOpening(&req, "weights", w, tl_ood, false, .{ .consistency = delta_key });
        }
    }

    if (key_proof) |kp| {
        var k = Account.init(a);
        errdefer k.deinit();
        const n_weights = std.math.exp2(@as(f64, @floatFromInt(key.log_rows + key.log_cols)));
        // key_alphas independent alpha drawn in one round: the error is the
        // single-alpha bound to that power (weight_key.zig, security.md 4.1)
        const ka = try weight_key.alphaCount(cfg);
        if (kp.gkr.output_claims_by_instance.len != 2 * ka) return error.KeyShape;
        const single = std.math.log2(2 * (n_weights + 256)) - LOG2_F;
        try k.add(if (ka == 1) "key logup alpha" else "key logup alpha x2", .logup, @as(f64, @floatFromInt(ka)) * single, 0, 1);
        try accountGkr(&k, "key gkr", &kp.gkr);
        // key opening: level 0 at delta_key (unique decoding) when the batches
        // rely on it, else fresh with the OOD sample; inner levels fresh
        var buf: [32]u8 = undefined;
        for (kinf, 0..) |li, lvl| {
            const nm = try std.fmt.bufPrint(&buf, "key L{d}", .{lvl});
            if (lvl == 0 and wprox) {
                _ = try levelTerms(&k, nm, li, .fresh, try bestProx(nm, li, key_vars), key_vars);
            } else if (lvl == 0) {
                var px = uniqueProx(li.log_cols, li.params.log_blowup);
                px.delta = delta_key;
                _ = try levelTerms(&k, nm, li, .fresh, px, null);
            } else {
                const ov: ?u32 = if (tl_ood) li.log_rows + li.log_cols else null;
                _ = try levelTerms(&k, nm, li, .fresh, try bestProx(nm, li, ov), ov);
            }
        }
        kacc = k;
    }
    var total = Account.init(a);
    errdefer total.deinit();
    try total.addAll(req, "");
    if (kacc) |k| try total.addAll(k, "");
    return .{ .request = req, .key = kacc, .total = total, .delta_key = delta_key, .logup_ok = info.logup_max_relation < P, .weight_proximity = wprox, .weight_openings = info.weight_shape != null };
}

pub fn writeReport(r: Report, out: anytype) !void {
    try out.print("\"security\":{{\"weight_binding\":\"{s}\",\"delta_key\":{d:.4},\"logup_below_p\":{},\"request\":", .{ if (!r.weight_openings) "no weight openings" else if (r.weight_proximity) "per-batch proximity + key OOD" else "key distance + key OOD", r.delta_key, r.logup_ok });
    try r.request.writeJson(out, 6);
    if (r.key) |k| {
        try out.print(",\"key\":", .{});
        try k.writeJson(out, 4);
    }
    try out.print(",\"total\":", .{});
    try r.total.writeJson(out, 6);
    try out.print("}},", .{});
}

// ---------------------------------------------------------------------------
// Tests.

test "compiled level matches FlashProve's 126.21 at w = 128" {
    try std.testing.expectApproxEqAbs(@as(f64, 126.21), compiledLevel(128, 256), 0.01);
}

test "unique decoding and Johnson parameters" {
    const ud = uniqueProx(10, 2);
    try std.testing.expect(ud.delta < 0.375 and ud.delta > 0.374);
    // Johnson radius at rho = 1/4 is 1/2; m = 20 -> 1 - delta = 0.525
    const j = johnsonProx(10, 2, 20);
    try std.testing.expectApproxEqAbs(@as(f64, 0.475), j.delta, 1e-12);
    try std.testing.expectEqual(@as(f64, 10), j.list);
    // the count is linear in n
    const j2 = johnsonProx(11, 2, 20);
    try std.testing.expect(j2.count > 1.99 * (j.count - j.list) and j2.count < 2.01 * j.count);
}

test "round-by-round (Markov) form of lambda and queries" {
    // witness L1 of the toy: log G' = 3, 76 queries at 0.412, 20 bits of work
    const r = lambdaRbr(3, 76, 0.412, 20);
    const with = -@max(r.lambda[0], r.query[0]);
    const without = -@max(r.lambda[1], r.query[1]);
    // the query term alone is 117.2 bits with work, 97.2 without; tau costs
    // ~2 bits with work (115.3) and almost nothing without
    const q0 = -76 * std.math.log2(0.412);
    try std.testing.expect(with > 115 and with < q0 + 20 - 1);
    try std.testing.expect(without > q0 - 0.01 and without <= q0);
    try std.testing.expect(-r.lambda[0] >= with and -r.query[0] >= with);
    // tau = 2^-x with x >= 1 keeps a + tau <= 1 meaningful
    const full = lambdaRbr(3, 10, 0.9, 0);
    try std.testing.expect(full.query[1] <= 0);
}

test "LogUp term: total degree max(arity - 1, 1) per denominator" {
    var acc = Account.init(std.testing.allocator);
    defer acc.deinit();
    try accountLogup(&acc, "a1", std.math.exp2(25.0), 1);
    try accountLogup(&acc, "a2", std.math.exp2(25.0), 2);
    try accountLogup(&acc, "a3", std.math.exp2(25.0), 3);
    // 2 * 2^25 / |F| for arity 1 and 2; 4 * 2^25 / |F| for arity 3
    try std.testing.expectApproxEqAbs(26 - LOG2_F, acc.terms.items[0].log2_err, 1e-9);
    try std.testing.expectApproxEqAbs(26 - LOG2_F, acc.terms.items[1].log2_err, 1e-9);
    try std.testing.expectApproxEqAbs(27 - LOG2_F, acc.terms.items[2].log2_err, 1e-9);
}

test "account sums and maxima" {
    var acc = Account.init(std.testing.allocator);
    defer acc.deinit();
    try acc.add("q", .query, -100, 20, 1);
    try acc.add("f", .field, -110, 0, 2);
    const s = acc.summary();
    try std.testing.expectApproxEqAbs(@as(f64, 100), s.round_without, 1e-9);
    try std.testing.expectApproxEqAbs(@as(f64, 110), s.round_with, 1e-9);
    // 2^-120 + 2 * 2^-110 ~ 2^-108.999
    try std.testing.expectApproxEqAbs(@as(f64, 108.9986), s.sum_with, 1e-3);
    try std.testing.expectEqualStrings("f", s.worst);
}

test "end-to-end accounting of a product proof: more queries, more bits" {
    const a = std.testing.allocator;
    const model = @import("model.zig");
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var results: [2]f64 = undefined;
    for ([_]usize{ 20, 60 }, 0..) |q, i| {
        const pc = proto.Config{ .two_level = .{ .outer = .{ .log_blowup = 2, .n_queries = q, .pow_bits = 2 }, .inner = .{ .log_blowup = 3, .n_queries = q, .pow_bits = 2 }, .depth = 1, .prox_rows = 2, .ood = true }, .weight_log_cols = 2, .gkr_threads = 2 };
        const dummy_info = [_]proto.TensorInfo{proto.TensorInfo.mat(2, 2)};
        var dummy: [16]i8 = [_]i8{0} ** 16;
        const dv = [_][]const i8{&dummy};
        var ws = try proto.commitWeights(a, &pool, pc, &dummy_info, &dv);
        defer ws.deinit(a);
        var built = try model.buildProduct(a, 10, 5);
        defer built.deinit(a);
        const wview = try a.alloc([]const i32, built.witness.len);
        defer a.free(wview);
        for (built.witness, 0..) |w, k| wview[k] = w;
        var tm: proto.Timings = .{};
        var st = built.statement();
        st.weights = &dummy_info;
        var proof = try proto.prove(a, &pool, pc, st, &ws, wview, &tm);
        defer proof.deinit(a);
        var rep = try accountProof(a, pc, st, proto.weightKey(&ws), &proof, null);
        defer rep.deinit();
        const s = rep.request.summary();
        try std.testing.expect(s.sum_with <= s.round_with);
        try std.testing.expect(s.sum_without <= s.sum_with);
        try std.testing.expect(s.rbr_round_without <= s.rbr_round_with);
        try std.testing.expect(s.rbr_round_with > 0 and s.rbr_round_without > 0);
        results[i] = s.sum_with;
        // a tampered proof is not accounted (the verifier runs first)
        proof.witness_value = proof.witness_value.add(f.QM31.one());
        try std.testing.expect(std.meta.isError(accountProof(a, pc, st, proto.weightKey(&ws), &proof, null)));
    }
    try std.testing.expect(results[1] > results[0] + 20);
}

test "weight binding modes: per-batch proximity is accounted fresh, consistency at delta_key" {
    const a = std.testing.allocator;
    const model = @import("model.zig");
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = model.Mlp{ .log_t = 3, .log_d = 4, .log_f = 5, .fused = false };
    const winfos = model.mlpWeightInfos(cfg);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 600 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    for ([_]bool{ true, false }) |wprox| {
        var pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 40, .pow_bits = 2 }, .weight_log_cols = 4, .witness_log_cols_max = 6, .gkr_threads = 1 };
        pc.weight_proximity = wprox;
        var ws = try proto.commitWeights(a, &pool, pc, &winfos, &.{ wdata[0], wdata[1], wdata[2] });
        defer ws.deinit(a);
        var kp = try weight_key.prove(a, &pool, pc, &ws);
        defer kp.deinit(a);
        const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 5);
        defer a.free(x);
        var built = try model.buildMlp(a, &pool, &ws, cfg, x);
        defer built.deinit(a);
        const wview = try a.alloc([]const i32, built.witness.len);
        defer a.free(wview);
        for (built.witness, 0..) |w, i| wview[i] = w;
        var tm: proto.Timings = .{};
        var proof = try proto.prove(a, &pool, pc, built.statement(), &ws, wview, &tm);
        defer proof.deinit(a);
        var rep = try accountProof(a, pc, built.statement(), proto.weightKey(&ws), &proof, &kp);
        defer rep.deinit();
        try std.testing.expectEqual(wprox, rep.weight_proximity);
        var has_prox = false;
        var has_consistency = false;
        for (rep.request.terms.items) |t| {
            if (std.mem.startsWith(u8, t.name, "weights L0 proximity")) has_prox = true;
            if (std.mem.startsWith(u8, t.name, "weights L0 queries") and t.kind == .query) {
                // consistency mode: per-query agreement rho + delta_key > 1 - delta
                has_consistency = std.mem.indexOf(u8, t.name, "at 0.") != null and !wprox;
            }
        }
        try std.testing.expectEqual(wprox, has_prox);
        try std.testing.expectEqual(!wprox, has_consistency);
        // no term is ever a conjectured (rho^t) figure: query agreement >= rho + something
        for (rep.total.terms.items) |t| if (t.kind == .query) try std.testing.expect(t.log2_err >= 40 * std.math.log2(0.25) + 1);
    }
}
