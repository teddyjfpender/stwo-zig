//! Offline weight key proof: proximity of the committed weight table AND a
//! range proof that every committed weight lies in [-128, 128).
//!
//! Why: the matmul relation is checked over M31. Accumulators stay below 2^30
//! (and so never wrap mod p) only when |w| <= 128 and |x| <= 128 with K <= 2^15.
//! Activations are range-checked per batch. Weights come from the committer and
//! need their own proof, checked once by each client; FlashProve's offline proof
//! plays the same role.
//!
//! Protocol (non-interactive, Blake2s transcript):
//!   0. mix weight root and the whole layout (tensor shapes, offsets, split);
//!      draw the OOD point z_ood (protocol.weightOodPoint) and mix the key's
//!      OOD answer v_ood = W(z_ood) (WeightKey.ood_value).
//!   1. (shape is part of step 0.)
//!   2. prover sends the histogram m[v], v in [0,256), of (w + 128) over the
//!      whole 2^n table, padding zeros included.
//!   3. alpha <- transcript. A LogUp-GKR batch of 2 instances:
//!        keys:  1/(alpha - (w_i + 128)),  i < 2^n   (singles)
//!        table: m_v/(alpha - v),           v < 256  (multiplicities)
//!      The verifier checks sum(keys) - sum(table) = 0 at the GKR outputs.
//!   4. Terminal claims: key instance den(rho) = alpha - W(rho) - 128 gives
//!      W(rho). Table instance: den(rho') = alpha - id(rho'), and num(rho')
//!      = MLE(m)(rho') is computed by the verifier from the sent histogram.
//!   5. One PCS opening of the weight table, with proximity, of two claim
//!      groups: W(rho) and the OOD claim (z_ood, v_ood). The OOD claim pins
//!      the decoded table D beyond unique decoding; every batch's weight
//!      opening carries the same claim, so the range proof and every batch
//!      speak about the same D (security.md 4.2).
//! Soundness: if some w_i is outside [0,256) after the +128 shift (as a field
//! element), the LogUp identity fails with probability >= 1 - O(N/|QM31|) over
//! alpha (needs 2^n + 256 < p: `error.LogUpCountAboveP` otherwise). The GKR soundness error is then added, plus the PCS
//! binding of W(rho) to the committed table.
//!
//! With Config.key_alphas = 2, step 3 draws alpha_1, alpha_2 back to back
//! (one round) and the GKR batch has 4 instances (keys and table for each
//! alpha); both sums must vanish, so the identity error is squared. The key
//! instances share the output point rho, and the verifier requires both to
//! give the same W(rho) (alpha_j - den_j(rho) - 128), which is the single
//! opened claim.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const f = @import("field.zig");
const canonical = @import("canonical.zig");
const pcs = @import("pcs.zig");
const pcs2 = @import("pcs2.zig");
const proto = @import("protocol.zig");
const Transcript = @import("transcript.zig").Transcript;

const M31 = f.M31;
const QM31 = f.QM31;
const lookups = engine.lookups;
const Fast = lookups.gkr_prover_fast.ForField(QM31);
const GkrVerifier = lookups.gkr_verifier;

pub const KeyProof = struct {
    histogram: [256]u32,
    gkr: GkrVerifier.GkrBatchProof,
    value: QM31,
    opening: proto.Opening,

    pub fn deinit(self: *KeyProof, a: std.mem.Allocator) void {
        self.gkr.deinit(a);
        self.opening.deinit(a);
    }

    pub fn byteSize(self: KeyProof) usize {
        var gk: usize = 0;
        for (self.gkr.sumcheck_proofs) |p| for (p.round_polys) |rp| {
            gk += rp.coeffsSlice().len * 16;
        };
        for (self.gkr.layer_masks_by_instance) |ms| for (ms) |m| {
            gk += m.columnsSlice().len * 32;
        };
        for (self.gkr.output_claims_by_instance) |c| gk += c.len * 16;
        return 256 * 4 + gk + 16 + self.opening.byteSize();
    }
};

/// Steps 0-1: layout, OOD point (returned in `z`, caller frees), OOD answer.
fn startTranscript(a: std.mem.Allocator, key: proto.WeightKey, z: *[]QM31) !Transcript {
    var tr = proto.keyTranscript(key);
    z.* = try a.alloc(QM31, key.log_rows + key.log_cols);
    tr.drawN(z.*);
    tr.mixFelt(key.ood_value);
    return tr;
}

/// LogUp over M31: 2^n keys + 256 table rows must stay below p (P7).
pub fn checkCount(n_vars: u32) !void {
    if (n_vars >= 31 or (@as(u64, 1) << @intCast(n_vars)) + 256 >= f.P) return error.LogUpCountAboveP;
}

/// The key's two opened claim groups: W(rho) and the OOD claim.
fn keyGroups(a: std.mem.Allocator, key: proto.WeightKey, rho: []const QM31, value: QM31, z: []const QM31) ![]pcs.Group {
    const cl = [_]pcs.Claim{ .{ .point = rho, .value = value }, .{ .point = z, .value = key.ood_value } };
    return pcs2.groupByColumn(a, &cl, key.log_rows);
}

fn histMle(a: std.mem.Allocator, h: [256]u32, point: []const QM31) !QM31 {
    var v: [256]i32 = undefined;
    for (0..256) |i| v[i] = @intCast(h[i]);
    return f.mleEvalI32(a, &v, point);
}

pub fn prove(a: std.mem.Allocator, pool: *f.Pool, cfg0: proto.Config, ws: *const proto.WeightStore) !KeyProof {
    // the key's opening runs at the key-time outer parameters (Config.key_outer)
    const cfg = try proto.keyConfig(cfg0);
    const key = proto.weightKey(ws);
    try checkCount(key.log_rows + key.log_cols);
    var z: []QM31 = &.{};
    var tr = try startTranscript(a, key, &z);
    defer a.free(z);
    const n = ws.table.len;
    var hist = [_]u32{0} ** 256;
    for (ws.table) |w| hist[@intCast(@as(i32, w) + 128)] += 1;
    var hw: [256]u32 = hist;
    tr.mixU32s(&hw);
    const n_alpha = try alphaCount(cfg);
    var alphas: [2]QM31 = undefined;
    for (alphas[0..n_alpha]) |*al| al.* = tr.draw();
    const alpha = alphas[0];

    var mult: [256]M31 = undefined;
    for (0..256) |v| mult[v] = M31.fromCanonical(hist[v] % f.P);
    var tden: [2][256]QM31 = undefined;
    var inputs: [4]Fast.Input = undefined;
    for (alphas[0..n_alpha], 0..) |al, j| {
        const den = try a.alloc(QM31, n);
        const Ctx = struct { t: []const i8, den: []QM31, alpha: QM31 };
        const ctx = Ctx{ .t = ws.table, .den = den, .alpha = al };
        pool.parallelFor(n, 8192, &ctx, struct {
            fn run(c: *const Ctx, s: usize, e: usize) void {
                for (s..e) |i| c.den[i] = c.alpha.sub(f.qFromI64(@as(i64, c.t[i]) + 128));
            }
        }.run);
        for (0..256) |v| tden[j][v] = al.sub(QM31.fromBase(M31.fromCanonical(@intCast(v))));
        inputs[2 * j] = .{ .num = .ones, .den = den, .owned = true };
        inputs[2 * j + 1] = .{ .num = .{ .base = &mult }, .den = &tden[j], .owned = false };
    }
    var res = try @import("accel.zig").gkrProveBatch(cfg.accel, a, &tr.ch, inputs[0 .. 2 * n_alpha], cfg.gkr_threads);
    defer res.artifact.deinit(a);
    const L = res.artifact.ood_point.len;
    const rho = res.artifact.ood_point[L - (key.log_rows + key.log_cols) ..];
    const value = alpha.sub(res.artifact.claims_to_verify_by_instance[0][1]).sub(f.qFromI64(128));
    const groups = try keyGroups(a, key, rho, value, z);
    defer pcs2.freeGroups(a, groups);
    const opening: proto.Opening = if (cfg.two_level) |tl|
        .{ .two = try pcs2.open(i8, a, pool, &tr, tl, &ws.com, ws.tableMatrix(), groups, true) }
    else
        .{ .flat = try pcs.open(i8, a, pool, &tr, cfg.pcs, &ws.com, ws.tableMatrix(), groups, true) };
    return .{ .histogram = hist, .gkr = res.proof, .value = value, .opening = opening };
}

/// Number of independent LogUp challenges of the key proof (1 or 2).
pub fn alphaCount(cfg: proto.Config) !usize {
    return switch (cfg.key_alphas) {
        1, 2 => cfg.key_alphas,
        else => error.KeyAlphas,
    };
}

pub fn verify(a: std.mem.Allocator, cfg0: proto.Config, key: proto.WeightKey, proof: *const KeyProof) !void {
    // every transmitted limb in [0, P) before any arithmetic (KERN-1)
    try canonical.check(proof);
    const cfg = try proto.keyConfig(cfg0);
    try proto.checkKeyLayout(a, key.infos, key);
    const n_vars = key.log_rows + key.log_cols;
    try checkCount(n_vars);
    var z: []QM31 = &.{};
    var tr = try startTranscript(a, key, &z);
    defer a.free(z);
    var total: u64 = 0;
    for (proof.histogram) |h| total += h;
    if (total != (@as(u64, 1) << @intCast(n_vars))) return error.KeyHistogram;
    var hw: [256]u32 = proof.histogram;
    tr.mixU32s(&hw);
    const n_alpha = try alphaCount(cfg);
    var alphas: [2]QM31 = undefined;
    for (alphas[0..n_alpha]) |*al| al.* = tr.draw();
    const gates = [_]GkrVerifier.Gate{ .LogUp, .LogUp, .LogUp, .LogUp };
    if (proof.gkr.output_claims_by_instance.len != 2 * n_alpha) return error.KeyShape;
    var art = try GkrVerifier.partiallyVerifyBatch(a, gates[0 .. 2 * n_alpha], &proof.gkr, &tr.ch);
    defer art.deinit(a);
    if (art.n_variables_by_instance.len != 2 * n_alpha or art.claims_to_verify_by_instance.len != 2 * n_alpha) return error.KeyShape;
    const L = art.ood_point.len;
    if (L < n_vars or L < 8) return error.KeyShape;
    const rho = art.ood_point[L - n_vars ..];
    const rho_t = art.ood_point[L - 8 ..];
    const hist_mle = try histMle(a, proof.histogram, rho_t);
    var value: QM31 = undefined;
    for (alphas[0..n_alpha], 0..) |alpha, j| {
        if (art.n_variables_by_instance[2 * j] != n_vars or art.n_variables_by_instance[2 * j + 1] != 8) return error.KeyShape;
        // LogUp sum: keys - table = 0, for every alpha
        const k = proof.gkr.output_claims_by_instance[2 * j];
        const t = proof.gkr.output_claims_by_instance[2 * j + 1];
        if (k.len != 2 or t.len != 2 or k[1].isZero() or t[1].isZero()) return error.KeyShape;
        if (!k[0].mul(t[1]).sub(t[0].mul(k[1])).isZero()) return error.KeyLogUp;
        const ck = art.claims_to_verify_by_instance[2 * j];
        const ct = art.claims_to_verify_by_instance[2 * j + 1];
        if (ck.len != 2 or ct.len != 2) return error.KeyShape;
        if (!ck[0].eql(QM31.one())) return error.KeyTerminal;
        if (!ct[0].eql(hist_mle)) return error.KeyTerminal;
        if (!ct[1].eql(alpha.sub(f.identityMle(rho_t)))) return error.KeyTerminal;
        // every alpha's key instance must give the same W(rho)
        const v = alpha.sub(ck[1]).sub(f.qFromI64(128));
        if (j == 0) value = v else if (!v.eql(value)) return error.KeyTerminal;
    }
    if (!value.eql(proof.value)) return error.KeyTerminal;
    const groups = try keyGroups(a, key, rho, value, z);
    defer pcs2.freeGroups(a, groups);
    const shape = pcs.Shape{ .log_rows = key.log_rows, .log_cols = key.log_cols, .log_blowup = proto.outerParams(cfg).log_blowup, .rows_used = key.rows_used };
    try proto.verifyOpeningAny(a, &tr, cfg, shape, key.root, groups, true, proof.opening);
}

test "weight key: range proof verifies, tampering rejected" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 2 }, .weight_log_cols = 5, .gkr_threads = 1 };
    const infos = [_]proto.TensorInfo{ proto.TensorInfo.mat(5, 6), proto.TensorInfo.mat(6, 5) };
    var prng = std.Random.DefaultPrng.init(3);
    var w0: [1 << 11]i8 = undefined;
    var w1: [1 << 11]i8 = undefined;
    for (&w0) |*x| x.* = prng.random().int(i8);
    for (&w1) |*x| x.* = prng.random().int(i8);
    const wv = [_][]const i8{ &w0, &w1 };
    var ws = try proto.commitWeights(a, &pool, pc, &infos, &wv);
    defer ws.deinit(a);
    var kp = try prove(a, &pool, pc, &ws);
    defer kp.deinit(a);
    const key = proto.weightKey(&ws);
    try verify(a, pc, key, &kp);
    // histogram tamper
    kp.histogram[3] += 1;
    kp.histogram[4] -= 1;
    try std.testing.expect(std.meta.isError(verify(a, pc, key, &kp)));
    kp.histogram[3] -= 1;
    kp.histogram[4] += 1;
    kp.value = kp.value.add(QM31.one());
    try std.testing.expect(std.meta.isError(verify(a, pc, key, &kp)));
    kp.value = kp.value.sub(QM31.one());
    try verify(a, pc, key, &kp);
}

test "weight key: two independent alpha (one round, one batched GKR)" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const pc1 = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 2 }, .weight_log_cols = 5, .gkr_threads = 1 };
    var pc = pc1;
    pc.key_alphas = 2;
    const infos = [_]proto.TensorInfo{proto.TensorInfo.mat(5, 6)};
    var prng = std.Random.DefaultPrng.init(7);
    var w0: [1 << 11]i8 = undefined;
    for (&w0) |*x| x.* = prng.random().int(i8);
    const wv = [_][]const i8{&w0};
    var ws = try proto.commitWeights(a, &pool, pc, &infos, &wv);
    defer ws.deinit(a);
    const key = proto.weightKey(&ws);
    var kp = try prove(a, &pool, pc, &ws);
    defer kp.deinit(a);
    try std.testing.expectEqual(@as(usize, 4), kp.gkr.output_claims_by_instance.len);
    try verify(a, pc, key, &kp);
    // the verifier's alpha count is part of the statement
    try std.testing.expect(std.meta.isError(verify(a, pc1, key, &kp)));
    var bad = pc;
    bad.key_alphas = 3;
    try std.testing.expectError(error.KeyAlphas, verify(a, bad, key, &kp));
    // histogram and value tampering
    kp.histogram[3] += 1;
    kp.histogram[4] -= 1;
    try std.testing.expect(std.meta.isError(verify(a, pc, key, &kp)));
    kp.histogram[3] -= 1;
    kp.histogram[4] += 1;
    kp.value = kp.value.add(QM31.one());
    try std.testing.expect(std.meta.isError(verify(a, pc, key, &kp)));
    kp.value = kp.value.sub(QM31.one());
    // every output claim of the second alpha's instances is checked
    for (2..4) |inst| for (0..2) |c| {
        kp.gkr.output_claims_by_instance[inst][c] = kp.gkr.output_claims_by_instance[inst][c].add(QM31.one());
        try std.testing.expect(std.meta.isError(verify(a, pc, key, &kp)));
        kp.gkr.output_claims_by_instance[inst][c] = kp.gkr.output_claims_by_instance[inst][c].sub(QM31.one());
    };
    try verify(a, pc, key, &kp);
    // with one alpha the proof is the old one (2 instances)
    var kp1 = try prove(a, &pool, pc1, &ws);
    defer kp1.deinit(a);
    try std.testing.expectEqual(@as(usize, 2), kp1.gkr.output_claims_by_instance.len);
    try verify(a, pc1, key, &kp1);
}
