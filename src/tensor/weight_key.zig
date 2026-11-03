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
//!   1. mix weight root and shape.
//!   2. prover sends the histogram m[v], v in [0,256), of (w + 128) over the
//!      whole 2^n table, padding zeros included.
//!   3. alpha <- transcript. A LogUp-GKR batch of 2 instances:
//!        keys:  1/(alpha - (w_i + 128)),  i < 2^n   (singles)
//!        table: m_v/(alpha - v),           v < 256  (multiplicities)
//!      The verifier checks sum(keys) - sum(table) = 0 at the GKR outputs.
//!   4. Terminal claims: key instance den(rho) = alpha - W(rho) - 128 gives
//!      W(rho). Table instance: den(rho') = alpha - id(rho'), and num(rho')
//!      = MLE(m)(rho') is computed by the verifier from the sent histogram.
//!   5. One PCS opening of the weight table at rho, with proximity.
//! Soundness: if some w_i is outside [0,256) after the +128 shift (as a field
//! element), the LogUp identity fails with probability >= 1 - O(N/|QM31|) over
//! alpha (sum m_v < p). The GKR soundness error is then added, plus the PCS
//! binding of W(rho) to the committed table.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const f = @import("field.zig");
const pcs = @import("pcs.zig");
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
    opening: pcs.OpeningProof,

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

fn startTranscript(key: proto.WeightKey) Transcript {
    var tr = Transcript.initDomain("stwo-tensor-weight-key-v1");
    tr.mixDigest(key.root);
    tr.mixU32s(&.{ key.log_rows, key.log_cols, @intCast(key.rows_used) });
    return tr;
}

fn histMle(a: std.mem.Allocator, h: [256]u32, point: []const QM31) !QM31 {
    var v: [256]i32 = undefined;
    for (0..256) |i| v[i] = @intCast(h[i]);
    return f.mleEvalI32(a, &v, point);
}

pub fn prove(a: std.mem.Allocator, pool: *f.Pool, cfg: proto.Config, ws: *const proto.WeightStore) !KeyProof {
    const key = proto.weightKey(ws);
    var tr = startTranscript(key);
    const n = ws.table.len;
    var hist = [_]u32{0} ** 256;
    for (ws.table) |w| hist[@intCast(@as(i32, w) + 128)] += 1;
    var hw: [256]u32 = hist;
    tr.mixU32s(&hw);
    const alpha = tr.draw();

    const den = try a.alloc(QM31, n);
    const Ctx = struct { t: []const i8, den: []QM31, alpha: QM31 };
    const ctx = Ctx{ .t = ws.table, .den = den, .alpha = alpha };
    pool.parallelFor(n, 8192, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |i| c.den[i] = c.alpha.sub(f.qFromI64(@as(i64, c.t[i]) + 128));
        }
    }.run);
    var mult: [256]M31 = undefined;
    var tden: [256]QM31 = undefined;
    for (0..256) |v| {
        mult[v] = M31.fromCanonical(hist[v] % f.P);
        tden[v] = alpha.sub(QM31.fromBase(M31.fromCanonical(@intCast(v))));
    }
    const inputs = [_]Fast.Input{
        .{ .num = .ones, .den = den, .owned = true },
        .{ .num = .{ .base = &mult }, .den = &tden, .owned = false },
    };
    var res = try @import("accel.zig").gkrProveBatch(cfg.accel, a, &tr.ch, &inputs, cfg.gkr_threads);
    defer res.artifact.deinit(a);
    const L = res.artifact.ood_point.len;
    const rho = res.artifact.ood_point[L - (key.log_rows + key.log_cols) ..];
    const value = alpha.sub(res.artifact.claims_to_verify_by_instance[0][1]).sub(f.qFromI64(128));
    const claims = [_]pcs.Claim{.{ .point = rho, .value = value }};
    const groups = [_]pcs.Group{.{ .claims = &claims }};
    const opening = try pcs.open(i8, a, pool, &tr, cfg.pcs, &ws.com, ws.tableMatrix(), &groups, true);
    return .{ .histogram = hist, .gkr = res.proof, .value = value, .opening = opening };
}

pub fn verify(a: std.mem.Allocator, cfg: proto.Config, key: proto.WeightKey, proof: *const KeyProof) !void {
    var tr = startTranscript(key);
    var total: u64 = 0;
    for (proof.histogram) |h| total += h;
    const n_vars = key.log_rows + key.log_cols;
    if (total != (@as(u64, 1) << @intCast(n_vars))) return error.KeyHistogram;
    var hw: [256]u32 = proof.histogram;
    tr.mixU32s(&hw);
    const alpha = tr.draw();
    const gates = [_]GkrVerifier.Gate{ .LogUp, .LogUp };
    if (proof.gkr.output_claims_by_instance.len != 2) return error.KeyShape;
    var art = try GkrVerifier.partiallyVerifyBatch(a, &gates, &proof.gkr, &tr.ch);
    defer art.deinit(a);
    if (art.n_variables_by_instance[0] != n_vars or art.n_variables_by_instance[1] != 8) return error.KeyShape;
    // LogUp sum: keys - table = 0
    const k = proof.gkr.output_claims_by_instance[0];
    const t = proof.gkr.output_claims_by_instance[1];
    if (k.len != 2 or t.len != 2 or k[1].isZero() or t[1].isZero()) return error.KeyShape;
    if (!k[0].mul(t[1]).sub(t[0].mul(k[1])).isZero()) return error.KeyLogUp;
    const L = art.ood_point.len;
    const rho = art.ood_point[L - n_vars ..];
    const rho_t = art.ood_point[L - 8 ..];
    const ck = art.claims_to_verify_by_instance[0];
    const ct = art.claims_to_verify_by_instance[1];
    if (ck.len != 2 or ct.len != 2) return error.KeyShape;
    if (!ck[0].eql(QM31.one())) return error.KeyTerminal;
    if (!ct[0].eql(try histMle(a, proof.histogram, rho_t))) return error.KeyTerminal;
    if (!ct[1].eql(alpha.sub(f.identityMle(rho_t)))) return error.KeyTerminal;
    const value = alpha.sub(ck[1]).sub(f.qFromI64(128));
    if (!value.eql(proof.value)) return error.KeyTerminal;
    var tw = try pcs.Twiddles.init(a, key.log_cols + cfg.pcs.log_blowup);
    defer tw.deinit(a);
    const claims = [_]pcs.Claim{.{ .point = rho, .value = value }};
    const groups = [_]pcs.Group{.{ .claims = &claims }};
    try pcs.verifyOpening(a, &tr, cfg.pcs, &tw, .{ .log_rows = key.log_rows, .log_cols = key.log_cols, .log_blowup = cfg.pcs.log_blowup, .rows_used = key.rows_used }, key.root, &groups, true, proof.opening);
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
