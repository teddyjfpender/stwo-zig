//! Adversarial review tests: kernels and acceleration (review-kern).
const std = @import("std");
const builtin = @import("builtin");
const f = @import("field.zig");
const sc = @import("sumcheck.zig");
const pcs = @import("pcs.zig");
const linalg = @import("linalg.zig");
const proto = @import("protocol.zig");
const model = @import("model.zig");
const recycle = @import("recycle.zig");
const Transcript = @import("transcript.zig").Transcript;
const digest = @import("digest.zig");
const canonical = @import("canonical.zig");
const tfm = @import("transformer.zig");
const xt = @import("ext.zig");

const QM31 = f.QM31;
const M31 = f.M31;
const P: u64 = f.P;

const T_PROD2 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }};

fn limbsOf(x: QM31) [4]u32 {
    return f.limbs(x);
}

/// Raw construction (no canonical assert), as a byte-level proof decoder
/// (memcpy / @bitCast of received limbs) would produce.
fn raw(l: [4]u32) QM31 {
    return .{ .c0 = .{ .a = .{ .v = l[0] }, .b = .{ .v = l[1] } }, .c1 = .{ .a = .{ .v = l[2] }, .b = .{ .v = l[3] } } };
}

fn setLimb(x: QM31, l: usize, v: u32) QM31 {
    var a = f.limbs(x);
    a[l] = v;
    return raw(a);
}

fn unitLimb(l: usize, v: u32) QM31 {
    var a = [4]u32{ 0, 0, 0, 0 };
    a[l] = v;
    return f.fromLimbs(a);
}

// ---------------------------------------------------------------------------
// 1. The sumcheck verifier does not reject non-canonical limbs in round
//    polynomials. M31.sub on a non-canonical subtrahend wraps by 2^32 = 2 mod p,
//    while QM31.mul's lazy path reduces non-canonical inputs correctly, so a
//    prover can shift the verified claim by 2 per limb per round.
test "review-kern: sumcheck verifier rejects a false claim carried by a non-canonical round eval" {
    // KERN-1 regression. Before the fix: ReleaseFast accepted the forgery;
    // under safety checks M31.sub's wrap was an integer-overflow panic inside
    // sc.verify (verifier abort). Now sc.verify rejects the limb >= P first.
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const n = 6;
    const len = 1 << n;
    var seed: u64 = 1;
    while (seed < 64) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        const r = prng.random();
        const fa = try a.alloc(QM31, len);
        defer a.free(fa);
        const fb = try a.alloc(QM31, len);
        defer a.free(fb);
        for (fa, fb) |*x, *y| {
            x.* = QM31.fromU32Unchecked(r.uintLessThan(u32, f.P), r.uintLessThan(u32, f.P), r.uintLessThan(u32, f.P), r.uintLessThan(u32, f.P));
            y.* = QM31.fromU32Unchecked(r.uintLessThan(u32, f.P), r.uintLessThan(u32, f.P), r.uintLessThan(u32, f.P), r.uintLessThan(u32, f.P));
        }
        var claim = QM31.zero();
        for (fa, fb) |x, y| claim = claim.add(x.mul(y));
        // honest round-0 polynomial
        const half = len / 2;
        var s0 = QM31.zero();
        var s2 = QM31.zero();
        for (0..half) |i| {
            s0 = s0.add(fa[i].mul(fb[i]));
            const a2 = fa[i + half].add(fa[i + half]).sub(fa[i]);
            const b2 = fb[i + half].add(fb[i + half]).sub(fb[i]);
            s2 = s2.add(a2.mul(b2));
        }
        // pick a limb l where the forged claim c' = c - 2 e_l still has
        // s0_l > c'_l (so the verifier's c' - s0' wraps)
        const two = M31.fromCanonical(2);
        var limb: ?usize = null;
        var false_claim = claim;
        for (0..4) |l| {
            const fc = claim.sub(unitLimb(l, two.v));
            if (limbsOf(s0)[l] > limbsOf(fc)[l] and limbsOf(s0)[l] + f.P <= std.math.maxInt(u32)) {
                limb = l;
                false_claim = fc;
                break;
            }
        }
        const l = limb orelse continue;
        try std.testing.expect(!false_claim.eql(claim));
        // non-canonical encoding of the honest s(0): s0_l + p
        const s0_nc = setLimb(s0, l, limbsOf(s0)[l] + f.P);
        // cheating prover: round 0 with the forged encoding, then honest rounds
        var trp = Transcript.initDomain("review-kern");
        var rp0 = sc.RoundPoly{ .evals = [_]QM31{QM31.zero()} ** sc.MAX_DEG };
        rp0.evals[0] = s0_nc;
        rp0.evals[1] = s2;
        trp.mixFelts(rp0.evals[0..2]);
        const r0 = trp.draw();
        const vals = [_]QM31{ s0, claim.sub(s0), s2 };
        const next = sc.interpolateAt(&vals, r0);
        const ga = try a.alloc(QM31, half);
        defer a.free(ga);
        const gb = try a.alloc(QM31, half);
        defer a.free(gb);
        for (0..half) |i| {
            ga[i] = fa[i].add(r0.mul(fa[i + half].sub(fa[i])));
            gb[i] = fb[i].add(r0.mul(fb[i + half].sub(fb[i])));
        }
        var rest = try sc.proveActive(2, &T_PROD2, a, &pool, &trp, next, .{ ga, gb }, half);
        defer rest.deinit(a);
        const rounds = try a.alloc(sc.RoundPoly, n);
        defer a.free(rounds);
        rounds[0] = rp0;
        @memcpy(rounds[1..], rest.proof.rounds);
        const proof = sc.Proof{ .rounds = rounds, .deg = 2 };
        // verifier, on the FALSE claim
        var trv = Transcript.initDomain("review-kern");
        if (sc.verify(a, &trv, false_claim, n, 2, proof)) |vr| {
            defer a.free(vr.point);
            const final_expected = sc.evalTerms(&T_PROD2, rest.finals);
            const accepted = vr.final_claim.eql(final_expected);
            if (accepted) std.debug.print("\n[review-kern] FORGERY: sumcheck verified false claim {any} (true {any}) via s0 limb {d} = {d} (>= p)\n", .{ limbsOf(false_claim), limbsOf(claim), l, limbsOf(s0_nc)[l] });
            try std.testing.expect(!accepted);
            return error.NonCanonicalNotRejected;
        } else |e| try std.testing.expectEqual(error.NonCanonical, e);
        return;
    }
    return error.NoSuitableSeed;
}

// 1b. KERN-4: QM31.mul's base-field shortcut (mulM31 -> mulVec4) assumes
//     canonical lanes and is wrong on a limb >= P; the lazy path happens to
//     reduce. The contract is "canonical inputs only" (field.zig), enforced
//     for transmitted values by canonical.check at verifier entry (KERN-1)
//     and for decoded values by field.fromLimbsChecked.
test "review-kern: non-canonical QM31.mul operands are excluded by the canonical-input contract" {
    const x = raw(.{ 0xffff_fff0, 5, 0x8000_0001, 9 });
    const y = QM31.fromBase(M31.fromCanonical(3));
    // the shortcut really is wrong off-contract (documents why the contract exists)
    var want: [4]u32 = undefined;
    for (f.limbs(x), 0..) |v, i| want[i] = @intCast(((@as(u64, v) % P) * 3) % P);
    try std.testing.expect(!std.mem.eql(u32, &f.limbs(x.mul(y)), &want));
    // ... so such a value can never reach it from a proof or a decoder
    try std.testing.expectError(error.NonCanonical, canonical.check(x));
    try std.testing.expectError(error.NonCanonical, f.fromLimbsChecked(f.limbs(x)));
    const xc = try f.fromLimbsChecked(.{ @intCast(0xffff_fff0 % P), 5, @intCast(0x8000_0001 % P), 9 });
    try canonical.check(xc);
    // on canonical inputs the shortcut agrees with the mod-p reference
    try std.testing.expectEqualSlices(u32, &want, &f.limbs(xc.mul(y)));
}

// 1c. Exhaustive-ish bound check of the lazy mul on the largest limbs.
test "review-kern: QM31.mul lazy path is exact for extreme non-canonical limbs" {
    const vals = [_]u32{ 0, 1, f.P - 1, f.P, f.P + 1, 0x8000_0000, 0xffff_fffe, 0xffff_ffff };
    for (vals) |a0| for (vals) |a2| for (vals) |b1| for (vals) |b3| {
        const x = raw(.{ a0, 0xffff_ffff, a2, 0xffff_ffff });
        const y = raw(.{ 0xffff_ffff, b1, 0xffff_ffff, b3 });
        const xc = QM31.fromU32Unchecked(@intCast(a0 % P), @intCast(0xffff_ffff % P), @intCast(a2 % P), @intCast(0xffff_ffff % P));
        const yc = QM31.fromU32Unchecked(@intCast(0xffff_ffff % P), @intCast(b1 % P), @intCast(0xffff_ffff % P), @intCast(b3 % P));
        const z = f.limbs(x.mul(y));
        for (z) |v| try std.testing.expect(v < f.P);
        try std.testing.expectEqualSlices(u32, &f.limbs(xc.mul(yc)), &z);
    };
}

// ---------------------------------------------------------------------------
// 2. KERN-3: the prover passed bound_log2 = 8 to colCombine for every i32
//    matmul operand. validateStatement admits wider operands (a 20-bit range
//    key with K = 2: 20 + 7 + 1 <= 30); at T = 2^13 rows the i64 limb
//    accumulators overflow (ReleaseSafe: panic in the prover; ReleaseFast: a
//    wrong fold, so the honest proof is rejected). The call sites now pass
//    proto.operandBoundLog2. Covers the per-matmul path, the batched shape-class
//    path, and the bound helper itself.
fn wideOperandProof(batch: bool) !void {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const lt = 13;
    const lk = 1;
    const ln = 2;
    const winfos = [_]proto.TensorInfo{ proto.TensorInfo.mat(lk, ln), proto.TensorInfo.mat(lk, ln) };
    var w0: [1 << (lk + ln)]i8 = .{ 127, -128, 3, -5, -128, 127, 1, 0 };
    var w1: [1 << (lk + ln)]i8 = .{ -1, 2, 127, -128, 0, 9, -128, 127 };
    const wv = [_][]const i8{ &w0, &w1 };
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .weight_log_cols = ln, .witness_log_cols_max = 8, .gkr_threads = 1, .batch_matmuls = batch };
    var ws = try proto.commitWeights(a, &pool, pc, &winfos, &wv);
    defer ws.deinit(a);
    var b = tfm.Builder.init(a, &pool);
    defer b.deinit();
    try b.weight_infos.appendSlice(a, &winfos);
    const xd = try a.alloc(i32, 1 << (lt + lk));
    var prng = std.Random.DefaultPrng.init(5);
    for (xd) |*v| v.* = (1 << 20) - 1 - @as(i32, prng.random().uintLessThan(u8, 4));
    const x = try b.add(proto.TensorInfo.mat(lt, lk), xd);
    // |x| < 2^20 proved by one 20-bit range key (bound 20, admitted for K = 2)
    try b.key(lt + lk, try b.expr(&.{tfm.term(1, xt.Ref.w(x), &.{tfm.ids(0, lt + lk)})}, 0), null, .{ .range = 20 });
    _ = try b.matmul(&ws, x, 0);
    _ = try b.matmul(&ws, x, 1);
    const st = b.statement();
    try proto.validateStatement(st);
    try std.testing.expectEqual(@as(u32, 20), proto.operandBoundLog2(st, x));
    const wit = try b.witnessView(a);
    defer a.free(wit);
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &pool, pc, st, &ws, wit, &tm);
    defer proof.deinit(a);
    try proto.verify(a, pc, st, proto.weightKey(&ws), &proof);
}

test "review-kern: KERN-3 matmul on a 20-bit range-keyed operand (T = 2^13) proves and verifies" {
    try wideOperandProof(false);
}

test "review-kern: KERN-3 batched shape-class matmuls on a 20-bit operand prove and verify" {
    try wideOperandProof(true);
}

test "review-kern: colCombine is exact at operandBoundLog2 for any i32 (unbounded -> 31)" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const R = 64;
    const C = 4;
    var data: [R * C]i32 = undefined;
    for (&data, 0..) |*d, i| d.* = if (i % 2 == 0) std.math.minInt(i32) else std.math.maxInt(i32);
    const m = pcs.Matrix(i32){ .data = &data, .log_rows = 6, .log_cols = 2 };
    var co: [R]QM31 = undefined;
    for (&co) |*c| c.* = QM31.fromU32Unchecked(f.P - 1, f.P - 1, f.P - 1, f.P - 1);
    const got = try linalg.colCombine(i32, a, &pool, m, &co, 31);
    defer a.free(got);
    for (0..C) |j| {
        var acc = QM31.zero();
        for (0..R) |i| acc = acc.add(co[i].mulM31(f.fromI64(data[i * C + j])));
        try std.testing.expect(acc.eql(got[j]));
    }
}

// rowDots at the declared bound with worst-case limbs (sanity: within contract).
test "review-kern: rowDots/combineRows exact at the declared bound with worst-case values" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 3);
    defer pool.deinit();
    const R = 4;
    const C = 1 << 12;
    const data = try a.alloc(i8, R * C);
    defer a.free(data);
    @memset(data, -128);
    const m = pcs.Matrix(i8){ .data = data, .log_rows = 2, .log_cols = 12 };
    const vec = try a.alloc(QM31, C);
    defer a.free(vec);
    @memset(vec, QM31.fromU32Unchecked(f.P - 1, f.P - 1, f.P - 1, f.P - 1));
    const rd = try linalg.rowDots(i8, a, &pool, m, vec, 7);
    defer a.free(rd);
    const want_l: u32 = @intCast((@as(u64, f.P - 1) * (P - 128) % P) * C % P);
    for (rd) |v| try std.testing.expectEqualSlices(u32, &.{ want_l, want_l, want_l, want_l }, &f.limbs(v));
    // i32 at the pcs2 bound (30): values -2^31 must also be exact
    const d32 = try a.alloc(i32, 64 * 4);
    defer a.free(d32);
    @memset(d32, -(1 << 30));
    const m32 = pcs.Matrix(i32){ .data = d32, .log_rows = 6, .log_cols = 2 };
    const co = try a.alloc(QM31, 64);
    defer a.free(co);
    @memset(co, QM31.fromU32Unchecked(f.P - 1, f.P - 1, f.P - 1, f.P - 1));
    const rows = try pcs.combineRows(i32, a, &pool, m32, &.{co}, 30);
    defer {
        for (rows) |x| a.free(x);
        a.free(rows);
    }
    var acc = QM31.zero();
    for (0..64) |_| acc = acc.add(co[0].mulM31(f.fromI32(-(1 << 30))));
    for (rows[0]) |v| try std.testing.expect(acc.eql(v));
}

// ---------------------------------------------------------------------------
// 3. Determinism across thread counts and the recycling allocator.
fn mlpDigest(backing: std.mem.Allocator, threads: usize, gkr_threads: usize) ![32]u8 {
    const a = backing;
    var pool: f.Pool = undefined;
    try pool.init(a, threads);
    defer pool.deinit();
    const cfg = model.Mlp{ .log_t = 3, .log_d = 5, .log_f = 6 };
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 2 }, .weight_log_cols = 5, .witness_log_cols_max = 6, .gkr_threads = gkr_threads };
    const winfos = model.mlpWeightInfos(cfg);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 300 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var ws = try proto.commitWeights(a, &pool, pc, &winfos, &wv);
    defer ws.deinit(a);
    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 17);
    defer a.free(x);
    var built = try model.buildMlp(a, &pool, &ws, cfg, x);
    defer built.deinit(a);
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &pool, pc, built.statement(), &ws, wview, &tm);
    defer proof.deinit(a);
    try proto.verify(a, pc, built.statement(), proto.weightKey(&ws), &proof);
    return digest.proofDigest(proof);
}

test "review-kern: proof digest independent of pool / GKR thread counts" {
    const a = std.testing.allocator;
    const d1 = try mlpDigest(a, 1, 1);
    for ([_][2]usize{ .{ 2, 1 }, .{ 3, 3 }, .{ 7, 2 }, .{ 16, 5 } }) |tc| {
        const d = try mlpDigest(a, tc[0], tc[1]);
        try std.testing.expectEqualSlices(u8, &d1, &d);
    }
}

test "review-kern: recycler (dirty reused blocks, tiny threshold) yields identical proofs" {
    var rc = recycle.Recycler.init(std.testing.allocator);
    defer rc.deinit();
    rc.threshold = 4096;
    const a = rc.allocator();
    const ref = try mlpDigest(std.testing.allocator, 2, 2);
    // poison the cache: allocate a spread of sizes, fill with garbage, free
    var blocks: [24][]u8 = undefined;
    for (&blocks, 0..) |*b, i| {
        b.* = try a.alloc(u8, 4096 + i * 16 * 1024 + 7);
        @memset(b.*, 0xA5);
    }
    for (blocks) |b| a.free(b);
    const d1 = try mlpDigest(a, 2, 2);
    const d2 = try mlpDigest(a, 3, 2);
    try std.testing.expect(rc.hits > 0);
    try std.testing.expectEqualSlices(u8, &ref, &d1);
    try std.testing.expectEqualSlices(u8, &ref, &d2);
}

test "review-kern: recycler concurrent alloc/free never aliases live blocks" {
    var rc = recycle.Recycler.init(std.heap.page_allocator);
    defer rc.deinit();
    rc.threshold = 1 << 14;
    const a = rc.allocator();
    const Worker = struct {
        fn run(al: std.mem.Allocator, id: u8, bad: *std.atomic.Value(u32)) void {
            var i: usize = 0;
            while (i < 300) : (i += 1) {
                const sz = (1 << 14) + (i % 3) * (1 << 14);
                const b = al.alloc(u8, sz) catch return;
                @memset(b, id);
                std.Thread.yield() catch {};
                for (b) |v| if (v != id) {
                    _ = bad.fetchAdd(1, .monotonic);
                    break;
                };
                al.free(b);
            }
        }
    };
    var bad = std.atomic.Value(u32).init(0);
    var th: [6]std.Thread = undefined;
    for (&th, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Worker.run, .{ a, @as(u8, @intCast(i + 1)), &bad });
    for (th) |t| t.join();
    try std.testing.expectEqual(@as(u32, 0), bad.load(.monotonic));
}
