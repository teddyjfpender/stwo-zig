//! Regression tests for the adversarial review (review-A findings), adapted
//! from the reviewers' failing tests in rev-{ext,proto,kern,parity}. Each test
//! asserts the correct behaviour and failed on 16ce61448.
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const xt = @import("ext.zig");
const tf = @import("transformer.zig");
const model = @import("model.zig");

const testing = std.testing;
const Ref = xt.Ref;
const TensorInfo = proto.TensorInfo;
const TI = proto.TensorInfo;
const P_M31: i64 = (1 << 31) - 1;

// ---------------------------------------------------------------------------
// EXT-5 / KERN-5: fromI32 on the ends of the i32 range.

test "EXT-5: mleEvalI32 on public values 2^31-1 and -2^31 is total and canonical" {
    const a = testing.allocator;
    const vals = [_]i32{ std.math.maxInt(i32), std.math.minInt(i32) };
    // MLE at (1) picks vals[1] = -2^31 = p - 1 (mod p); at (0) vals[0] = p = 0
    const one = [_]f.QM31{f.QM31.one()};
    const zero = [_]f.QM31{f.QM31.zero()};
    try testing.expect((try f.mleEvalI32(a, &vals, &one)).eql(f.QM31.fromBase(f.fromI64(std.math.minInt(i32)))));
    try testing.expect((try f.mleEvalI32(a, &vals, &zero)).eql(f.QM31.zero()));
}

// ---------------------------------------------------------------------------
// EXT-1 / EXT-3: softmax-PV.

const Att = struct {
    pool: f.Pool,
    ws: proto.WeightStore,
    b: tf.Builder,
    at: tf.AttnOut,
    pc: proto.Config,
};

/// Attention core alone at T = 2^lt, 1 head, dh = 2. q, k are all zero (every
/// score is 0, so row t has den = 256 (t + 1)); v[j, :] = v_of(j). The
/// operands are range-checked (9-bit q / k as RoPE outputs, int8 v) so the
/// statement passes validateStatement's no-wrap checks.
const att_winfo = [_]TensorInfo{TensorInfo.mat(2, 2)};

fn buildAtt(a: std.mem.Allocator, att: *Att, lt: u32, v_of: *const fn (usize) i32) !void {
    try att.pool.init(a, 2);
    att.pc = .{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .weight_log_cols = 2, .witness_log_cols_max = 8, .gkr_threads = 2 };
    var dummy: [16]i8 = [_]i8{0} ** 16;
    const dv = [_][]const i8{&dummy};
    // WeightStore borrows `infos` (the key's layout is checked against it at
    // prove and verify time), so they must outlive the store: container scope.
    att.ws = try proto.commitWeights(a, &att.pool, att.pc, &att_winfo, &dv);
    att.b = tf.Builder.init(a, &att.pool);
    const b = &att.b;
    try b.weight_infos.append(a, TensorInfo.mat(2, 2));
    const cfg = tf.LayerCfg{ .log_t = lt, .log_d = 1, .log_f = 1, .log_heads = 0, .log_kv_heads = 0 };
    try cfg.validate();
    const cb = try tf.causalBias(a, lt);
    defer a.free(cb);
    const bias = try b.public(2 * lt, cb);
    const et = tf.expTable();
    const exp_table = try b.xtable(10, &et);
    const c = tf.Ctx{ .cfg = cfg, .ws = &att.ws, .rope = 0, .bias = bias, .exp_table = exp_table, .silu = 0, .gammas = &.{} };
    const T = @as(usize, 1) << @intCast(lt);
    const qr = try b.add(TensorInfo.mat(lt, 1), try a.alloc(i32, 2 * T));
    @memset(b.wit.items[qr], 0);
    try b.rangeSigned(qr, 9);
    const kr = try b.add(TensorInfo.mat(lt, 1), try a.alloc(i32, 2 * T));
    @memset(b.wit.items[kr], 0);
    try b.rangeSigned(kr, 9);
    const v = try b.add(TensorInfo.mat(lt, 1), try a.alloc(i32, 2 * T));
    for (0..T) |j| {
        b.wit.items[v][2 * j] = v_of(j);
        b.wit.items[v][2 * j + 1] = v_of(j);
    }
    try b.rangeSigned(v, 8);
    att.at = try tf.attention(b, c, qr, kr, v, &.{});
}

fn deinitAtt(a: std.mem.Allocator, att: *Att) void {
    att.b.deinit();
    att.ws.deinit(a);
    att.pool.deinit();
}

fn proveVerify(a: std.mem.Allocator, att: *Att) !void {
    const st = att.b.statement();
    const wv = try att.b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &att.pool, att.pc, st, &att.ws, wv, &tm);
    defer proof.deinit(a);
    try proto.verify(a, att.pc, st, proto.weightKey(&att.ws), &proof);
}

fn vFirst(j: usize) i32 {
    return @intFromBool(j == 0);
}
fn vConst(_: usize) i32 {
    return 100;
}

/// The rangeWide limbs (lo, hi) of the division slack whose expression has
/// `coeff * acc` as its first term.
fn slackLimbs(b: *const tf.Builder, acc: u32, coeff: i64) ![2]u32 {
    for (b.xops.items) |op| if (op == .lineq) {
        const t = op.lineq.expr.terms;
        if (t.len != 5) continue;
        for (t[0..3]) |x| if (x.t.id == acc and !x.t.public and x.coeff == coeff) return .{ t[3].t.id, t[4].t.id };
    };
    return error.NoSlack;
}

// EXT-1 (was: "softmax reciprocal wraps mod p at lt = 8 (cheating rden
// accepted)"). The reciprocal rden is gone; the analogous attack inflates the
// output o of the last row (the reviewer's cheat made O[T-1] = 64 instead of 1)
// with od = o * den recomputed in the field and the slack limbs recomputed mod p.
// Every product is now below 2^(lt+15), so no value of o in int8 can satisfy
// the division slack except the honest one.
test "EXT-1: softmax at lt = 8 verifies honestly; inflated outputs with consistent products are rejected" {
    const a = testing.allocator;
    const lt: u32 = 8;
    var att: Att = undefined;
    try buildAtt(a, &att, lt, &vFirst);
    defer deinitAtt(a, &att);
    try proto.validateStatement(att.b.statement());
    try proveVerify(a, &att); // completeness at this size

    const b = &att.b;
    const at = att.at;
    const T = @as(usize, 1) << @intCast(lt);
    const row = T - 1;
    const den: i64 = b.wit.items[at.den][row];
    try testing.expectEqual(@as(i64, 256 * 256), den);
    try testing.expectEqual(@as(i32, 0), b.wit.items[at.o][row * 2]); // round(256 / 65536) = 0
    const lo1 = try slackLimbs(b, at.acc, 2);
    const lo2 = try slackLimbs(b, at.acc, -2);
    for ([_]i32{ 1, 64, 127, -1 }) |o_c| {
        const acc: i64 = b.wit.items[at.acc][row * 2];
        const od: i64 = @mod(@as(i64, o_c) * den, P_M31);
        const s1: i64 = @mod(2 * acc + den - 2 * od, P_M31);
        const s2: i64 = @mod(den - 2 * acc + 2 * od - 1, P_M31);
        const sv = .{ b.wit.items[at.o][row * 2], b.wit.items[at.od][row * 2], b.wit.items[lo1[0]][row * 2], b.wit.items[lo1[1]][row * 2], b.wit.items[lo2[0]][row * 2], b.wit.items[lo2[1]][row * 2] };
        b.wit.items[at.o][row * 2] = o_c;
        b.wit.items[at.od][row * 2] = @intCast(od);
        b.wit.items[lo1[0]][row * 2] = @intCast(s1 & 0xffff);
        b.wit.items[lo1[1]][row * 2] = @intCast(s1 >> 16);
        b.wit.items[lo2[0]][row * 2] = @intCast(s2 & 0xffff);
        b.wit.items[lo2[1]][row * 2] = @intCast(s2 >> 16);
        {
            xt.test_unchecked_prover = true;
            defer xt.test_unchecked_prover = false;
            const st = b.statement();
            const wv = try b.witnessView(a);
            defer a.free(wv);
            var tm: proto.Timings = .{};
            var proof = try proto.prove(a, &att.pool, att.pc, st, &att.ws, wv, &tm);
            defer proof.deinit(a);
            if (proto.verify(a, att.pc, st, proto.weightKey(&att.ws), &proof)) |_| {
                std.debug.print("[regress] VERIFIER ACCEPTED o = {d} (honest 0)\n", .{o_c});
                return error.CheatAccepted;
            } else |_| {}
        }
        b.wit.items[at.o][row * 2] = sv[0];
        b.wit.items[at.od][row * 2] = sv[1];
        b.wit.items[lo1[0]][row * 2] = sv[2];
        b.wit.items[lo1[1]][row * 2] = sv[3];
        b.wit.items[lo2[0]][row * 2] = sv[4];
        b.wit.items[lo2[1]][row * 2] = sv[5];
    }
    try proveVerify(a, &att); // restored witness still verifies
}

// EXT-3 (was: "honest integer softmax is not normalised on flat rows (T = 256,
// 512, 1024)"; old sums 2.0 / 0.0 / 0.0). With v constant the softmax-weighted
// average must return v exactly on every row, at every T.
test "EXT-3: honest softmax is normalised on flat rows (T = 256, 512, 1024)" {
    const a = testing.allocator;
    inline for (.{ 8, 9, 10 }) |lt| {
        var att: Att = undefined;
        try buildAtt(a, &att, lt, &vConst);
        defer deinitAtt(a, &att);
        for (att.b.wit.items[att.at.o]) |o| try testing.expectEqual(@as(i32, 100), o);
    }
    // one-hot v at T = 512: row t averages over t + 1 equal weights, so
    // o[t] = round(1 / (t + 1)) (the old 1/128-resolution P gave 0 for every row)
    var att: Att = undefined;
    try buildAtt(a, &att, 9, &vFirst);
    defer deinitAtt(a, &att);
    const o = att.b.wit.items[att.at.o];
    try testing.expectEqual(@as(i32, 1), o[0]);
    try testing.expectEqual(@as(i32, 1), o[2 * 1]); // round(1/2) = 1 (half up)
    try testing.expectEqual(@as(i32, 0), o[2 * 2]);
}

// The old reciprocal gadget, as a statement: rden in [0, 2^16) by a range key,
// den = sum_j e with e from the exp table (|den| <= 2^(lt+8)), pr = rden * den
// exact. At lt = 8 the integer product reaches 2^32: validateStatement now
// rejects it from the statement alone (EXT-1, statement-level no-wrap check).
test "EXT-1: an exact product that can exceed p is rejected by validateStatement" {
    const lt: u32 = 8;
    const infos = [_]TI{ TI.vec(2 * lt), TI.vec(2 * lt), TI.vec(lt), TI.vec(lt), TI.vec(lt) }; // d, e, den, rden, pr
    var et = tf.expTable();
    const tables = [_]xt.LookupTable{.{ .log_size = 10, .values = &et }};
    const all2 = xt.labels(tf.ids(0, 2 * lt));
    const all1 = xt.labels(tf.ids(0, lt));
    const sum_lab = tf.cat(&.{ tf.ids(0, lt), tf.sums(lt) });
    const eops = [_]xt.Op{
        .{ .key = .{ .n = @intCast(2 * lt), .input = .{ .terms = &.{.{ .coeff = 1, .t = Ref.w(0), .labels = all2 }} }, .output = .{ .terms = &.{.{ .coeff = 1, .t = Ref.w(1), .labels = all2 }} }, .table = .{ .lookup = 0 } } },
        .{ .lineq = .{ .n = @intCast(lt), .expr = .{ .terms = &.{ .{ .coeff = 1, .t = Ref.w(2), .labels = all1 }, .{ .coeff = -1, .t = Ref.w(1), .labels = sum_lab } } } } },
        .{ .key = .{ .n = @intCast(lt), .input = .{ .terms = &.{.{ .coeff = 1, .t = Ref.w(3), .labels = all1 }} }, .table = .{ .range = 16 } } },
        .{ .einsum = .{ .a = Ref.w(3), .b = Ref.w(2), .y = 4, .n_out = @intCast(lt), .n_k = 0, .a_labels = all1, .b_labels = all1 } },
    };
    var st = proto.Statement{ .witness = &infos, .weights = &.{}, .tables = &.{}, .ops = &.{}, .ext = .{ .ops = &eops, .tables = &tables } };
    try testing.expectError(error.StatementAccumulatorBound, proto.validateStatement(st));
    // at lt = 4 the same gadget (rden < 2^12) fits: 12 + 12 <= 29
    const lt4: u32 = 4;
    const infos4 = [_]TI{ TI.vec(2 * lt4), TI.vec(2 * lt4), TI.vec(lt4), TI.vec(lt4), TI.vec(lt4) };
    const a2 = xt.labels(tf.ids(0, 2 * lt4));
    const a1 = xt.labels(tf.ids(0, lt4));
    const sl = tf.cat(&.{ tf.ids(0, lt4), tf.sums(lt4) });
    const eops4 = [_]xt.Op{
        .{ .key = .{ .n = @intCast(2 * lt4), .input = .{ .terms = &.{.{ .coeff = 1, .t = Ref.w(0), .labels = a2 }} }, .output = .{ .terms = &.{.{ .coeff = 1, .t = Ref.w(1), .labels = a2 }} }, .table = .{ .lookup = 0 } } },
        .{ .lineq = .{ .n = @intCast(lt4), .expr = .{ .terms = &.{ .{ .coeff = 1, .t = Ref.w(2), .labels = a1 }, .{ .coeff = -1, .t = Ref.w(1), .labels = sl } } } } },
        .{ .key = .{ .n = @intCast(lt4), .input = .{ .terms = &.{.{ .coeff = 1, .t = Ref.w(3), .labels = a1 }} }, .table = .{ .range = 12 } } },
        .{ .einsum = .{ .a = Ref.w(3), .b = Ref.w(2), .y = 4, .n_out = @intCast(lt4), .n_k = 0, .a_labels = a1, .b_labels = a1 } },
    };
    st = .{ .witness = &infos4, .weights = &.{}, .tables = &.{}, .ops = &.{}, .ext = .{ .ops = &eops4, .tables = &tables } };
    try proto.validateStatement(st);
}

// ---------------------------------------------------------------------------
// PROTO-1, PROTO-2, PROTO-4, EXT-2: validateStatement bound derivation.

fn cfgP() proto.Config {
    return .{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .weight_log_cols = 2, .witness_log_cols_max = 4, .gkr_threads = 1 };
}

/// integer matmul X[T,K] . W[K,N] (i64)
fn matmulI64(a: std.mem.Allocator, x: []const i32, w: []const i8, T: usize, K: usize, N: usize) ![]i64 {
    const out = try a.alloc(i64, T * N);
    for (0..T) |t| for (0..N) |n| {
        var s: i64 = 0;
        for (0..K) |k| s += @as(i64, x[t * K + k]) * w[k * N + n];
        out[t * N + n] = s;
    };
    return out;
}

fn modP(v: i64) i64 {
    var r = @mod(v, P_M31);
    if (r > @divFloor(P_M31, 2)) r -= P_M31;
    return r;
}

/// Proves a cheating witness (the integer accumulator wraps mod p) and returns
/// the verifier's verdict; validation errors are returned before proving.
fn proveCheat(st: proto.Statement, x: []const i32, extra: []const []const i32, w: *const [16]i8) !void {
    const a = testing.allocator;
    try proto.validateStatement(st);
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const acc_int = try matmulI64(a, x, w, 2, 4, 4);
    defer a.free(acc_int);
    var accf: [8]i64 = undefined;
    var y: [8]i32 = undefined;
    for (0..8) |i| {
        accf[i] = modP(acc_int[i]);
        y[i] = proto.requant(accf[i], 1);
    }
    const pc = cfgP();
    const wv = [_][]const i8{w};
    var ws = try proto.commitWeights(a, &pool, pc, st.weights, &wv);
    defer ws.deinit(a);
    var wit: [4][]const i32 = undefined;
    for (extra, 0..) |e, i| wit[i] = e;
    wit[extra.len] = &y;
    var accs: [1]?[]i64 = .{&accf};
    var tm: proto.Timings = .{};
    var proof = try proto.proveWithAccumulators(a, &pool, pc, st, &ws, wit[0 .. extra.len + 1], &accs, &tm);
    defer proof.deinit(a);
    try proto.verify(a, pc, st, proto.weightKey(&ws), &proof);
    return error.UnboundedOperandAccepted;
}

// PROTO-2 (was R2): EXT_EXACT_BOUND let an unbounded tensor be a matmul operand.
test "PROTO-2: exact ext einsum output of an unbounded witness is not a valid matmul operand" {
    const infos = [_]TI{ TI.vec(3), TI.mat(1, 2), TI.mat(1, 2) };
    const winfos = [_]TI{TI.mat(2, 2)};
    var w: [16]i8 = [_]i8{0} ** 16;
    for (0..8) |i| w[i] = 1;
    var ones: [8]i32 = [_]i32{1} ** 8;
    const pubs = [_]xt.Public{.{ .log_size = 3, .values = &ones }};
    const eops = [_]xt.Op{.{ .einsum = .{ .a = xt.Ref.w(0), .b = xt.Ref.p(0), .y = 1, .n_out = 3, .n_k = 0, .a_labels = xt.labels(&.{ 0, 1, 2 }), .b_labels = xt.labels(&.{ 0, 1, 2 }) } }};
    const ops = [_]proto.Op{.{ .matmul = .{ .x = 1, .w = 0, .y = 2, .shift = 1 } }};
    const st = proto.Statement{ .witness = &infos, .weights = &winfos, .tables = &.{}, .ops = &ops, .ext = .{ .ops = &eops, .publics = &pubs } };
    const big: i32 = 1 << 30;
    var u: [8]i32 = .{ big, big, 0, 0, big, big, 0, 0 };
    try testing.expectError(error.StatementUnboundedOperand, proveCheat(st, &u, &.{ &u, &u }, &w));
    // with U range-checked (int8) the same einsum output is a valid operand:
    // bound(X) = bound(U) + bound(ones) + n_k = 7 + 0 + 0
    const kops = [_]xt.Op{
        .{ .key = .{ .n = 3, .input = .{ .terms = &.{.{ .coeff = 1, .t = Ref.w(0), .labels = xt.labels(&.{ 0, 1, 2 }) }}, .constant = 128 }, .table = .{ .range = 8 } } },
        eops[0],
    };
    var st2 = st;
    st2.ext.ops = &kops;
    try proto.validateStatement(st2);
}

fn keyStatement(comptime use_sum: bool, eops: *[1]xt.Op, terms: *[1]xt.Term) proto.Statement {
    const S = struct {
        const infos = [_]TI{ TI.mat(1, 2), TI.mat(1, 2) };
        const winfos = [_]TI{TI.mat(2, 2)};
        const ops = [_]proto.Op{.{ .matmul = .{ .x = 0, .w = 0, .y = 1, .shift = 1 } }};
    };
    const lab = if (use_sum) xt.labels(&.{ xt.SUM, 0, 1 }) else xt.labels(&.{ xt.FIX0, 0, 1 });
    terms[0] = .{ .coeff = 1, .t = xt.Ref.w(0), .labels = lab };
    eops[0] = .{ .key = .{ .n = 2, .input = .{ .terms = terms }, .table = .{ .range = 8 } } };
    return .{ .witness = &S.infos, .weights = &S.winfos, .tables = &.{}, .ops = &S.ops, .ext = .{ .ops = eops } };
}

// PROTO-1 (was R3a / R3b): a key with a SUM label, or on a FIX0 slice, bounded
// the whole tensor; the verifier accepted wrapped matmul accumulators.
test "PROTO-1: SUM- or FIX-labelled range keys do not bound a matmul operand" {
    var w: [16]i8 = [_]i8{0} ** 16;
    for (0..8) |i| w[i] = 1;
    const big: i32 = 1 << 30;
    inline for (.{ true, false }) |use_sum| {
        var eops: [1]xt.Op = undefined;
        var terms: [1]xt.Term = undefined;
        const st = keyStatement(use_sum, &eops, &terms);
        try xt.validate(st);
        var x: [8]i32 = if (use_sum) .{ big, big, 0, 0, -big + 3, -big + 3, 5, 5 } else .{ 3, 3, 3, 3, big, big, 0, 0 };
        try testing.expectError(error.StatementUnboundedOperand, proveCheat(st, &x, &.{&x}, &w));
    }
}

// EXT-2 (was "validateStatement infers a full-tensor bound from a FIX-slice /
// SUM range key").
test "EXT-2: validateStatement fails closed on FIX-slice and SUM range keys" {
    const infos = [_]TI{ TI.mat(1, 2), TI.mat(1, 2) };
    const winfo = [_]TI{TI.mat(2, 2)};
    const ops = [_]proto.Op{.{ .matmul = .{ .x = 0, .w = 0, .y = 1, .shift = 1 } }};
    const base = proto.Statement{ .witness = &infos, .weights = &winfo, .tables = &.{}, .ops = &ops };
    try testing.expectError(error.StatementUnboundedOperand, proto.validateStatement(base));
    const k_slice = [_]xt.Op{.{ .key = .{ .n = 2, .input = .{ .terms = &.{.{ .coeff = 1, .t = Ref.w(0), .labels = xt.labels(&.{ xt.FIX0, 0, 1 }) }}, .constant = 128 }, .table = .{ .range = 8 } } }};
    var st = base;
    st.ext = .{ .ops = &k_slice };
    try xt.validate(st);
    try testing.expectError(error.StatementUnboundedOperand, proto.validateStatement(st));
    const k_sum = [_]xt.Op{.{ .key = .{ .n = 0, .input = .{ .terms = &.{.{ .coeff = 1, .t = Ref.w(0), .labels = xt.labels(&.{ xt.FIX0, xt.SUM, xt.SUM }) }}, .constant = 128 }, .table = .{ .range = 8 } } }};
    st.ext = .{ .ops = &k_sum };
    try xt.validate(st);
    try testing.expectError(error.StatementUnboundedOperand, proto.validateStatement(st));
    // repeated (diagonal) labels do not cover the tensor either
    const k_diag = [_]xt.Op{.{ .key = .{ .n = 2, .input = .{ .terms = &.{.{ .coeff = 1, .t = Ref.w(0), .labels = xt.labels(&.{ 0, 0, 1 }) }}, .constant = 128 }, .table = .{ .range = 8 } } }};
    st.ext = .{ .ops = &k_diag };
    try testing.expect(std.meta.isError(proto.validateStatement(st)));
    // a plain key over all bits bounds the operand
    const k_full = [_]xt.Op{.{ .key = .{ .n = 3, .input = .{ .terms = &.{.{ .coeff = 1, .t = Ref.w(0), .labels = xt.labels(&.{ 0, 1, 2 }) }}, .constant = 128 }, .table = .{ .range = 8 } } }};
    st.ext = .{ .ops = &k_full };
    try proto.validateStatement(st);
}

// PROTO-4 (was R5, opt-in panic probe): malformed ext statements are rejected
// before any indexing, in every build mode.
test "PROTO-4: validateStatement rejects out-of-range ids and bad shapes without indexing" {
    const infos = [_]TI{ TI.vec(2), TI.vec(2) };
    const eops = [_]xt.Op{.{ .einsum = .{ .a = xt.Ref.w(0), .b = xt.Ref.w(1), .y = 9, .n_out = 2, .n_k = 0, .a_labels = xt.labels(&.{ 0, 1 }), .b_labels = xt.labels(&.{ 0, 1 }) } }};
    var st = proto.Statement{ .witness = &infos, .weights = &.{}, .tables = &.{}, .ops = &.{}, .ext = .{ .ops = &eops } };
    try testing.expectError(error.ExtStatement, proto.validateStatement(st));
    // y >= 4096 (old: out-of-bounds stack write in ReleaseFast)
    var big = eops;
    big[0].einsum.y = 5000;
    st.ext.ops = &big;
    try testing.expectError(error.ExtStatement, proto.validateStatement(st));
    // key on a lookup table that does not exist
    const kops = [_]xt.Op{.{ .key = .{ .n = 2, .input = .{ .terms = &.{.{ .coeff = 1, .t = Ref.w(0), .labels = xt.labels(&.{ 0, 1 }) }} }, .output = .{ .terms = &.{.{ .coeff = 1, .t = Ref.w(1), .labels = xt.labels(&.{ 0, 1 }) }} }, .table = .{ .lookup = 3 } } }};
    st.ext.ops = &kops;
    try testing.expectError(error.ExtStatement, proto.validateStatement(st));
    // n_dims beyond MAX_DIMS
    var bad = infos;
    bad[0].n_dims = 9;
    st = .{ .witness = &bad, .weights = &.{}, .tables = &.{}, .ops = &.{} };
    try testing.expectError(error.StatementShape, proto.validateStatement(st));
    // core op ids out of range
    const cops = [_]proto.Op{.{ .hadamard = .{ .a = 0, .b = 7, .y = 1, .shift = 1 } }};
    st = .{ .witness = &infos, .weights = &.{}, .tables = &.{}, .ops = &cops };
    try testing.expectError(error.StatementShape, proto.validateStatement(st));
}

// PROTO-2 with MoE: the dispatch selector is boolean (Disp^2 = Disp) and one-hot
// over tokens (occ = sum_t Disp, occ boolean), so Xe = Disp . y is int8-bounded
// (7) and a valid expert matmul operand; without the boolean proof it is not.
test "PROTO-2: MoE dispatch output validates via the proved one-hot selector, not without it" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = tf.LayerCfg{ .log_t = 3, .log_d = 4, .log_f = 5, .log_heads = 1, .log_kv_heads = 0, .log_experts = 2, .log_capacity = 3, .router_log_cols = 3 };
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 }, .weight_log_cols = 3, .witness_log_cols_max = 8, .gkr_threads = 2 };
    var sw = try tf.setupWeights(a, &pool, cfg, pc, 900);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    var b = tf.Builder.init(a, &pool);
    defer b.deinit();
    const c = try tf.initCtx(&b, cfg, &sw.ws, 901);
    const x = try model.randomInput(a, @as(usize, 1) << @intCast(cfg.log_t + cfg.log_d), 902);
    defer a.free(x);
    const out = try tf.buildStack(&b, c, x);
    const st = b.statement();
    try proto.validateStatement(st);
    // drop Disp^2 = Disp: Xe loses its bound, the expert matmuls are rejected
    const xops = try a.dupe(xt.Op, st.ext.ops);
    defer a.free(xops);
    const disp = out.moe.?.disp;
    var dropped = false;
    for (xops) |*op| if (op.* == .einsum and op.einsum.y != null and op.einsum.y.? == disp and op.einsum.a.id == disp) {
        // keep the op count; turn it into a harmless zero-check on a boolean
        op.* = .{ .lineq = .{ .n = 0, .expr = .{} } };
        dropped = true;
    };
    try testing.expect(dropped);
    var st2 = st;
    st2.ext.ops = xops;
    try testing.expectError(error.StatementUnboundedOperand, proto.validateStatement(st2));
}

// ---------------------------------------------------------------------------
// P1 / P2: I/O binding and a public model definition.

const MlpCfg = model.Mlp{ .log_t = 3, .log_d = 5, .log_f = 6 };
const MlpPC = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 16, .pow_bits = 2 }, .weight_log_cols = 4, .witness_log_cols_max = 6, .gkr_threads = 1 };

const MlpSetup = struct {
    pool: f.Pool,
    wdata: [3][]i8,
    winfos: [3]TensorInfo,
    ws: proto.WeightStore,

    fn init(self: *MlpSetup, a: std.mem.Allocator, seed: u64) !void {
        try self.pool.init(a, 1);
        self.winfos = model.mlpWeightInfos(MlpCfg); // ws.infos points here
        for (&self.wdata, 0..) |*w, i| w.* = try model.randomWeights(a, self.winfos[i].size(), seed + i, -8, 7);
        const wv = [_][]const i8{ self.wdata[0], self.wdata[1], self.wdata[2] };
        self.ws = try proto.commitWeights(a, &self.pool, MlpPC, &self.winfos, &wv);
    }
    fn deinit(self: *MlpSetup, a: std.mem.Allocator) void {
        self.ws.deinit(a);
        for (self.wdata) |w| a.free(w);
        self.pool.deinit();
    }
};

fn proveBuilt(a: std.mem.Allocator, s: *MlpSetup, b: *const model.Built) !proto.Proof {
    const wv = try a.alloc([]const i32, b.witness.len);
    defer a.free(wv);
    for (b.witness, 0..) |w, i| wv[i] = w;
    var tm: proto.Timings = .{};
    return proto.prove(a, &s.pool, MlpPC, b.statement(), &s.ws, wv, &tm);
}

// P1 (was "review-parity: MLP proof for input X2 verifies under the statement
// built from a different input X1", which passed: the statement bound no I/O).
test "P1: an MLP proof for input X2 is rejected for the statement of X1 (and for a wrong output)" {
    const a = testing.allocator;
    var s: MlpSetup = undefined;
    try s.init(a, 300);
    defer s.deinit(a);
    const D = @as(usize, 1) << MlpCfg.log_d;
    const x1 = try model.randomInput(a, @as(usize, 1) << (MlpCfg.log_t + MlpCfg.log_d), 11);
    defer a.free(x1);
    const x2 = try a.dupe(i32, x1); // tokens 0 and 1 swapped: same shifts, different output
    defer a.free(x2);
    for (0..D) |d| std.mem.swap(i32, &x2[d], &x2[D + d]);
    const mc = try model.calibrateMlp(a, &s.pool, &s.ws, MlpCfg, &.{ x1, x2 });
    var b1 = try model.buildMlpWith(a, &s.pool, &s.ws, mc, x1);
    defer b1.deinit(a);
    var b2 = try model.buildMlpWith(a, &s.pool, &s.ws, mc, x2);
    defer b2.deinit(a);
    const y1 = b1.witness[b1.witness.len - 1];
    const y2 = b2.witness[b2.witness.len - 1];
    try testing.expect(!std.mem.eql(i32, y1, y2));
    var proof2 = try proveBuilt(a, &s, &b2);
    defer proof2.deinit(a);
    const key = proto.weightKey(&s.ws);
    // the verifier's own statements (no prover-supplied statement)
    var v2 = try model.mlpStatement(a, mc, x2, y2);
    defer v2.deinit(a);
    try proto.verify(a, MlpPC, v2.statement(), key, &proof2);
    var v1 = try model.mlpStatement(a, mc, x1, y1);
    defer v1.deinit(a);
    try testing.expect(std.meta.isError(proto.verify(a, MlpPC, v1.statement(), key, &proof2)));
    var v12 = try model.mlpStatement(a, mc, x1, y2);
    defer v12.deinit(a);
    try testing.expect(std.meta.isError(proto.verify(a, MlpPC, v12.statement(), key, &proof2)));
    // the prover's statement for X1 rejects it too
    try testing.expect(std.meta.isError(proto.verify(a, MlpPC, b1.statement(), key, &proof2)));
    // claimed output off by one
    const y_bad = try a.dupe(i32, y2);
    defer a.free(y_bad);
    y_bad[0] += 1;
    var vb = try model.mlpStatement(a, mc, x2, y_bad);
    defer vb.deinit(a);
    try testing.expect(std.meta.isError(proto.verify(a, MlpPC, vb.statement(), key, &proof2)));
}

// P2 (was "review-parity: requant shifts (the model's scales) are chosen by the
// prover from the input", which passed: X1 and X1/16 got different shifts).
test "P2: shifts come from a fixed MlpConfig; another config's statement rejects the proof" {
    const a = testing.allocator;
    var s: MlpSetup = undefined;
    try s.init(a, 400);
    defer s.deinit(a);
    const x1 = try model.randomInput(a, @as(usize, 1) << (MlpCfg.log_t + MlpCfg.log_d), 12);
    defer a.free(x1);
    const x2 = try a.dupe(i32, x1);
    defer a.free(x2);
    for (x2) |*v| v.* = @divFloor(v.*, 16);
    const mc = try model.calibrateMlp(a, &s.pool, &s.ws, MlpCfg, &.{x1});
    var b1 = try model.buildMlpWith(a, &s.pool, &s.ws, mc, x1);
    defer b1.deinit(a);
    var b2 = try model.buildMlpWith(a, &s.pool, &s.ws, mc, x2);
    defer b2.deinit(a);
    // same model, same scales, for both inputs
    try testing.expectEqualSlices(proto.Op, b1.ops, b2.ops);
    try testing.expectEqualSlices(u8, &b1.model_digest.?, &b2.model_digest.?);
    var proof = try proveBuilt(a, &s, &b2);
    defer proof.deinit(a);
    const key = proto.weightKey(&s.ws);
    const y2 = b2.witness[b2.witness.len - 1];
    var v = try model.mlpStatement(a, mc, x2, y2);
    defer v.deinit(a);
    try proto.verify(a, MlpPC, v.statement(), key, &proof);
    // a different (e.g. per-input) shift choice is a different model: rejected
    var mc2 = mc;
    mc2.shifts[3] += 1;
    var v2 = try model.mlpStatement(a, mc2, x2, y2);
    defer v2.deinit(a);
    try testing.expect(std.meta.isError(proto.verify(a, MlpPC, v2.statement(), key, &proof)));
    // ops identical but a different model digest: rejected (the digest is bound)
    var v3 = try model.mlpStatement(a, mc, x2, y2);
    defer v3.deinit(a);
    v3.model_digest.?[0] ^= 1;
    try testing.expect(std.meta.isError(proto.verify(a, MlpPC, v3.statement(), key, &proof)));
    // an input outside the calibrated model is refused by the prover
    const x3 = try a.dupe(i32, x1);
    defer a.free(x3);
    for (x3) |*q| q.* = if (q.* >= 0) 127 else -128;
    try testing.expectError(error.RequantOverflow, model.buildMlpWith(a, &s.pool, &s.ws, mc, x3));
}

fn layerIoCase(cfg: tf.LayerCfg, seed: u64) !void {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 }, .weight_log_cols = 3, .witness_log_cols_max = 8, .gkr_threads = 2 };
    var sw = try tf.setupWeights(a, &pool, cfg, pc, seed);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    const n_in = @as(usize, 1) << @intCast(cfg.log_t + cfg.log_d);
    const x1 = try model.randomInput(a, n_in, seed + 1);
    defer a.free(x1);
    const x2 = try a.dupe(i32, x1);
    defer a.free(x2);
    x2[0] = if (x2[0] > 0) x2[0] - 1 else x2[0] + 1;
    const mc = try tf.calibrate(a, &pool, &sw.ws, cfg, seed + 2, &.{ x1, x2 });
    defer a.free(mc.shifts);
    var b = tf.Builder.init(a, &pool);
    defer b.deinit();
    const out = try tf.buildWith(&b, mc, &sw.ws, x1);
    const y1 = b.wit.items[out.out];
    const wv = try b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &pool, pc, b.statement(), &sw.ws, wv, &tm);
    defer proof.deinit(a);
    const key = proto.weightKey(&sw.ws);
    // verifier builds the statement from (ModelConfig, x, claimed y), no weights
    var v1 = try tf.statementFor(a, &pool, mc, x1, y1);
    defer v1.deinit();
    try proto.verify(a, pc, v1.statement(), key, &proof);
    var v2 = try tf.statementFor(a, &pool, mc, x2, y1);
    defer v2.deinit();
    try testing.expect(std.meta.isError(proto.verify(a, pc, v2.statement(), key, &proof)));
    const y_bad = try a.dupe(i32, y1);
    defer a.free(y_bad);
    y_bad[y_bad.len - 1] += 1;
    var v3 = try tf.statementFor(a, &pool, mc, x1, y_bad);
    defer v3.deinit();
    try testing.expect(std.meta.isError(proto.verify(a, pc, v3.statement(), key, &proof)));
    const sh2 = try a.dupe(u5, mc.shifts);
    defer a.free(sh2);
    sh2[0] += 1;
    var mc2 = mc;
    mc2.shifts = sh2;
    var v4 = try tf.statementFor(a, &pool, mc2, x1, y1);
    defer v4.deinit();
    try testing.expect(std.meta.isError(proto.verify(a, pc, v4.statement(), key, &proof)));
}

test "P1/P2: decoder layer statements are built by the verifier from (ModelConfig, x, y); other inputs, outputs, configs rejected" {
    try layerIoCase(.{ .log_t = 2, .log_d = 4, .log_f = 5, .log_heads = 2, .log_kv_heads = 1 }, 70);
    try layerIoCase(.{ .log_t = 3, .log_d = 4, .log_f = 5, .log_heads = 1, .log_kv_heads = 0, .log_experts = 2, .log_capacity = 3, .router_log_cols = 3 }, 80);
    try layerIoCase(.{ .log_t = 2, .log_d = 4, .log_f = 5, .log_heads = 1, .log_kv_heads = 0, .n_layers = 2, .fused_qkv = true }, 90);
}
