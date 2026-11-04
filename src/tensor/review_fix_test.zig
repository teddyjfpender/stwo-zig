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
fn buildAtt(a: std.mem.Allocator, att: *Att, lt: u32, v_of: *const fn (usize) i32) !void {
    try att.pool.init(a, 2);
    att.pc = .{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .weight_log_cols = 2, .witness_log_cols_max = 8, .gkr_threads = 2 };
    var dummy: [16]i8 = [_]i8{0} ** 16;
    const dv = [_][]const i8{&dummy};
    const winfo = [_]TensorInfo{TensorInfo.mat(2, 2)};
    att.ws = try proto.commitWeights(a, &att.pool, att.pc, &winfo, &dv);
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
