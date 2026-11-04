//! Wide slack key (ledger.md section "wide slack key"): above 16 bits,
//! `Builder.rangeWide` emits ONE key of the (never committed) expression into
//! range(bits) when bits <= MAX_TABLE_BITS and n >= bits + 2, instead of two
//! committed 16-bit limbs, two limb keys and a limb lineq. These tests pin the
//! rule, the statement shape, completeness, and soundness against an
//! out-of-range expression (slack = -1, slack = 2^bits) and against the
//! inflated-attention-output attack of EXT-1 in the virtual form.
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const xt = @import("ext.zig");
const tf = @import("transformer.zig");
const rf = @import("review_fix_test.zig");

const testing = std.testing;
const Ref = xt.Ref;
const TensorInfo = proto.TensorInfo;
const term = tf.term;
const ids = tf.ids;
const P_M31: i64 = (1 << 31) - 1;

test "wide slack key: rule depends only on (n, bits)" {
    try testing.expect(!tf.Builder.wideKeyDirect(30, 16)); // <= 16 bits: plain key, not this rule
    try testing.expect(tf.Builder.wideKeyDirect(19, 17));
    try testing.expect(!tf.Builder.wideKeyDirect(18, 17)); // table > 1/4 of the keys: limbs
    try testing.expect(tf.Builder.wideKeyDirect(22, 20));
    try testing.expect(!tf.Builder.wideKeyDirect(30, 21)); // above MAX_TABLE_BITS: limbs
    // dense ledger layer (T 1024, D 2048): slack n = 21, bits = 19
    try testing.expect(tf.Builder.wideKeyDirect(21, 19));
    // RMSNorm isqrt slacks (n = lt, bits >= 17) keep limbs at every T <= 2^18
    try testing.expect(!tf.Builder.wideKeyDirect(10, 17));
}

const winfo = [_]TensorInfo{TensorInfo.mat(2, 2)};

const Syn = struct {
    pool: f.Pool,
    ws: proto.WeightStore,
    b: tf.Builder,
    pc: proto.Config,
    a_id: u32,
    b_id: u32,
};

/// a, b in [0, 2^16) (range keys); rangeWide(n, 3a - b, 17). Honest a = b.
fn buildSyn(al: std.mem.Allocator, s: *Syn, n: u32) !void {
    try s.pool.init(al, 2);
    s.pc = .{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .weight_log_cols = 2, .witness_log_cols_max = 8, .gkr_threads = 2 };
    var dummy: [16]i8 = [_]i8{0} ** 16;
    const dv = [_][]const i8{&dummy};
    s.ws = try proto.commitWeights(al, &s.pool, s.pc, &winfo, &dv);
    s.b = tf.Builder.init(al, &s.pool);
    const b = &s.b;
    try b.weight_infos.append(al, TensorInfo.mat(2, 2));
    const N = @as(usize, 1) << @intCast(n);
    const av = try al.alloc(i32, N);
    for (av, 0..) |*x, i| x.* = @intCast(i % 30000 + 1);
    s.a_id = try b.add(TensorInfo.vec(n), av);
    s.b_id = try b.add(TensorInfo.vec(n), try al.dupe(i32, av));
    try b.key(n, try b.expr(&.{term(1, Ref.w(s.a_id), &.{ids(0, n)})}, 0), null, .{ .range = 16 });
    try b.key(n, try b.expr(&.{term(1, Ref.w(s.b_id), &.{ids(0, n)})}, 0), null, .{ .range = 16 });
    try b.rangeWide(n, try b.expr(&.{ term(3, Ref.w(s.a_id), &.{ids(0, n)}), term(-1, Ref.w(s.b_id), &.{ids(0, n)}) }, 0), 17);
}

fn deinitSyn(al: std.mem.Allocator, s: *Syn) void {
    s.b.deinit();
    s.ws.deinit(al);
    s.pool.deinit();
}

fn proveVerifyParts(al: std.mem.Allocator, pool: *f.Pool, pc: proto.Config, b: *const tf.Builder, ws: *const proto.WeightStore) !void {
    const st = b.statement();
    const wv = try b.witnessView(al);
    defer al.free(wv);
    var tm: proto.Timings = .{};
    var proof = try proto.prove(al, pool, pc, st, ws, wv, &tm);
    defer proof.deinit(al);
    try proto.verify(al, pc, st, proto.weightKey(ws), &proof);
}

fn proveVerifyUnchecked(al: std.mem.Allocator, pool: *f.Pool, pc: proto.Config, b: *const tf.Builder, ws: *const proto.WeightStore) !void {
    xt.test_unchecked_prover = true;
    defer xt.test_unchecked_prover = false;
    try proveVerifyParts(al, pool, pc, b, ws);
}

fn countKeys(st: proto.Statement, bits: u5) usize {
    var c: usize = 0;
    for (st.ext.ops) |op| if (op == .key and op.key.table == .range and op.key.table.range == bits) {
        c += 1;
    };
    return c;
}

fn countLineqs(st: proto.Statement) usize {
    var c: usize = 0;
    for (st.ext.ops) |op| c += @intFromBool(op == .lineq);
    return c;
}

test "wide slack key: one virtual key at n >= bits + 2, limbs below; out-of-range expression rejected" {
    const al = testing.allocator;
    // limb path below the threshold (n = 18 < 17 + 2): 2 limbs + lineq
    {
        var s: Syn = undefined;
        try buildSyn(al, &s, 18);
        defer deinitSyn(al, &s);
        const st = s.b.statement();
        try testing.expectEqual(@as(usize, 4), st.witness.len);
        try testing.expectEqual(@as(usize, 1), countLineqs(st));
        try testing.expectEqual(@as(usize, 0), countKeys(st, 17));
        try proto.validateStatement(st);
    }
    var s: Syn = undefined;
    try buildSyn(al, &s, 19);
    defer deinitSyn(al, &s);
    const st = s.b.statement();
    // nothing committed beyond a, b; no lineq; one range(17) key
    try testing.expectEqual(@as(usize, 2), st.witness.len);
    try testing.expectEqual(@as(usize, 0), countLineqs(st));
    try testing.expectEqual(@as(usize, 1), countKeys(st, 17));
    try proto.validateStatement(st);
    try proveVerifyParts(al, &s.pool, s.pc, &s.b, &s.ws); // completeness
    const A = s.b.wit.items[s.a_id];
    const B = s.b.wit.items[s.b_id];
    // 3a - b = -1 (a = 0, b = 1) and 3a - b = 2^17 (a = 43691, b = 1); a, b stay in range
    for ([_][2]i32{ .{ 0, 1 }, .{ 43691, 1 } }) |ab| {
        const sv = .{ A[5], B[5] };
        A[5] = ab[0];
        B[5] = ab[1];
        if (proveVerifyUnchecked(al, &s.pool, s.pc, &s.b, &s.ws)) |_| {
            std.debug.print("[wide slack] VERIFIER ACCEPTED 3a - b = {d}\n", .{3 * ab[0] - ab[1]});
            return error.CheatAccepted;
        } else |_| {}
        A[5] = sv[0];
        B[5] = sv[1];
    }
    try proveVerifyParts(al, &s.pool, s.pc, &s.b, &s.ws); // restored witness verifies
}

test "wide slack key: honest prover refuses an out-of-range expression" {
    const al = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(al, 2);
    defer pool.deinit();
    var b = tf.Builder.init(al, &pool);
    defer b.deinit();
    const n: u32 = 19;
    const av = try al.alloc(i32, @as(usize, 1) << n);
    @memset(av, 0);
    av[7] = 1 << 17;
    const x = try b.add(TensorInfo.vec(n), av);
    try testing.expectError(error.ValueOutOfRange, b.rangeWide(n, try b.expr(&.{term(1, Ref.w(x), &.{ids(0, n)})}, 0), 17));
    av[7] = -1;
    try testing.expectError(error.ValueOutOfRange, b.rangeWide(n, try b.expr(&.{term(1, Ref.w(x), &.{ids(0, n)})}, 0), 17));
}

// Attention core at T = 256 with one 2048-wide head: the division slacks are
// lt + 9 = 17 bits over n = 19 bits, so both become virtual range(17) keys.
// EXT-1's attack (inflate o on the last row, recompute od = o den in the
// field) no longer has limbs to recompute: the virtual slack 2 acc + den -
// 2 od is out of [0, 2^17) for every o but the honest one.
test "wide slack key: attention division slack is one range(lt + 9) key; inflated outputs rejected" {
    const al = testing.allocator;
    const lt: u32 = 8;
    const ld: u32 = 11;
    var att: rf.Att = undefined;
    try rf.buildAttD(al, &att, lt, ld, &rf.vFirst);
    defer rf.deinitAtt(al, &att);
    const st = att.b.statement();
    try proto.validateStatement(st);
    for (att.b.labels.items) |l| try testing.expect(!std.mem.eql(u8, l.name, "range.limb") and !std.mem.startsWith(u8, l.name, "div.slack"));
    try testing.expectEqual(@as(usize, 2), countKeys(st, @intCast(lt + 9)));
    try rf.proveVerify(al, &att);

    const b = &att.b;
    const at = att.at;
    const T = @as(usize, 1) << @intCast(lt);
    const Dh = @as(usize, 1) << @intCast(ld);
    const i = (T - 1) * Dh;
    const den: i64 = b.wit.items[at.den][T - 1];
    try testing.expectEqual(@as(i64, 256 * 256), den);
    try testing.expectEqual(@as(i32, 0), b.wit.items[at.o][i]);
    for ([_]i32{ 1, 64, 127, -1 }) |o_c| {
        const sv = .{ b.wit.items[at.o][i], b.wit.items[at.od][i] };
        b.wit.items[at.o][i] = o_c;
        b.wit.items[at.od][i] = @intCast(@mod(@as(i64, o_c) * den, P_M31));
        if (proveVerifyUnchecked(al, &att.pool, att.pc, &att.b, &att.ws)) |_| {
            std.debug.print("[wide slack] VERIFIER ACCEPTED o = {d} (honest 0)\n", .{o_c});
            return error.CheatAccepted;
        } else |_| {}
        b.wit.items[at.o][i] = sv[0];
        b.wit.items[at.od][i] = sv[1];
    }
    try rf.proveVerify(al, &att);
}
