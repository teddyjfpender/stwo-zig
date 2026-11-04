//! Independent adversarial checks of the wide slack key (ledger.md section 6).
//! Unlike the "reject" loops in wide_slack_test.zig, every cheat here must be
//! produced by the (unchecked) prover WITHOUT error and then rejected by the
//! verifier, so a rejection cannot come from a prover-side check.
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

const winfo = [_]TensorInfo{TensorInfo.mat(2, 2)};

fn vVar(j: usize) i32 {
    return @as(i32, @intCast(j % 97)) - 40;
}

const Outcome = enum { accepted, verifier_rejected };

/// Prove `prove_st` (unchecked when `cheat`), verify against `verify_st`.
/// A prover error fails the test: it would mask what the verifier does.
fn run(al: std.mem.Allocator, pool: *f.Pool, pc: proto.Config, prove_st: proto.Statement, verify_st: proto.Statement, b: *const tf.Builder, ws: *const proto.WeightStore, cheat: bool) !Outcome {
    xt.test_unchecked_prover = cheat;
    defer xt.test_unchecked_prover = false;
    const wv = try b.witnessView(al);
    defer al.free(wv);
    var tm: proto.Timings = .{};
    var proof = proto.prove(al, pool, pc, prove_st, ws, wv, &tm) catch |e| {
        std.debug.print("[wide slack adv] prover failed: {s}\n", .{@errorName(e)});
        return error.ProverFailed;
    };
    defer proof.deinit(al);
    proto.verify(al, pc, verify_st, proto.weightKey(ws), &proof) catch return .verifier_rejected;
    return .accepted;
}

const Syn = struct { pool: f.Pool, ws: proto.WeightStore, b: tf.Builder, pc: proto.Config, a_id: u32, b_id: u32 };

/// a, b in [0, 2^16) by range keys; rangeWide(19, 3a - b, 17) is the virtual key.
fn buildSyn(al: std.mem.Allocator, s: *Syn) !void {
    const n: u32 = 19;
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

test "wide slack adv: edges accepted, every out-of-range value rejected by the verifier" {
    const al = testing.allocator;
    var s: Syn = undefined;
    try buildSyn(al, &s);
    defer deinitSyn(al, &s);
    const st = s.b.statement();
    try proto.validateStatement(st);
    const A = s.b.wit.items[s.a_id];
    const B = s.b.wit.items[s.b_id];
    // completeness at the edges 0 and 2^17 - 1 (honest prover, checked)
    for ([_][2]i32{ .{ 0, 0 }, .{ 43691, 2 } }) |ab| {
        A[9] = ab[0];
        B[9] = ab[1];
        try testing.expectEqual(Outcome.accepted, try run(al, &s.pool, s.pc, st, st, &s.b, &s.ws, false));
    }
    // soundness: -1, -2^16 + 1, 2^17, 2^17 + 1, max 3(2^16-1) (all with a, b in range)
    for ([_][2]i32{ .{ 0, 1 }, .{ 0, 65535 }, .{ 43691, 1 }, .{ 43691, 0 }, .{ 65535, 0 } }) |ab| {
        A[9] = ab[0];
        B[9] = ab[1];
        const o = try run(al, &s.pool, s.pc, st, st, &s.b, &s.ws, true);
        if (o != .verifier_rejected) std.debug.print("[wide slack adv] ACCEPTED 3a-b = {d}\n", .{3 * ab[0] - ab[1]});
        try testing.expectEqual(Outcome.verifier_rejected, o);
    }
}

/// Copy of `st` with every range(from) key retargeted to range(to).
fn retarget(ar: std.mem.Allocator, st: proto.Statement, from: u5, to: u5) !proto.Statement {
    const ops = try ar.dupe(xt.Op, st.ext.ops);
    var hit: usize = 0;
    for (ops) |*op| if (op.* == .key and op.key.table == .range and op.key.table.range == from) {
        op.key.table = .{ .range = to };
        hit += 1;
    };
    try testing.expect(hit > 0);
    var out = st;
    out.ext.ops = ops;
    return out;
}

test "wide slack adv: statement edit (looser table) is rejected against the honest statement" {
    const al = testing.allocator;
    var s: Syn = undefined;
    try buildSyn(al, &s);
    defer deinitSyn(al, &s);
    var arena = std.heap.ArenaAllocator.init(al);
    defer arena.deinit();
    const st = s.b.statement();
    const loose = try retarget(arena.allocator(), st, 17, 18);
    try proto.validateStatement(loose);
    const A = s.b.wit.items[s.a_id];
    const B = s.b.wit.items[s.b_id];
    A[9] = 43691;
    B[9] = 0; // 3a - b = 131073 in range(18), not in range(17)
    // the loose statement accepts it on its own ...
    try testing.expectEqual(Outcome.accepted, try run(al, &s.pool, s.pc, loose, loose, &s.b, &s.ws, true));
    // ... but the verifier holds the honest statement
    try testing.expectEqual(Outcome.verifier_rejected, try run(al, &s.pool, s.pc, loose, st, &s.b, &s.ws, true));
}

test "wide slack adv: attention division, off-by-one outputs rejected by the verifier" {
    const al = testing.allocator;
    const lt: u32 = 8;
    const ld: u32 = 11;
    var att: rf.Att = undefined;
    try rf.buildAttD(al, &att, lt, ld, &vVar);
    defer rf.deinitAtt(al, &att);
    const st = att.b.statement();
    try proto.validateStatement(st);
    try testing.expect(tf.Builder.wideKeyDirect(lt + ld, lt + 9));
    try testing.expectEqual(Outcome.accepted, try run(al, &att.pool, att.pc, st, st, &att.b, &att.ws, false));
    const b = &att.b;
    const at = att.at;
    const Dh = @as(usize, 1) << @intCast(ld);
    // rows 0, 1, 37, 255; o +- 1 with od recomputed: slack_lo or slack_hi leaves [0, 2^17)
    for ([_]usize{ 0, 1, 37, 255 }) |t| for ([_]i32{ 1, -1 }) |dlt| {
        const i = t * Dh + 5;
        const sv = .{ b.wit.items[at.o][i], b.wit.items[at.od][i] };
        const den: i64 = b.wit.items[at.den][t];
        const oc = sv[0] + dlt;
        b.wit.items[at.o][i] = oc;
        b.wit.items[at.od][i] = @intCast(@mod(@as(i64, oc) * den, P_M31));
        const o = try run(al, &att.pool, att.pc, st, st, &att.b, &att.ws, true);
        if (o != .verifier_rejected) std.debug.print("[wide slack adv] ACCEPTED row {d} o {d} -> {d}\n", .{ t, sv[0], oc });
        try testing.expectEqual(Outcome.verifier_rejected, o);
        b.wit.items[at.o][i] = sv[0];
        b.wit.items[at.od][i] = sv[1];
    };
    try testing.expectEqual(Outcome.accepted, try run(al, &att.pool, att.pc, st, st, &att.b, &att.ws, false));
}

/// rangeWide(19, c a - b, 17) with a, b in range(16), built shape-only.
fn wrapStatement(al: std.mem.Allocator, pool: *f.Pool, c: i64) !tf.Builder {
    const n: u32 = 19;
    var b = tf.Builder.init(al, pool);
    errdefer b.deinit();
    b.shape_only = true;
    const av = try al.alloc(i32, @as(usize, 1) << n);
    @memset(av, 0);
    const a_id = try b.add(TensorInfo.vec(n), av);
    const b_id = try b.add(TensorInfo.vec(n), try al.dupe(i32, av));
    try b.key(n, try b.expr(&.{term(1, Ref.w(a_id), &.{ids(0, n)})}, 0), null, .{ .range = 16 });
    try b.key(n, try b.expr(&.{term(1, Ref.w(b_id), &.{ids(0, n)})}, 0), null, .{ .range = 16 });
    try b.rangeWide(n, try b.expr(&.{ term(c, Ref.w(a_id), &.{ids(0, n)}), term(-1, Ref.w(b_id), &.{ids(0, n)}) }, 0), 17);
    return b;
}

// Wrap mod p: a virtual key proves x mod p in [0, 2^bits), which is the
// integer statement only when |x| + 2^bits < p. With a's proved bound 2^16,
// c = 2^15 gives |x| up to 2^31 + 2^16 > p (a wrap the verifier cannot exclude).
// The verifier must refuse such a statement (|x| + 2^bits >= p) and accept
// c = 2^14 - 1, where |x| + 2^bits < p.
test "wide slack adv: virtual key expression that can wrap mod p is refused" {
    const al = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(al, 2);
    defer pool.deinit();
    {
        var b = try wrapStatement(al, &pool, 1 << 15);
        defer b.deinit();
        try testing.expectError(error.StatementAccumulatorBound, proto.validateStatement(b.statement()));
    }
    {
        // bound 32766 * 2^16 + 2^16 = 2^31 - 2^16; + 2^17 > p: refused
        var b = try wrapStatement(al, &pool, (1 << 15) - 2);
        defer b.deinit();
        try testing.expectError(error.StatementAccumulatorBound, proto.validateStatement(b.statement()));
    }
    {
        var b = try wrapStatement(al, &pool, (1 << 14) - 1);
        defer b.deinit();
        try proto.validateStatement(b.statement());
    }
}
