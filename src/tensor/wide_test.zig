//! Wide core-matmul outputs (proto Op.matmul.out_bits, accuracy.md "Wide
//! activations"): range enforcement, statement binding, bounds, wire.
const std = @import("std");
const testing = std.testing;
const f = @import("field.zig");
const proto = @import("protocol.zig");
const tf = @import("transformer.zig");
const bounds = @import("bounds.zig");
const wire = @import("wire.zig");
const TensorInfo = proto.TensorInfo;

fn pc() proto.Config {
    return .{ .two_level = .{ .outer = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 }, .inner = .{ .log_blowup = 3, .n_queries = 10, .pow_bits = 1 }, .depth = 1 }, .gkr_threads = 2, .weight_log_cols = 2 };
}

const Fx = struct {
    pool: f.Pool,
    ws: proto.WeightStore,
    w: [1][]i8,
    infos: [1]TensorInfo,

    fn init(self: *Fx, a: std.mem.Allocator) !void {
        try self.pool.init(a, 2);
        self.w[0] = try a.alloc(i8, 16);
        for (self.w[0], 0..) |*v, i| v.* = @intCast(@as(i32, @intCast(i * 37 % 255)) - 127);
        self.infos = .{TensorInfo.mat(2, 2)};
        const wv = [_][]const i8{self.w[0]};
        self.ws = try proto.commitWeights(a, &self.pool, pc(), &self.infos, &wv);
    }
    fn deinit(self: *Fx, a: std.mem.Allocator) void {
        self.ws.deinit(a);
        a.free(self.w[0]);
        self.pool.deinit();
    }
};

/// X [2, 4] 12-bit, Y = rq_s(X W) with `ob`-bit output.
fn build(a: std.mem.Allocator, fx: *Fx, shift: u5, ob: u5) !tf.Builder {
    var b = tf.Builder.init(a, &fx.pool);
    errdefer b.deinit();
    const x = try a.alloc(i32, 8);
    for (x, 0..) |*v, i| v.* = @as(i32, @intCast(i * 517 % 4096)) - 2048;
    const xid = try b.add(TensorInfo.mat(1, 2), x);
    try b.rangeSigned(xid, 12);
    try b.weight_infos.append(a, fx.ws.infos[0]);
    _ = try b.matmulBits(&fx.ws, xid, 0, shift, ob);
    return b;
}

fn proveVerify(a: std.mem.Allocator, fx: *Fx, b: *tf.Builder, vst: ?proto.Statement) !void {
    const wv = try b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &fx.pool, pc(), b.statement(), &fx.ws, wv, &tm);
    defer proof.deinit(a);
    try proto.verify(a, pc(), vst orelse b.statement(), proto.weightKey(&fx.ws), &proof);
}

test "wide matmul: 12-bit output proves and verifies; a verifier with another out_bits rejects" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a);
    defer fx.deinit(a);
    var b = try build(a, &fx, 8, 12);
    defer b.deinit();
    var mx: i32 = 0;
    for (b.wit.items[1]) |v| mx = @max(mx, @as(i32, @intCast(@abs(v))));
    try testing.expect(mx > 127 and mx < 2048); // really wide, in range
    try proveVerify(a, &fx, &b, null);
    // same ops, out_bits 13 at the verifier: different statement -> reject
    const ops = try a.dupe(proto.Op, b.statement().ops);
    defer a.free(ops);
    ops[0].matmul.out_bits = 13;
    var st = b.statement();
    st.ops = ops;
    try testing.expect(std.meta.isError(proveVerify(a, &fx, &b, st)));
}

test "wide matmul: a Y outside its out_bits range is refused (range key at the wide width)" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a);
    defer fx.deinit(a);
    // shift 4: |rq_4(acc)| exceeds 2^11 (the builder does not check a fixed
    // shift outside replay mode, so the witness reaches the prover)
    var b = try build(a, &fx, 4, 12);
    defer b.deinit();
    var mx: i32 = 0;
    for (b.wit.items[1]) |v| mx = @max(mx, @as(i32, @intCast(@abs(v))));
    try testing.expect(mx >= 2048);
    try testing.expectError(error.ValueOutOfRange, proveVerify(a, &fx, &b, null));
    // the same values are fine under a 16-bit range (shift 4 + 16 <= 30)
    var b16 = try build(a, &fx, 4, 16);
    defer b16.deinit();
    try proveVerify(a, &fx, &b16, null);
}

test "wide matmul bounds: wrapped accumulator, shift + out_bits and out_bits caps rejected" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    // X 12-bit (|X| <= 2^11), K = 2^lk: |acc| <= 2^(11 + 7 + lk) must be <= 2^30
    for ([_]struct { lk: u32, ok: bool }{ .{ .lk = 12, .ok = true }, .{ .lk = 13, .ok = false } }) |c| {
        var b = tf.Builder.init(a, &pool);
        defer b.deinit();
        b.shape_only = true;
        const x = try a.alloc(i32, @as(usize, 2) << @intCast(c.lk));
        @memset(x, 0);
        const xid = try b.add(TensorInfo.mat(1, c.lk), x);
        try b.rangeSigned(xid, 12);
        try b.weight_infos.append(a, TensorInfo.mat(c.lk, 1));
        const y = try a.alloc(i32, 4);
        @memset(y, 0);
        const yid = try b.add(TensorInfo.mat(1, 1), y);
        try b.pushOp(.{ .matmul = .{ .x = xid, .w = 0, .y = yid, .shift = 8, .out_bits = 12 } }, null);
        if (c.ok) try bounds.validateStatement(b.statement()) else try testing.expectError(error.StatementAccumulatorBound, bounds.validateStatement(b.statement()));
    }
    // shift + out_bits > 30, out_bits > 16, out_bits < 8
    for ([_]struct { s: u5, ob: u5, e: anyerror }{ .{ .s = 15, .ob = 16, .e = error.StatementAccumulatorBound }, .{ .s = 4, .ob = 17, .e = error.StatementShape }, .{ .s = 4, .ob = 7, .e = error.StatementShape } }) |c| {
        var b = tf.Builder.init(a, &pool);
        defer b.deinit();
        b.shape_only = true;
        const x = try a.alloc(i32, 8);
        @memset(x, 0);
        const xid = try b.add(TensorInfo.mat(1, 2), x);
        try b.rangeSigned(xid, 8);
        try b.weight_infos.append(a, TensorInfo.mat(2, 1));
        const y = try a.alloc(i32, 2);
        @memset(y, 0);
        const yid = try b.add(TensorInfo.mat(1, 0), y);
        try b.pushOp(.{ .matmul = .{ .x = xid, .w = 0, .y = yid, .shift = c.s, .out_bits = c.ob } }, null);
        try testing.expectError(c.e, bounds.validateStatement(b.statement()));
    }
}

test "wide matmul wire: tag 7 round-trips out_bits; int8 ops keep tag 1" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a);
    defer fx.deinit(a);
    for ([_]u5{ 8, 12 }) |ob| {
        var b = try build(a, &fx, 9, ob);
        defer b.deinit();
        const bytes = try wire.encodeStatement(a, pc(), b.statement());
        defer a.free(bytes);
        var sf = try wire.decodeStatement(a, bytes);
        defer sf.deinit();
        try testing.expectEqual(ob, sf.st.ops[0].matmul.out_bits);
        try testing.expectEqual(@as(u5, 9), sf.st.ops[0].matmul.shift);
    }
}
