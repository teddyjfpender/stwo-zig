//! Regression tests for adversarial review phase B, serving findings
//! SERVE-1..3 (serve.zig). Copied from the reviewers' tests
//! (revb-serve/src/tensor/review_serve_test.zig), which asserted the
//! defective behaviour; here each asserts the fixed behaviour.
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const model = @import("model.zig");
const serve = @import("serve.zig");

const QM31 = f.QM31;
const testing = std.testing;

fn tlConfig() proto.Config {
    return .{
        .two_level = .{
            .outer = .{ .log_blowup = 2, .n_queries = 16, .pow_bits = 2 },
            .inner = .{ .log_blowup = 3, .n_queries = 12, .pow_bits = 1 },
            .depth = 1,
        },
        .gkr_threads = 2,
        .batch_matmuls = true,
    };
}

const MCFG = model.Mlp{ .log_t = 3, .log_d = 5, .log_f = 6 };

const Fx = struct {
    pool: f.Pool,
    ws: proto.WeightStore,
    wdata: [3][]i8,
    winfos: [3]proto.TensorInfo,

    fn init(fx: *Fx, a: std.mem.Allocator, pc: *proto.Config) !void {
        try fx.pool.init(a, 2);
        fx.winfos = model.mlpWeightInfos(MCFG);
        pc.weight_log_cols = try proto.chooseWeightLogCols(pc.*, a, &fx.winfos, 2);
        for (&fx.wdata, 0..) |*w, i| w.* = try model.randomWeights(a, fx.winfos[i].size(), 100 + i, -8, 7);
        const wv = [_][]const i8{ fx.wdata[0], fx.wdata[1], fx.wdata[2] };
        fx.ws = try proto.commitWeights(a, &fx.pool, pc.*, &fx.winfos, &wv);
    }

    fn deinit(fx: *Fx, a: std.mem.Allocator) void {
        fx.ws.deinit(a);
        for (fx.wdata) |w| a.free(w);
        fx.pool.deinit();
    }
};

const Req = struct {
    built: model.Built,
    view: []const []const i32,

    fn init(a: std.mem.Allocator, fx: *Fx, seed: u64) !Req {
        const x = try model.randomInput(a, @as(usize, 1) << (MCFG.log_t + MCFG.log_d), seed);
        defer a.free(x);
        var b = try model.buildMlp(a, &fx.pool, &fx.ws, MCFG, x);
        errdefer b.deinit(a);
        const v = try a.alloc([]const i32, b.witness.len);
        for (b.witness, 0..) |w, i| v[i] = w;
        return .{ .built = b, .view = v };
    }

    fn deinit(r: *Req, a: std.mem.Allocator) void {
        r.built.deinit(a);
        a.free(r.view);
    }

    fn request(r: *const Req, salt: ?[32]u8) serve.Request {
        return .{ .st = r.built.statement(), .witness = r.view, .acc = r.built.accs, .salt = salt };
    }
};

/// Appends an unreferenced point (any length, any values) to a slot.
fn expectReject(r: anyerror!void) !void {
    if (r) |_| return error.TamperAccepted else |_| {}
}

/// Allocator wrapper recording the peak live bytes.
const Counting = struct {
    child: std.mem.Allocator,
    live: usize = 0,
    peak: usize = 0,

    fn allocator(self: *Counting) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, n: usize, al: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        const p = self.child.rawAlloc(n, al, ra) orelse return null;
        self.live += n;
        self.peak = @max(self.peak, self.live);
        return p;
    }
    fn resize(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ra: usize) bool {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        if (!self.child.rawResize(m, al, n, ra)) return false;
        self.live = self.live - m.len + n;
        self.peak = @max(self.peak, self.live);
        return true;
    }
    fn remap(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        const p = self.child.rawRemap(m, al, n, ra) orelse return null;
        self.live = self.live - m.len + n;
        self.peak = @max(self.peak, self.live);
        return p;
    }
    fn free(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, ra: usize) void {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        self.child.rawFree(m, al, ra);
        self.live -= m.len;
    }
};

fn appendJunkPoint(a: std.mem.Allocator, cs: *serve.ClaimSet, len: usize) !void {
    const np = try a.alloc([]QM31, cs.points.len + 1);
    @memcpy(np[0..cs.points.len], cs.points);
    const junk = try a.alloc(QM31, len);
    for (junk, 0..) |*v, i| v.* = QM31.fromBase(f.M31.fromCanonical(@intCast(1234 + i)));
    np[cs.points.len] = junk;
    a.free(cs.points);
    cs.points = np;
}

// REVIEW-SERVE-1: a slot is not canonical. Verifier i checks slot i's claims
// (count, full points, values) but never that `points` holds only referenced
// points, nor the length of an unreferenced point. Any party (the server)
// can pad slot i itself with arbitrary data that is absorbed into the batch
// transcript: a free, cheap grinding knob inside the victim's own slot, and
// many distinct shared openings accepted for the same request proof.
// SERVE-1 regression: slots are canonical (every point referenced, distinct,
// first-use order) and verifier i compares its own slot byte for byte with
// the one it rebuilds. A junk point in any slot is rejected by every verifier.
test "review serve: unreferenced junk point in the verifier's OWN slot is rejected" {
    const a = testing.allocator;
    var pc = tlConfig();
    var fx: Fx = undefined;
    try fx.init(a, &pc);
    defer fx.deinit(a);
    const key = proto.weightKey(&fx.ws);
    var r0 = try Req.init(a, &fx, 9);
    defer r0.deinit(a);
    var r1 = try Req.init(a, &fx, 10);
    defer r1.deinit(a);
    const q0 = r0.request(serve.testSalt(0));
    const q1 = r1.request(serve.testSalt(1));
    // mode 0: honest; 1: junk in slot 0 (the victim's own slot) with a length
    // that matches no weight (the reviewer's case); 2: junk of a valid weight
    // length in slot 1 only (another client's slot); 3: slot 1's points
    // reordered (not first-use order). The server pads BEFORE finish, so the
    // shared opening is consistent with the padded transcript.
    for (0..4) |mode| {
        var bp = serve.BatchProver.init(a, &fx.pool, pc, &fx.ws);
        defer bp.deinit();
        var tm: proto.Timings = .{};
        try bp.add(q0, &tm);
        try bp.add(q1, &tm);
        switch (mode) {
            1 => {
                try appendJunkPoint(a, &bp.sets.items[0], 3);
                try appendJunkPoint(a, &bp.sets.items[1], 1);
            },
            2 => try appendJunkPoint(a, &bp.sets.items[1], bp.sets.items[1].points[0].len),
            3 => {
                const s = &bp.sets.items[1];
                try testing.expect(s.points.len >= 2);
                std.mem.swap([]QM31, &s.points[0], &s.points[1]);
                for (s.point_of) |*pi| {
                    if (pi.* == 0) pi.* = 1 else if (pi.* == 1) pi.* = 0;
                }
            },
            else => {},
        }
        var batch = try bp.finish();
        defer batch.deinit(a);
        try testing.expectEqual(@as(usize, 2), batch.shared.requests.len);
        const v0 = serve.verifyRequest(a, pc, q0.st, key, &batch.requests[0], &batch.shared, 0);
        const v1 = serve.verifyRequest(a, pc, q1.st, key, &batch.requests[1], &batch.shared, 1);
        if (mode == 0) {
            try v0;
            try v1;
        } else {
            try expectReject(v0);
            try expectReject(v1);
        }
    }
}

// REVIEW-SERVE-2: the leakage argument of serving.md 1.1 ("points and digests
// depend on the other request's salt, so they are pseudo-random to this
// client") needs a secret uniform salt, but the API takes a caller-chosen
// salt and the only salt source in the tree (bench `tensor-bench model`) is
// `testSalt(seed*1000+j)`, a public function of the index. With a known salt
// the slot digest is a deterministic function of the request's prompt: a
// client confirms a guess of another client's prompt from its slot.
// SERVE-2 regression: the default salt (Request.salt = null) is drawn from
// std.crypto.random by BatchProver.add; a client can no longer confirm a
// guess of another client's prompt by replaying its slot with the salt the
// old harness used (testSalt(index)), nor with any public salt.
test "review serve: with default secret salts, a client cannot confirm another client's prompt from its slot digest" {
    const a = testing.allocator;
    var pc = tlConfig();
    var fx: Fx = undefined;
    try fx.init(a, &pc);
    defer fx.deinit(a);
    var r0 = try Req.init(a, &fx, 9);
    defer r0.deinit(a);
    var r1 = try Req.init(a, &fx, 10); // the victim's secret prompt (seed 10)
    defer r1.deinit(a);
    const reqs = [_]serve.Request{ r0.request(null), r1.request(null) };
    var batch = try serve.proveRequests(a, &fx.pool, pc, &fx.ws, &reqs, null);
    defer batch.deinit(a);
    const seen = batch.shared.requests[1].digest; // what client 0 downloads
    // salts are fresh per request (distinct, not the test salts)
    try testing.expect(!std.mem.eql(u8, &batch.requests[0].salt, &batch.requests[1].salt));
    try testing.expect(!std.mem.eql(u8, &batch.requests[1].salt, &serve.testSalt(1)));

    // client 0 tries two candidate prompts for request 1
    for ([_]u64{ 10, 11 }) |guess| {
        var g = try Req.init(a, &fx, guess);
        defer g.deinit(a);
        var bp = serve.BatchProver.init(a, &fx.pool, pc, &fx.ws);
        defer bp.deinit();
        var tm: proto.Timings = .{};
        try bp.add(g.request(serve.testSalt(1)), &tm);
        const match = std.mem.eql(u8, &bp.sets.items[0].digest, &seen);
        try testing.expect(!match);
    }
}

// REVIEW-SERVE-3 (completeness coupling / DoS, by design but undocumented as
// such): one malformed or false slot of ANOTHER request makes every honest
// request of the batch fail. An honest client cannot distinguish "my request
// was false" from "some other slot was bad".
// SERVE-3 regression. By design (serving.md 1.1, "availability coupling"),
// a TRUE fabricated slot is still accepted: R and batch membership are not
// attested, and one false slot fails every verifier. What is fixed: a slot
// with more claims than the cap (max_claims_per_weight * |weights|), or more
// points than claims, is rejected before the verifier allocates per claim.
test "review serve: an extra fabricated slot appended by the server is accepted by verifier 0 when it is true; oversized slots rejected" {
    const a = testing.allocator;
    var pc = tlConfig();
    var fx: Fx = undefined;
    try fx.init(a, &pc);
    defer fx.deinit(a);
    const key = proto.weightKey(&fx.ws);
    var r0 = try Req.init(a, &fx, 9);
    defer r0.deinit(a);
    var r1 = try Req.init(a, &fx, 10);
    defer r1.deinit(a);
    const q0 = r0.request(serve.testSalt(0));
    var bp = serve.BatchProver.init(a, &fx.pool, pc, &fx.ws);
    defer bp.deinit();
    var tm: proto.Timings = .{};
    try bp.add(q0, &tm);
    // the server adds a second request (no client behind it, arbitrary
    // digest): verifier 0 learns nothing about R or about who is in the batch
    try bp.add(r1.request(serve.testSalt(77)), &tm);
    bp.sets.items[1].digest = [_]u8{0xAB} ** 32;
    var batch = try bp.finish();
    defer batch.deinit(a);
    try serve.verifyRequest(a, pc, q0.st, key, &batch.requests[0], &batch.shared, 0);
    // an oversized, otherwise well-formed slot 1 (2^18 claims on weight 0 at
    // its first point): rejected before the verifier allocates per claim
    // (peak verifier allocation stays far below the slot's 2^18 * 24 bytes)
    {
        const s = &batch.shared.requests[1];
        const cap = serve.max_claims_per_weight * key.infos.len;
        try testing.expect(s.w.len <= cap); // the honest slot is under the cap
        const n_big: usize = 1 << 18;
        try testing.expect(n_big > cap);
        const saved = .{ s.w, s.point_of, s.values };
        const bw = try a.alloc(u32, n_big);
        defer a.free(bw);
        const bp_ = try a.alloc(u32, n_big);
        defer a.free(bp_);
        const bv = try a.alloc(QM31, n_big);
        defer a.free(bv);
        @memset(bw, saved[0][0]);
        @memset(bp_, 0);
        @memset(bv, QM31.zero());
        s.w = bw;
        s.point_of = bp_;
        s.values = bv;
        var ca = Counting{ .child = a };
        try expectReject(serve.verifyRequest(ca.allocator(), pc, q0.st, key, &batch.requests[0], &batch.shared, 0));
        try testing.expect(ca.peak < n_big * 8);
        s.w = saved[0];
        s.point_of = saved[1];
        s.values = saved[2];
    }
    try serve.verifyRequest(a, pc, q0.st, key, &batch.requests[0], &batch.shared, 0);
}
