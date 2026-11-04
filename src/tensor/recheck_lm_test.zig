//! Independent adversarial re-check of LM-1/2/3 (verifier-built statement).
//! Each attack: a modified statement that the HONEST prover proves (the
//! proof is asserted valid for the prover's statement via
//! serve.verifyRequest), then lm.verifyRequest(prompt, claim) must reject.
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const xt = @import("ext.zig");
const tf = @import("transformer.zig");
const lm = @import("lm.zig");
const serve = @import("serve.zig");

const TensorInfo = proto.TensorInfo;
const Ref = xt.Ref;
const ids = tf.ids;
const sums = tf.sums;
const term = tf.term;
const testing = std.testing;

const CFG = lm.ModelCfg{ .log_t = 3, .log_d = 4, .log_heads = 1, .log_kv_heads = 0, .log_f = 5, .n_layers = 1, .log_vocab = 4, .log_out = 1, .weight_log_cols = 3 };

fn testPc(cfg: lm.ModelCfg) proto.Config {
    return .{
        .two_level = .{
            .outer = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 },
            .inner = .{ .log_blowup = 3, .n_queries = 10, .pow_bits = 1 },
            .depth = 1,
        },
        .gkr_threads = 2,
        .batch_matmuls = true,
        .weight_log_cols = cfg.weight_log_cols,
    };
}

const Fx = struct {
    pool: f.Pool,
    sw: tf.WeightSetup,
    desc: lm.ModelDesc,
    pc: proto.Config,
    cfg: lm.ModelCfg,

    fn init(fx: *Fx, a: std.mem.Allocator, cfg: lm.ModelCfg) !void {
        try fx.pool.init(a, 2);
        fx.cfg = cfg;
        fx.pc = testPc(cfg);
        fx.sw = try lm.setupWeights(a, &fx.pool, cfg, fx.pc, 700);
        fx.desc = try lm.testDesc(a, &fx.pool, cfg, &fx.sw.ws, 3);
    }

    fn deinit(fx: *Fx, a: std.mem.Allocator) void {
        fx.desc.deinit(a);
        fx.sw.ws.deinit(a);
        for (fx.sw.wdata) |w| a.free(w);
        a.free(fx.sw.wdata);
        a.free(fx.sw.winfos);
        fx.pool.deinit();
    }

    fn key(fx: *const Fx) proto.WeightKey {
        return proto.weightKey(&fx.sw.ws);
    }
};

/// Proves b's statement honestly; asserts it verifies against b's statement;
/// returns whether lm.verifyRequest(req) ACCEPTS (true = attack works).
fn attack(a: std.mem.Allocator, fx: *Fx, b: *tf.Builder, req: lm.Request) !bool {
    const wv = try b.witnessView(a);
    defer a.free(wv);
    const reqs = [_]serve.Request{.{ .st = b.statement(), .witness = wv }};
    var batch = try serve.proveRequests(a, &fx.pool, fx.pc, &fx.sw.ws, &reqs, null);
    defer batch.deinit(a);
    try serve.verifyRequest(a, fx.pc, reqs[0].st, fx.key(), &batch.requests[0], &batch.shared, 0);
    lm.verifyRequest(a, &fx.pool, fx.pc, fx.key(), &fx.desc, req, &batch.requests[0], &batch.shared, 0) catch |e| {
        std.debug.print("  rejected: {s}\n", .{@errorName(e)});
        return false;
    };
    return true;
}

fn termOf(e: xt.Expr, r: Ref) ?usize {
    for (e.terms, 0..) |t, k| if (t.t.public == r.public and t.t.id == r.id) return k;
    return null;
}

fn onehot2(a: std.mem.Allocator, window: []const u32, V: usize) ![]i32 {
    const oh = try a.alloc(i32, window.len * V);
    @memset(oh, 0);
    for (window, 0..) |t, i| oh[i * V + t] = 2;
    return oh;
}

/// p1 differing from rq.prompt in token 0 with a different honest decode.
fn otherPrompt(a: std.mem.Allocator, fx: *Fx, rq: *const lm.TestRequest) ![]u32 {
    const V = @as(usize, 1) << @intCast(fx.cfg.log_vocab);
    const p1 = try a.dupe(u32, rq.prompt);
    for (1..V) |dv| {
        p1[0] = @intCast((rq.prompt[0] + dv) % V);
        const y1 = lm.decodeGreedy(a, &fx.pool, &fx.desc, &fx.sw.ws, p1) catch continue;
        defer a.free(y1);
        if (!std.mem.eql(u32, y1, rq.y)) return p1;
    }
    a.free(p1);
    return error.NoCandidate;
}

// ---------------------------------------------------------------------------
// LM-1

// A1 (alter labels): the OH-pin lineq's vocab labels turned into SUM labels,
// so it only says each row of OH sums to 2 (both sides). OH public = the
// verifier's one-hot of (p1 || y2[..]); OH witness = p2's one-hot.
test "recheck LM-1 A1: OH-pin lineq weakened by SUM labels" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a, CFG);
    defer fx.deinit(a);
    const V = @as(usize, 1) << CFG.log_vocab;
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 44);
    defer rq.deinit(a);
    const p1 = try otherPrompt(a, &fx, &rq);
    defer a.free(p1);
    const win1 = try lm.requestWindow(a, CFG, p1, rq.y);
    defer a.free(win1);
    const oh1 = try onehot2(a, win1, V);
    defer a.free(oh1);
    rq.b.publics.items[rq.mo.oh_pub].values = try rq.b.arena.allocator().dupe(i32, oh1);
    var n_pin: usize = 0;
    for (rq.b.xops.items) |*op| if (op.* == .lineq and termOf(op.lineq.expr, Ref.p(rq.mo.oh_pub)) != null) {
        op.lineq = .{ .n = @intCast(CFG.log_t), .expr = try rq.b.expr(&.{
            term(1, Ref.w(rq.mo.oh), &.{ ids(0, CFG.log_t), sums(CFG.log_vocab) }),
            term(-1, Ref.p(rq.mo.oh_pub), &.{ ids(0, CFG.log_t), sums(CFG.log_vocab) }),
        }, 0) };
        n_pin += 1;
    };
    try testing.expectEqual(@as(usize, 1), n_pin);
    try testing.expect(!try attack(a, &fx, &rq.b, .{ .prompt = p1, .y = rq.y }));
}

// A2 (extra witness tensor + redirected core op): OH witness = OH public =
// one-hot(p1 window) (the pin lineq holds), a NEW range-checked witness OH2
// = one-hot(p2 window), and the embedding matmul's input redirected to OH2.
test "recheck LM-1 A2: embedding matmul reads an extra witness one-hot" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a, CFG);
    defer fx.deinit(a);
    const V = @as(usize, 1) << CFG.log_vocab;
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 44);
    defer rq.deinit(a);
    const p1 = try otherPrompt(a, &fx, &rq);
    defer a.free(p1);
    const win1 = try lm.requestWindow(a, CFG, p1, rq.y);
    defer a.free(win1);
    const oh1 = try onehot2(a, win1, V);
    defer a.free(oh1);
    const n_oh = CFG.log_t + CFG.log_vocab;
    const oh2 = try rq.b.add(TensorInfo.mat(CFG.log_t, CFG.log_vocab), try a.dupe(i32, rq.b.wit.items[rq.mo.oh]));
    try rq.b.key(n_oh, try rq.b.expr(&.{term(1, Ref.w(oh2), &.{ids(0, n_oh)})}, 0), null, .{ .range = 2 });
    @memcpy(rq.b.wit.items[rq.mo.oh], oh1);
    rq.b.publics.items[rq.mo.oh_pub].values = try rq.b.arena.allocator().dupe(i32, oh1);
    var n_mm: usize = 0;
    for (rq.b.ops.items) |*op| if (op.* == .matmul and op.matmul.x == rq.mo.oh) {
        op.matmul.x = oh2;
        n_mm += 1;
    };
    try testing.expectEqual(@as(usize, 1), n_mm);
    try testing.expect(!try attack(a, &fx, &rq.b, .{ .prompt = p1, .y = rq.y }));
}

// A3 (reorder ops): the honest statement for (p, y) with the OH-pin lineq
// moved to the end of the ext ops (an equivalent relation). Not a false
// claim; checks that op order is bound (the verifier uses its own order).
test "recheck LM-1 A3: ext ops reordered (equivalent statement)" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a, CFG);
    defer fx.deinit(a);
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 41);
    defer rq.deinit(a);
    var pin: ?usize = null;
    for (rq.b.xops.items, 0..) |op, i| if (op == .lineq and termOf(op.lineq.expr, Ref.p(rq.mo.oh_pub)) != null) {
        pin = i;
    };
    const op = rq.b.xops.orderedRemove(pin.?);
    const acc = rq.b.ext_accs.orderedRemove(pin.?);
    try rq.b.xops.append(a, op);
    try rq.b.ext_accs.append(a, acc);
    const accepted = try attack(a, &fx, &rq.b, .{ .prompt = rq.prompt, .y = rq.y });
    std.debug.print("  A3 reorder accepted={}\n", .{accepted});
    try testing.expect(!accepted);
}

// A4 (another log_capacity, MoE): proved at the prover's own capacity; the
// client's request names the descriptor's capacity -> rejected; at the
// prover's capacity it verifies (capacity does not change the semantics:
// every token is dispatched, sum_c Disp = Sel); an out-of-range capacity
// is BadConfig (no verifier blow-up).
test "recheck LM-1 A4: proof at another log_capacity" {
    const a = testing.allocator;
    const MCFG = lm.ModelCfg{ .log_t = 3, .log_d = 4, .log_heads = 1, .log_kv_heads = 0, .log_f = 5, .n_layers = 1, .moe_every = 1, .log_experts = 1, .log_f_expert = 4, .log_capacity = 3, .log_vocab = 4, .log_out = 1, .weight_log_cols = 3 };
    var fx: Fx = undefined;
    try fx.init(a, MCFG);
    defer fx.deinit(a);
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 51);
    defer rq.deinit(a);
    // the same request at capacity 2^2 per expert, if the loads fit
    var d2 = fx.desc;
    d2.cfg.log_capacity = 2;
    const w = try lm.requestWindow(a, MCFG, rq.prompt, rq.y);
    defer a.free(w);
    var b = tf.Builder.init(a, &fx.pool);
    defer b.deinit();
    var built = true;
    _ = lm.buildModel(&b, &d2, &fx.sw.ws, w, rq.y) catch |e| {
        std.debug.print("  A4 cap=2 refused by prover: {s}\n", .{@errorName(e)});
        built = false;
    };
    if (built) {
        try testing.expect(!try attack(a, &fx, &b, .{ .prompt = rq.prompt, .y = rq.y }));
        try testing.expect(try attack(a, &fx, &b, .{ .prompt = rq.prompt, .y = rq.y, .log_capacity = 2 }));
    }
    // honest at default capacity verifies; at log_t + 1 -> BadConfig
    try testing.expect(try attack(a, &fx, &rq.b, .{ .prompt = rq.prompt, .y = rq.y }));
    var vb = lm.requestStatement(a, &fx.pool, &fx.desc, .{ .prompt = rq.prompt, .y = rq.y, .log_capacity = MCFG.log_t + 1 });
    if (vb) |*v| v.deinit() else |e| try testing.expectEqual(error.BadConfig, e);
    try testing.expect(std.meta.isError(vb));
}

// ---------------------------------------------------------------------------
// LM-2

fn lastRow(b: *tf.Builder, id: u32, V: usize) []i32 {
    const v = b.wit.items[id];
    return v[v.len - V ..];
}

fn setGreedyPublics(b: *tf.Builder, g: lm.GreedyOut, y: []const u32, V: usize) !void {
    const ar = b.arena.allocator();
    const sel = try ar.alloc(i32, y.len * V);
    const ltv = try ar.alloc(i32, y.len * V);
    for (y, 0..) |tok, t| for (0..V) |v| {
        sel[t * V + v] = @intFromBool(v == tok);
        ltv[t * V + v] = @intFromBool(v < tok);
    };
    b.publics.items[g.sel].values = sel;
    b.publics.items[g.lt].values = ltv;
}

// B1 (extra witness tensor): fake int8 logits Lf (range-checked) whose last
// row has yf as least maximiser; the greedy lineq's logits term redirected
// to Lf; m, Dr recomputed; Sel/Lt publics are the verifier's for yf.
test "recheck LM-2 B1: greedy check reads fake witness logits" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a, CFG);
    defer fx.deinit(a);
    const V = @as(usize, 1) << CFG.log_vocab;
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 45);
    defer rq.deinit(a);
    const yf = try a.dupe(u32, rq.y);
    defer a.free(yf);
    const tok: u32 = @intCast((yf[yf.len - 1] + 1) % V);
    yf[yf.len - 1] = tok;
    const g = rq.mo.greedy;
    const L = rq.b.wit.items[rq.mo.logits];
    const lf = try a.dupe(i32, L);
    const row = lf[lf.len - V ..];
    for (row, 0..) |*v, i| {
        if (i < tok) v.* = @min(v.*, 126);
        if (i == tok) v.* = 127;
    }
    const lf_id = try rq.b.add(rq.b.infos.items[rq.mo.logits], lf);
    try rq.b.rangeSigned(lf_id, 8);
    lastRow(&rq.b, g.m, 1)[0] = 127;
    for (lastRow(&rq.b, g.dr, V), row) |*d, l| d.* = 127 - l;
    var n: usize = 0;
    for (rq.b.xops.items) |*op| if (op.* == .lineq and termOf(op.lineq.expr, Ref.w(g.dr)) != null) {
        if (termOf(op.lineq.expr, Ref.w(rq.mo.logits))) |ti| {
            const ts = try rq.b.arena.allocator().dupe(xt.Term, op.lineq.expr.terms);
            ts[ti].t = Ref.w(lf_id);
            op.lineq.expr.terms = ts;
            n += 1;
        }
    };
    try testing.expectEqual(@as(usize, 1), n);
    try setGreedyPublics(&rq.b, g, yf, V);
    try testing.expect(!try attack(a, &fx, &rq.b, .{ .prompt = rq.prompt, .y = yf }));
}

// B2 (altered key / table window): the "Dr - Lt in [0, 256)" key's constant
// changed to +128 and its table to 9 bits (so Dr >= -127 passes); m = L[yf] for a NON-maximising yf.
test "recheck LM-2 B2: greedy range key shifted to admit negative Dr" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a, CFG);
    defer fx.deinit(a);
    const V = @as(usize, 1) << CFG.log_vocab;
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 45);
    defer rq.deinit(a);
    const g = rq.mo.greedy;
    const Lrow = lastRow(&rq.b, rq.mo.logits, V);
    var mx: i32 = -1000;
    var mn: i32 = 1000;
    for (Lrow) |v| {
        mx = @max(mx, v);
        mn = @min(mn, v);
    }
    var tok: ?u32 = null;
    for (0..V) |v| if (Lrow[v] < mx and mx - Lrow[v] <= 127 and Lrow[v] - mn <= 127) {
        tok = @intCast(v);
        break;
    };
    const yf = try a.dupe(u32, rq.y);
    defer a.free(yf);
    yf[yf.len - 1] = tok.?;
    const m = Lrow[tok.?];
    lastRow(&rq.b, g.m, 1)[0] = m;
    for (lastRow(&rq.b, g.dr, V), Lrow) |*d, l| d.* = m - l;
    var n: usize = 0;
    for (rq.b.xops.items) |*op| if (op.* == .key and termOf(op.key.input, Ref.p(g.lt)) != null) {
        op.key.input.constant = 128;
        op.key.table = .{ .range = 9 };
        n += 1;
    };
    try testing.expectEqual(@as(usize, 1), n);
    try setGreedyPublics(&rq.b, g, yf, V);
    try testing.expect(!try attack(a, &fx, &rq.b, .{ .prompt = rq.prompt, .y = yf }));
}

/// desc with plan entry k changed by +1 (owned plan); digest left to caller.
fn shiftedDesc(a: std.mem.Allocator, d: lm.ModelDesc, k: usize) !lm.ModelDesc {
    const sh = try a.dupe(u5, d.shifts.?);
    sh[k] += 1;
    return .{ .cfg = d.cfg, .gains = d.gains, .shifts = sh };
}

/// Builds a request statement under `d2` with model_digest overwritten to the
/// real descriptor's, for a prompt whose decode under d2 differs from the
/// real one. Returns false if no seed gives a difference.
fn falseUnder(a: std.mem.Allocator, fx: *Fx, d2: *const lm.ModelDesc, rq: *lm.TestRequest) !bool {
    for (60..140) |seed| {
        rq.* = lm.TestRequest.init(a, &fx.pool, d2, &fx.sw.ws, seed) catch continue;
        const yd = lm.decodeGreedy(a, &fx.pool, &fx.desc, &fx.sw.ws, rq.prompt) catch null;
        defer if (yd) |v| a.free(v);
        if (yd != null and !std.mem.eql(u32, yd.?, rq.y)) {
            rq.b.model_digest = fx.desc.digest();
            return true;
        }
        rq.deinit(a);
    }
    return false;
}

// B3 (change shifts): the LM head matmul's requant shift +1 in the statement
// (last plan entry), model_digest = the real descriptor's; claim = greedy of
// the coarser logits, which differs from the real model's output.
test "recheck LM-2 B3: LM head shift changed" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a, CFG);
    defer fx.deinit(a);
    var d2 = try shiftedDesc(a, fx.desc, fx.desc.shifts.?.len - 1);
    defer a.free(d2.shifts.?);
    var rq: lm.TestRequest = undefined;
    const found = try falseUnder(a, &fx, &d2, &rq);
    std.debug.print("  B3 false claim found={}\n", .{found});
    try testing.expect(found);
    defer rq.deinit(a);
    try testing.expect(!try attack(a, &fx, &rq.b, .{ .prompt = rq.prompt, .y = rq.y }));
}

// ---------------------------------------------------------------------------
// LM-3

// C1 (change shifts): a mid-model shift (plan entry 1) +1, digest overwritten.
test "recheck LM-3 C1: a mid-model requant shift changed" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a, CFG);
    defer fx.deinit(a);
    var found = false;
    var k: usize = 0;
    while (k + 1 < fx.desc.shifts.?.len and !found) : (k += 1) {
        var d2 = try shiftedDesc(a, fx.desc, k);
        defer a.free(d2.shifts.?);
        var rq: lm.TestRequest = undefined;
        if (try falseUnder(a, &fx, &d2, &rq)) {
            defer rq.deinit(a);
            found = true;
            std.debug.print("  C1 plan entry {d}\n", .{k});
            try testing.expect(!try attack(a, &fx, &rq.b, .{ .prompt = rq.prompt, .y = rq.y }));
        }
    }
    try testing.expect(found);
}

// C2 (swap gamma publics between norms): built with gains 0 and 2 swapped
// (attention norm <-> final norm); the public values are then restored to
// the descriptor's and the two einsums' gamma refs swapped, so every public
// and the digest equal the verifier's but the norms read each other's gain.
test "recheck LM-3 C2: RMSNorm gamma refs permuted across norms" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a, CFG);
    defer fx.deinit(a);
    const D = @as(usize, 1) << CFG.log_d;
    const g = try a.dupe(i32, fx.desc.gains);
    defer a.free(g);
    @memcpy(g[0..D], fx.desc.gain(2));
    @memcpy(g[2 * D ..][0..D], fx.desc.gain(0));
    const d2 = lm.ModelDesc{ .cfg = CFG, .gains = g, .shifts = fx.desc.shifts };
    var rq: lm.TestRequest = undefined;
    const found = try falseUnder(a, &fx, &d2, &rq);
    try testing.expect(found);
    defer rq.deinit(a);
    var pid: [3]?u32 = .{ null, null, null };
    for (rq.b.publics.items, 0..) |p, i| for (0..3) |gi| {
        if (p.log_size == CFG.log_d and std.mem.eql(i32, p.values, d2.gain(gi))) pid[gi] = @intCast(i);
    };
    const p0 = pid[0].?;
    const p2 = pid[2].?;
    rq.b.publics.items[p0].values = try rq.b.arena.allocator().dupe(i32, fx.desc.gain(0));
    rq.b.publics.items[p2].values = try rq.b.arena.allocator().dupe(i32, fx.desc.gain(2));
    var n: usize = 0;
    for (rq.b.xops.items) |*op| if (op.* == .einsum) {
        const e = &op.einsum;
        if (e.b.public and e.b.id == p0) {
            e.b = Ref.p(p2);
            n += 1;
        } else if (e.b.public and e.b.id == p2) {
            e.b = Ref.p(p0);
            n += 1;
        }
    };
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expect(!try attack(a, &fx, &rq.b, .{ .prompt = rq.prompt, .y = rq.y }));
}
