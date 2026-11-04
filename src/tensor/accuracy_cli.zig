//! tensor-accuracy: replays a quantized model file through lm.buildModel
//! (the integer forward the prover proves) and dumps logits / hidden states
//! for scripts/tensor_accuracy.py, which checks its numpy emulation against
//! this bit for bit; optionally runs lm.calibrate, and proves + verifies
//! requests end to end (serve.proveRequests, lm.verifyRequest).
//!
//!   tensor-accuracy <model.bin> <windows.bin> <out.bin>
//!       [--calibrate <calib.win.bin> <plan_out.bin> <headroom>]
//!       [--prove <n>]
//!
//! model.bin (little-endian): "STWOACC1", u32 x 11 (log_t, log_d, log_heads,
//! log_kv_heads, log_f, n_layers, log_vocab, log_out, fused_qkv,
//! weight_log_cols, score_bits), u32 n + i32 gains[n], u32 n + u8 shifts[n]
//! (n = 0: uncalibrated), u32 n_weights, then per weight u32 size + i8 data
//! (lm.weightInfos order, row-major [K, N]).
//! windows.bin: u32 n, u32 T, u32 tokens[n T].
//! out.bin: u32 n, then per window i32 status (0 ok, 1 refused:
//! RequantOverflow / ValueOutOfRange, 2 other error), i32 logits [2, V] (last
//! two rows of the head), i32 hidden [T, D] (final residual stream).
const std = @import("std");
const t = @import("stwo_tensor");
const f = t.field;
const proto = t.protocol;
const lm = t.lm;
const tf = t.transformer;
const serve = t.serve;

fn now() std.time.Instant {
    return std.time.Instant.now() catch unreachable;
}
fn since(t0: std.time.Instant) f64 {
    return @as(f64, @floatFromInt(now().since(t0))) / 1e9;
}

const Reader = struct {
    b: []const u8,
    p: usize = 0,
    fn u32_(self: *Reader) !u32 {
        if (self.p + 4 > self.b.len) return error.Truncated;
        const v = std.mem.readInt(u32, self.b[self.p..][0..4], .little);
        self.p += 4;
        return v;
    }
    fn bytes(self: *Reader, n: usize) ![]const u8 {
        if (self.p + n > self.b.len) return error.Truncated;
        const s = self.b[self.p..][0..n];
        self.p += n;
        return s;
    }
};

const Windows = struct { n: usize, T: usize, toks: []u32 };

fn readWindows(a: std.mem.Allocator, path: []const u8) !Windows {
    const raw = try std.fs.cwd().readFileAlloc(a, path, 1 << 30);
    defer a.free(raw);
    var r = Reader{ .b = raw };
    const n = try r.u32_();
    const T = try r.u32_();
    const toks = try a.alloc(u32, n * T);
    for (toks) |*v| v.* = try r.u32_();
    return .{ .n = n, .T = T, .toks = toks };
}

fn isRefusal(e: anyerror) bool {
    return e == error.RequantOverflow or e == error.ValueOutOfRange;
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const a = gpa.allocator();
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 4) {
        std.debug.print("usage: tensor-accuracy <model.bin> <windows.bin> <out.bin> [--calibrate <calib.win.bin> <plan_out.bin> <headroom>] [--prove <n>]\n", .{});
        std.process.exit(2);
    }
    var cal: ?[3][]const u8 = null;
    var n_prove: usize = 0;
    var i: usize = 4;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--calibrate") and i + 3 < args.len) {
            cal = .{ args[i + 1], args[i + 2], args[i + 3] };
            i += 3;
        } else if (std.mem.eql(u8, args[i], "--prove") and i + 1 < args.len) {
            n_prove = try std.fmt.parseInt(usize, args[i + 1], 10);
            i += 1;
        } else return error.BadArgs;
    }
    const out = std.fs.File.stdout().deprecatedWriter();

    // --- model file -------------------------------------------------------
    const raw = try std.fs.cwd().readFileAlloc(a, args[1], 1 << 30);
    defer a.free(raw);
    var r = Reader{ .b = raw };
    // STWOACC1: int8 activations / residual; STWOACC2 adds act_bits, resid_bits
    const magic = try r.bytes(8);
    const v2 = std.mem.eql(u8, magic, "STWOACC2");
    if (!v2 and !std.mem.eql(u8, magic, "STWOACC1")) return error.BadMagic;
    var h: [13]u32 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8 };
    for (h[0..if (v2) 13 else 11]) |*v| v.* = try r.u32_();
    const cfg = lm.ModelCfg{
        .log_t = h[0],
        .log_d = h[1],
        .log_heads = h[2],
        .log_kv_heads = h[3],
        .log_f = h[4],
        .n_layers = h[5],
        .log_vocab = h[6],
        .log_out = h[7],
        .fused_qkv = h[8] != 0,
        .weight_log_cols = h[9],
        .score_bits = h[10],
        .act_bits = h[11],
        .resid_bits = h[12],
    };
    try cfg.validate();
    const n_g = try r.u32_();
    const gains = try a.alloc(i32, n_g);
    defer a.free(gains);
    for (gains) |*g| g.* = @bitCast(try r.u32_());
    const n_s = try r.u32_();
    var plan: ?[]u5 = null;
    if (n_s > 0) {
        const sb = try r.bytes(n_s);
        const p = try a.alloc(u5, n_s);
        for (p, sb) |*d, s| d.* = @intCast(s);
        plan = p;
    }
    const winfos = try lm.weightInfos(a, cfg);
    defer a.free(winfos);
    const n_w = try r.u32_();
    if (n_w != winfos.len) return error.WeightCount;
    const wv = try a.alloc([]const i8, n_w);
    defer a.free(wv);
    for (wv, winfos) |*w, info| {
        const sz = try r.u32_();
        if (sz != info.size()) return error.WeightShape;
        w.* = @ptrCast(try r.bytes(sz));
    }

    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    var pc = proto.recommendedConfig(.{}, .{ .n_queries = 54 });
    pc.weight_log_cols = cfg.weight_log_cols;
    const t_commit = now();
    var ws = try proto.commitWeights(a, &pool, pc, winfos, wv);
    defer ws.deinit(a);
    const commit_s = since(t_commit);

    var desc = lm.ModelDesc{ .cfg = cfg, .gains = gains, .shifts = plan };
    defer if (desc.shifts) |p| a.free(p);
    try desc.validate();

    if (cal) |c| {
        const cw = try readWindows(a, c[0]);
        defer a.free(cw.toks);
        const lists = try a.alloc([]const u32, cw.n);
        defer a.free(lists);
        for (lists, 0..) |*l, j| l.* = cw.toks[j * cw.T ..][0..cw.T];
        const headroom = try std.fmt.parseInt(u5, c[2], 10);
        if (desc.shifts) |p| a.free(p);
        desc.shifts = null;
        // lm.calibrate frees a previous plan with `a` and sets desc.shifts (owned by `a`)
        try lm.calibrate(a, &pool, &desc, &ws, lists, headroom);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(a);
        try buf.appendSlice(a, std.mem.asBytes(&@as(u32, @intCast(desc.shifts.?.len))));
        for (desc.shifts.?) |s| try buf.append(a, s);
        try std.fs.cwd().writeFile(.{ .sub_path = c[1], .data = buf.items });
    }
    if (desc.shifts == null) return error.NotCalibrated;

    // --- forward replay -----------------------------------------------------
    const W = try readWindows(a, args[2]);
    defer a.free(W.toks);
    const T = @as(usize, 1) << @intCast(cfg.log_t);
    const D = @as(usize, 1) << @intCast(cfg.log_d);
    const V = @as(usize, 1) << @intCast(cfg.log_vocab);
    if (W.T != T) return error.WindowLength;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(a);
    try buf.appendSlice(a, std.mem.asBytes(&@as(u32, @intCast(W.n))));
    const zeros = try a.alloc(i32, 2 * V + T * D);
    defer a.free(zeros);
    @memset(zeros, 0);
    var n_ok: usize = 0;
    var n_ref: usize = 0;
    const t_fwd = now();
    for (0..W.n) |j| {
        const win = W.toks[j * T ..][0..T];
        var b = tf.Builder.init(a, &pool);
        defer b.deinit();
        const status: i32 = if (lm.buildModel(&b, &desc, &ws, win, null)) |mo| blk: {
            const lg = b.wit.items[mo.logits];
            try buf.appendSlice(a, std.mem.asBytes(&@as(i32, 0)));
            try buf.appendSlice(a, std.mem.sliceAsBytes(lg[lg.len - 2 * V ..]));
            try buf.appendSlice(a, std.mem.sliceAsBytes(b.wit.items[mo.hidden]));
            break :blk 0;
        } else |e| blk: {
            const st: i32 = if (isRefusal(e)) 1 else 2;
            if (st == 2) std.debug.print("window {d}: {s}\n", .{ j, @errorName(e) });
            try buf.appendSlice(a, std.mem.asBytes(&st));
            try buf.appendSlice(a, std.mem.sliceAsBytes(zeros));
            break :blk st;
        };
        if (status == 0) n_ok += 1 else n_ref += 1;
    }
    const fwd_s = since(t_fwd);
    try std.fs.cwd().writeFile(.{ .sub_path = args[3], .data = buf.items });
    try out.print("{{\"windows\":{d},\"ok\":{d},\"refused_or_error\":{d},\"forward_s\":{d:.3},\"commit_s\":{d:.3},\"n_shifts\":{d}", .{ W.n, n_ok, n_ref, fwd_s, commit_s, desc.shifts.?.len });

    // --- prove + verify requests ------------------------------------------------
    if (n_prove > 0) {
        if (cfg.log_out != 0) return error.ProveNeedsLogOut0;
        var trs: std.ArrayList(struct { prompt: []const u32, y: []u32, b: tf.Builder, view: []const []const i32 }) = .empty;
        defer {
            for (trs.items) |*x| {
                a.free(x.y);
                a.free(x.view);
                x.b.deinit();
            }
            trs.deinit(a);
        }
        var j: usize = 0;
        while (j < W.n and trs.items.len < n_prove) : (j += 1) {
            const prompt = W.toks[j * T ..][0..T];
            const y = lm.decodeGreedy(a, &pool, &desc, &ws, prompt) catch |e| {
                if (isRefusal(e)) continue;
                return e;
            };
            const w = try lm.requestWindow(a, cfg, prompt, y);
            defer a.free(w);
            var b = tf.Builder.init(a, &pool);
            _ = try lm.buildModel(&b, &desc, &ws, w, y);
            const view = try b.witnessView(a);
            try trs.append(a, .{ .prompt = prompt, .y = y, .b = b, .view = view });
        }
        const reqs = try a.alloc(serve.Request, trs.items.len);
        defer a.free(reqs);
        for (reqs, trs.items, 0..) |*q, *x, k| q.* = .{ .st = x.b.statement(), .witness = x.view, .salt = serve.testSalt(k) };
        const t_prove = now();
        var batch = try serve.proveRequests(a, &pool, pc, &ws, reqs, null);
        defer batch.deinit(a);
        const prove_s = since(t_prove);
        const key = proto.weightKey(&ws);
        const t_ver = now();
        var n_ver: usize = 0;
        for (trs.items, 0..) |x, k| {
            try lm.verifyRequest(a, &pool, pc, key, &desc, .{ .prompt = x.prompt, .y = x.y }, &batch.requests[k], &batch.shared, k);
            n_ver += 1;
        }
        const ver_s = since(t_ver);
        // a wrong claimed token must be rejected
        var n_rej: usize = 0;
        for (trs.items, 0..) |x, k| {
            const bad = try a.dupe(u32, x.y);
            defer a.free(bad);
            bad[0] = (bad[0] + 1) % @as(u32, @intCast(V));
            if (std.meta.isError(lm.verifyRequest(a, &pool, pc, key, &desc, .{ .prompt = x.prompt, .y = bad }, &batch.requests[k], &batch.shared, k))) n_rej += 1;
        }
        // proof cost: committed witness elements and wire-encoded proof bytes
        // per request (core proof), shared weight-opening bytes per batch
        var wit_elems: usize = 0;
        for (trs.items) |x| for (x.b.statement().witness) |inf| {
            wit_elems += inf.size();
        };
        var enc_bytes: usize = 0;
        for (batch.requests) |rp| {
            const pb = try t.wire.encodeProof(a, rp.core);
            defer a.free(pb);
            enc_bytes += pb.len + 32;
        }
        const n_r = @max(trs.items.len, 1);
        try out.print(",\"witness_elems_per_request\":{d},\"committed_bits_per_request\":{d},\"request_proof_bytes_mean\":{d},\"shared_opening_bytes\":{d}", .{ wit_elems / n_r, 32 * wit_elems / n_r, enc_bytes / n_r, batch.shared.byteSize() });
        try out.print(",\"proved\":{d},\"verified\":{d},\"wrong_token_rejected\":{d},\"prove_batch_s\":{d:.3},\"verify_total_s\":{d:.3},\"tokens\":[", .{ trs.items.len, n_ver, n_rej, prove_s, ver_s });
        for (trs.items, 0..) |x, k| try out.print("{s}{d}", .{ if (k == 0) "" else ",", x.y[0] });
        try out.print("]", .{});
    }
    try out.print("}}\n", .{});
}
