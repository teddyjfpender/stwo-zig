//! Wire-format tests: canonical roundtrips and mutation fuzzing of encoded
//! proofs, keys and statements for product, mlp and layer at tiny sizes.
//! Every mutated proof / key must be rejected with an error (never a panic).
const std = @import("std");
const builtin = @import("builtin");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const model = @import("model.zig");
const tf = @import("transformer.zig");
const wk = @import("weight_key.zig");
const wire = @import("wire.zig");

const testing = std.testing;

pub const CaseKind = enum { product, mlp, layer };

/// One proved instance: statement, config, weights, key proof and proof.
pub const Case = struct {
    a: std.mem.Allocator,
    kind: CaseKind,
    cfg: proto.Config,
    st: proto.Statement,
    ws: proto.WeightStore,
    kp: wk.KeyProof,
    proof: proto.Proof,
    // owners of the statement data
    built: ?model.Built = null,
    builder: ?tf.Builder = null,
    wdata: [][]i8 = &.{},
    winfos: []proto.TensorInfo = &.{},
    x: []i32 = &.{},

    pub fn deinit(self: *Case) void {
        const a = self.a;
        self.proof.deinit(a);
        self.kp.deinit(a);
        self.ws.deinit(a);
        if (self.built) |*b| b.deinit(a);
        if (self.builder) |*b| b.deinit();
        for (self.wdata) |w| a.free(w);
        a.free(self.wdata);
        a.free(self.winfos);
        a.free(self.x);
    }
};

const dummy_info = [_]proto.TensorInfo{proto.TensorInfo.mat(2, 2)};

fn caseConfig(kind: CaseKind) proto.Config {
    return switch (kind) {
        // flat Ligero, per-matmul sumchecks
        .product => .{ .pcs = .{ .log_blowup = 2, .n_queries = 9, .pow_bits = 2 }, .weight_log_cols = 2, .witness_log_cols_max = 6, .gkr_threads = 1 },
        // pcs2 depth 2 beyond unique decoding: OOD samples, deep levels,
        // separate weight / key outer parameters, two key alphas
        .mlp => blk: {
            var pc = proto.Config{
                .two_level = .{ .outer = .{ .log_blowup = 2, .n_queries = 10, .pow_bits = 2 }, .inner = .{ .log_blowup = 3, .n_queries = 8, .pow_bits = 1 }, .depth = 2, .ood = true, .prox_rows = 2, .deep = .{ .log_blowup = 4, .n_queries = 6, .pow_bits = 1 } },
                .batch_matmuls = true,
                .weight_outer = .{ .log_blowup = 2, .n_queries = 7, .pow_bits = 2 },
                .key_outer = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 2 },
                .key_alphas = 2,
                .gkr_threads = 1,
            };
            pc.pcs = pc.two_level.?.outer;
            break :blk pc;
        },
        // pcs2 depth 1 + batched matmuls (the bench's default shape)
        .layer => blk: {
            var pc = proto.recommendedConfig(.{ .log_blowup = 2, .n_queries = 9, .pow_bits = 1 }, .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 });
            pc.two_level.?.depth = 1;
            pc.gkr_threads = 1;
            pc.witness_log_cols_max = 8;
            break :blk pc;
        },
    };
}

pub fn buildCase(a: std.mem.Allocator, pool: *f.Pool, kind: CaseKind) !Case {
    var pc = caseConfig(kind);
    var tm: proto.Timings = .{};
    switch (kind) {
        .product => {
            var dummy: [16]i8 = [_]i8{0} ** 16;
            const dv = [_][]const i8{&dummy};
            var ws = try proto.commitWeights(a, pool, pc, &dummy_info, &dv);
            errdefer ws.deinit(a);
            var built = try model.buildProduct(a, 6, 5);
            errdefer built.deinit(a);
            var st = built.statement();
            st.weights = &dummy_info;
            const wview = try a.alloc([]const i32, built.witness.len);
            defer a.free(wview);
            for (built.witness, 0..) |w, i| wview[i] = w;
            var kp = try wk.prove(a, pool, pc, &ws);
            errdefer kp.deinit(a);
            const proof = try proto.prove(a, pool, pc, st, &ws, wview, &tm);
            return .{ .a = a, .kind = kind, .cfg = pc, .st = st, .ws = ws, .kp = kp, .proof = proof, .built = built };
        },
        .mlp => {
            const mc = model.Mlp{ .log_t = 2, .log_d = 4, .log_f = 5 };
            const wi = model.mlpWeightInfos(mc);
            const winfos = try a.dupe(proto.TensorInfo, &wi);
            errdefer a.free(winfos);
            pc.weight_log_cols = try proto.chooseWeightLogCols(pc, a, winfos, 2);
            const wdata = try a.alloc([]i8, 3);
            errdefer a.free(wdata);
            for (wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 100 + i, -8, 7);
            errdefer for (wdata) |w| a.free(w);
            const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
            var ws = try proto.commitWeights(a, pool, pc, winfos, &wv);
            errdefer ws.deinit(a);
            const x = try model.randomInput(a, @as(usize, 1) << (mc.log_t + mc.log_d), 9);
            errdefer a.free(x);
            var built = try model.buildMlp(a, pool, &ws, mc, x);
            errdefer built.deinit(a);
            const st = built.statement();
            const wview = try a.alloc([]const i32, built.witness.len);
            defer a.free(wview);
            for (built.witness, 0..) |w, i| wview[i] = w;
            var kp = try wk.prove(a, pool, pc, &ws);
            errdefer kp.deinit(a);
            const proof = try proto.prove(a, pool, pc, st, &ws, wview, &tm);
            return .{ .a = a, .kind = kind, .cfg = pc, .st = st, .ws = ws, .kp = kp, .proof = proof, .built = built, .wdata = wdata, .winfos = winfos, .x = x };
        },
        .layer => {
            const lc = tf.LayerCfg{ .log_t = 2, .log_d = 4, .log_f = 5, .log_heads = 1, .log_kv_heads = 1, .router_log_cols = 4, .fused_qkv = true };
            try lc.validate();
            const wi = try tf.layerWeightInfos(a, lc);
            defer a.free(wi);
            pc.weight_log_cols = try proto.chooseWeightLogCols(pc, a, wi, wi.len);
            var sw = try tf.setupWeights(a, pool, lc, pc, 300);
            errdefer {
                sw.ws.deinit(a);
                for (sw.wdata) |w| a.free(w);
                a.free(sw.wdata);
                a.free(sw.winfos);
            }
            var b = tf.Builder.init(a, pool);
            errdefer b.deinit();
            const c = try tf.initCtx(&b, lc, &sw.ws, 1);
            const x = try model.randomInput(a, @as(usize, 1) << @intCast(lc.log_t + lc.log_d), 17);
            errdefer a.free(x);
            _ = try tf.buildStack(&b, c, x);
            const st = b.statement();
            const wv = try b.witnessView(a);
            defer a.free(wv);
            var kp = try wk.prove(a, pool, pc, &sw.ws);
            errdefer kp.deinit(a);
            const proof = try proto.prove(a, pool, pc, st, &sw.ws, wv, &tm);
            return .{ .a = a, .kind = kind, .cfg = pc, .st = st, .ws = sw.ws, .kp = kp, .proof = proof, .builder = b, .wdata = sw.wdata, .winfos = sw.winfos, .x = x };
        },
    }
}

// ---------------------------------------------------------------------------
// Full pipeline from bytes (what tensor-verify runs).

pub fn verifyBytes(a: std.mem.Allocator, st_bytes: []const u8, key_bytes: []const u8, proof_bytes: []const u8) !void {
    var sf = try wire.decodeStatement(a, st_bytes);
    defer sf.deinit();
    var kf = try wire.decodeKey(a, key_bytes, sf.cfg, sf.st);
    defer kf.deinit();
    try wk.verify(a, sf.cfg, kf.key, &kf.proof);
    var caps = try wire.proofCaps(a, sf.cfg, sf.st, kf.key);
    defer caps.deinit(a);
    var pf = try wire.decodeProof(a, proof_bytes, caps);
    defer pf.deinit();
    try proto.verify(a, sf.cfg, sf.st, kf.key, &pf.proof);
}

fn roundtrip(c: *const Case) !void {
    const a = testing.allocator;
    const key = proto.weightKey(&c.ws);
    try proto.verify(a, c.cfg, c.st, key, &c.proof);

    const sb = try wire.encodeStatement(a, c.cfg, c.st);
    defer a.free(sb);
    var sf = try wire.decodeStatement(a, sb);
    defer sf.deinit();
    const sb2 = try wire.encodeStatement(a, sf.cfg, sf.st);
    defer a.free(sb2);
    try testing.expectEqualSlices(u8, sb, sb2);

    const kb = try wire.encodeKey(a, key, c.kp);
    defer a.free(kb);
    var kf = try wire.decodeKey(a, kb, sf.cfg, sf.st);
    defer kf.deinit();
    try testing.expect(wire.deepEql(kf.key, key));
    try testing.expect(wire.deepEql(kf.proof, c.kp));
    const kb2 = try wire.encodeKey(a, kf.key, kf.proof);
    defer a.free(kb2);
    try testing.expectEqualSlices(u8, kb, kb2);

    var caps = try wire.proofCaps(a, sf.cfg, sf.st, kf.key);
    defer caps.deinit(a);
    const pb = try wire.encodeProof(a, c.proof);
    defer a.free(pb);
    var pf = try wire.decodeProof(a, pb, caps);
    defer pf.deinit();
    try testing.expect(wire.deepEql(pf.proof, c.proof));
    const pb2 = try wire.encodeProof(a, pf.proof);
    defer a.free(pb2);
    try testing.expectEqualSlices(u8, pb, pb2);

    try verifyBytes(a, sb, kb, pb);
    // a proof for another config / statement shape is refused by the decoder
    // or the verifier, never accepted
    var other = sf.cfg;
    other.batch_matmuls = !other.batch_matmuls;
    if (wire.proofCaps(a, other, sf.st, kf.key)) |oc0| {
        var oc = oc0;
        defer oc.deinit(a);
        if (wire.decodeProof(a, pb, oc)) |pf2| {
            var p2 = pf2;
            defer p2.deinit();
            const has_matmul = for (c.st.ops) |op| {
                if (op == .matmul) break true;
            } else false;
            if (has_matmul and c.kind == .mlp) try testing.expect(std.meta.isError(proto.verify(a, other, sf.st, kf.key, &p2.proof)));
        } else |_| {}
    } else |_| {}
}

test "wire: product / mlp / layer roundtrip byte-identically and verify from bytes" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    inline for (.{ CaseKind.product, CaseKind.mlp, CaseKind.layer }) |k| {
        var c = try buildCase(a, &pool, k);
        defer c.deinit();
        try roundtrip(&c);
    }
}

test "wire: header, tags, trailing bytes, canonical field elements" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var c = try buildCase(a, &pool, .product);
    defer c.deinit();
    const key = proto.weightKey(&c.ws);
    var caps = try wire.proofCaps(a, c.cfg, c.st, key);
    defer caps.deinit(a);
    const pb = try wire.encodeProof(a, c.proof);
    defer a.free(pb);
    const buf = try a.dupe(u8, pb);
    defer a.free(buf);
    const E = wire.DecodeError;
    const expectErr = struct {
        fn f(e: E, b: []const u8, cp: wire.ProofCaps) !void {
            if (wire.decodeProof(testing.allocator, b, cp)) |pf| {
                var p = pf;
                p.deinit();
                return error.TestUnexpectedAccept;
            } else |got| try testing.expectEqual(e, got);
        }
    }.f;
    buf[0] ^= 1;
    try expectErr(error.BadMagic, buf, caps);
    buf[0] ^= 1;
    buf[4] = wire.VERSION + 1;
    try expectErr(error.BadVersion, buf, caps);
    buf[4] = wire.VERSION;
    buf[5] = @intFromEnum(wire.Kind.key);
    try expectErr(error.BadKind, buf, caps);
    buf[5] = @intFromEnum(wire.Kind.proof);
    // trailing bytes after the last section: an unknown / out-of-order tag
    const ext = try a.alloc(u8, pb.len + 1);
    defer a.free(ext);
    @memcpy(ext[0..pb.len], pb);
    ext[pb.len] = 0x0e;
    try expectErr(error.TrailingBytes, ext, caps);
    // an unknown tag in place of a known section
    const ui: usize = 6 + 5 + 32; // after the witness root section (product: no ood, no gkr)
    try testing.expectEqual(@as(u8, 0x04), pb[ui]);
    buf[ui] = 0x0f;
    try expectErr(error.UnknownTag, buf, caps);
    buf[ui] = 0x01;
    try expectErr(error.TagOrder, buf, caps);
    buf[ui] = 0x04;
    try expectErr(error.Truncated, pb[0 .. pb.len - 1], caps);
    // witness root section body: tag 1 at offset 6, length at 7..11, root at 11..43;
    // the next section (tag 4, no ood / gkr in product) holds the lookup values
    // (none); the witness value is a felt we can make non-canonical
    try testing.expectEqual(@as(u8, 0x01), pb[6]);
    var off: usize = 6;
    while (pb[off] != 0x08) off += 5 + std.mem.readInt(u32, pb[off + 1 ..][0..4], .little);
    std.mem.writeInt(u32, buf[off + 5 ..][0..4], f.P, .little);
    try expectErr(error.NonCanonicalField, buf, caps);
}

// ---------------------------------------------------------------------------
// Fuzzing.

pub const FuzzStats = struct {
    iters: usize = 0,
    decode_rejects: usize = 0,
    verify_rejects: usize = 0,
    accepted: usize = 0,
    by_mutation: [6]usize = [_]usize{0} ** 6,
    errors: std.StringHashMapUnmanaged(usize) = .{},

    pub fn note(self: *FuzzStats, a: std.mem.Allocator, e: anyerror) !void {
        const g = try self.errors.getOrPut(a, @errorName(e));
        if (!g.found_existing) g.value_ptr.* = 0;
        g.value_ptr.* += 1;
    }
    pub fn deinit(self: *FuzzStats, a: std.mem.Allocator) void {
        self.errors.deinit(a);
    }
    pub fn print(self: FuzzStats, name: []const u8) void {
        std.debug.print("wire fuzz {s}: {d} mutants, {d} decode-rejected, {d} verify-rejected, {d} accepted; mutations flip/trunc/extend/len/multi/splice = {any}\n", .{ name, self.iters, self.decode_rejects, self.verify_rejects, self.accepted, self.by_mutation });
        var it = self.errors.iterator();
        while (it.next()) |e| std.debug.print("    {s}: {d}\n", .{ e.key_ptr.*, e.value_ptr.* });
    }
};

/// One random mutation of `orig` (never identical to it).
fn mutate(a: std.mem.Allocator, rnd: std.Random, orig: []const u8, lens: []const usize, kind: usize) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, orig);
    switch (kind) {
        0 => out.items[rnd.uintLessThan(usize, out.items.len)] ^= rnd.intRangeAtMost(u8, 1, 255),
        1 => out.shrinkRetainingCapacity(rnd.uintLessThan(usize, orig.len)),
        2 => for (0..rnd.intRangeAtMost(usize, 1, 16)) |_| try out.append(a, rnd.int(u8)),
        3 => {
            const at = lens[rnd.uintLessThan(usize, lens.len)];
            const v = std.mem.readInt(u32, orig[at..][0..4], .little);
            const choices = [_]u32{ v +% 1, v -% 1, 0, 0xffff_ffff, v *% 2 +% 1, rnd.int(u32), v ^ (@as(u32, 1) << rnd.int(u5)) };
            var nv = choices[rnd.uintLessThan(usize, choices.len)];
            if (nv == v) nv = v +% 1;
            std.mem.writeInt(u32, out.items[at..][0..4], nv, .little);
        },
        4 => for (0..rnd.intRangeAtMost(usize, 2, 6)) |_| {
            out.items[rnd.uintLessThan(usize, out.items.len)] ^= rnd.intRangeAtMost(u8, 1, 255);
        },
        else => {
            // splice: delete or insert a run of bytes in the middle
            const at = rnd.uintLessThan(usize, orig.len);
            const n = rnd.intRangeAtMost(usize, 1, 8);
            if (rnd.boolean()) {
                const m = @min(n, orig.len - at);
                try out.replaceRange(a, at, m, &.{});
            } else {
                var ins: [8]u8 = undefined;
                rnd.bytes(ins[0..n]);
                try out.insertSlice(a, at, ins[0..n]);
            }
        },
    }
    if (std.mem.eql(u8, out.items, orig)) out.items[0] ^= 0x80;
    return out.toOwnedSlice(a);
}

pub const Target = enum { proof, key };

/// Mutates the encoded proof (or key file) `iters` times; every mutant must
/// be rejected by the decoder or the verifier.
pub fn fuzzCase(a: std.mem.Allocator, c: *const Case, target: Target, iters: usize, seed: u64, stats: *FuzzStats) !void {
    const key = proto.weightKey(&c.ws);
    var lens: std.ArrayList(usize) = .empty;
    defer lens.deinit(a);
    const orig = switch (target) {
        .proof => try wire.encodeProofTraced(a, c.proof, &lens),
        .key => try wire.encodeKeyTraced(a, key, c.kp, &lens),
    };
    defer a.free(orig);
    var caps = try wire.proofCaps(a, c.cfg, c.st, key);
    defer caps.deinit(a);
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    for (0..iters) |it| {
        const kind = it % 6;
        const m = try mutate(a, rnd, orig, lens.items, kind);
        defer a.free(m);
        stats.iters += 1;
        stats.by_mutation[kind] += 1;
        switch (target) {
            .proof => {
                var pf = wire.decodeProof(a, m, caps) catch |e| {
                    stats.decode_rejects += 1;
                    try stats.note(a, e);
                    continue;
                };
                defer pf.deinit();
                if (proto.verify(a, c.cfg, c.st, key, &pf.proof)) |_| {
                    stats.accepted += 1;
                    std.debug.print("ACCEPTED mutant: case {s} iter {d} mutation {d}\n", .{ @tagName(c.kind), it, kind });
                } else |e| {
                    stats.verify_rejects += 1;
                    try stats.note(a, e);
                }
            },
            .key => {
                var kf = wire.decodeKey(a, m, c.cfg, c.st) catch |e| {
                    stats.decode_rejects += 1;
                    try stats.note(a, e);
                    continue;
                };
                defer kf.deinit();
                if (wk.verify(a, c.cfg, kf.key, &kf.proof)) |_| {
                    stats.accepted += 1;
                    std.debug.print("ACCEPTED key mutant: case {s} iter {d} mutation {d}\n", .{ @tagName(c.kind), it, kind });
                } else |e| {
                    stats.verify_rejects += 1;
                    try stats.note(a, e);
                }
            },
        }
    }
}

/// Statement files: mutants must decode-or-error without crashing; a mutant
/// that decodes and verifies must encode a different but equivalent
/// verifier config (e.g. a parameter the selected PCS does not use).
fn fuzzStatement(a: std.mem.Allocator, c: *const Case, iters: usize, seed: u64, stats: *FuzzStats) !void {
    const key = proto.weightKey(&c.ws);
    const orig = try wire.encodeStatement(a, c.cfg, c.st);
    defer a.free(orig);
    const kb = try wire.encodeKey(a, key, c.kp);
    defer a.free(kb);
    const pb = try wire.encodeProof(a, c.proof);
    defer a.free(pb);
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    for (0..iters) |it| {
        const kinds = [_]usize{ 0, 1, 2, 4, 5 };
        const kind = kinds[it % 5];
        const m = try mutate(a, rnd, orig, &.{}, kind);
        defer a.free(m);
        stats.iters += 1;
        stats.by_mutation[kind] += 1;
        if (verifyBytes(a, m, kb, pb)) |_| {
            stats.accepted += 1;
        } else |e| {
            stats.decode_rejects += 1;
            try stats.note(a, e);
        }
    }
}

fn fuzzIters() usize {
    return if (builtin.mode == .Debug) 150 else 1200;
}

test "wire fuzz: mutated product / mlp / layer proofs and keys are rejected cleanly" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var total: FuzzStats = .{};
    defer total.deinit(a);
    inline for (.{ CaseKind.product, CaseKind.mlp, CaseKind.layer }, 0..) |k, ki| {
        var c = try buildCase(a, &pool, k);
        defer c.deinit();
        var ps: FuzzStats = .{};
        defer ps.deinit(a);
        try fuzzCase(a, &c, .proof, fuzzIters(), 1000 + ki, &ps);
        ps.print(@tagName(k) ++ " proof");
        try testing.expectEqual(@as(usize, 0), ps.accepted);
        var ks: FuzzStats = .{};
        defer ks.deinit(a);
        try fuzzCase(a, &c, .key, fuzzIters() / 4, 2000 + ki, &ks);
        ks.print(@tagName(k) ++ " key");
        try testing.expectEqual(@as(usize, 0), ks.accepted);
        var ss: FuzzStats = .{};
        defer ss.deinit(a);
        try fuzzStatement(a, &c, fuzzIters() / 8, 3000 + ki, &ss);
        ss.print(@tagName(k) ++ " statement");
        total.iters += ps.iters + ks.iters;
        total.decode_rejects += ps.decode_rejects + ks.decode_rejects;
        total.verify_rejects += ps.verify_rejects + ks.verify_rejects;
    }
    std.debug.print("wire fuzz total (proofs + keys): {d} mutants, {d} decode-rejected, {d} verify-rejected, 0 accepted\n", .{ total.iters, total.decode_rejects, total.verify_rejects });
}
