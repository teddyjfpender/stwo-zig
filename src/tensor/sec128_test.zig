//! -Dchallenge=om31 suite: the degree-8 challenge field end to end and the
//! 128/160-bit security levels (proto.SecurityLevel, security.md section 10).
//! Run with: zig build test -Doptimize=ReleaseSafe -Dchallenge=om31
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const model = @import("model.zig");
const wk = @import("weight_key.zig");
const wire = @import("wire.zig");
const security = @import("security.zig");
const Transcript = @import("transcript.zig").Transcript;

const testing = std.testing;

test "om31 build: challenge field is degree 8, QM31 is its subfield" {
    try testing.expect(f.IS_OM31);
    try testing.expectEqual(@as(usize, 8), f.N_LIMBS);
    const x = f.fromLimbs(.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try testing.expectEqualSlices(u32, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, &f.limbs(x));
    try testing.expect(x.mul(try x.inv()).eql(f.QM31.one()));
    // QM31 constants keep their meaning: fromU32Unchecked is the subfield
    const q = f.QM31.fromU32Unchecked(3, 1, 4, 1);
    const q4 = f.Q4.fromU32Unchecked(3, 1, 4, 1);
    try testing.expect(q.mul(q).c0.eql(q4.mul(q4)) and q.mul(q).c1.isZero());
    // v^2 = u (the irreducible quadratic of core/fields/om31.zig)
    const v = f.QM31{ .c0 = f.Q4.zero(), .c1 = f.Q4.one() };
    try testing.expect(v.mul(v).eql(f.QM31.fromU32Unchecked(0, 0, 1, 0)));
    try testing.expectApproxEqAbs(@as(f64, 248.0), security.LOG2_F, 1e-6);
}

test "om31 transcript draws use all 8 coordinates and are deterministic" {
    var t = Transcript.initDomain("x");
    const d = t.draw();
    try testing.expect(!d.c1.isZero());
    var t2 = Transcript.initDomain("x");
    try testing.expect(t2.draw().eql(d));
}

const dummy_info = [_]proto.TensorInfo{proto.TensorInfo.mat(2, 2)};

/// The level's parameters with a tiny witness split
fn levelConfig(level: proto.SecurityLevel) proto.Config {
    const base = proto.Config{ .gkr_threads = 1, .weight_log_cols = 2, .witness_log_cols_max = 6, .batch_matmuls = true };
    return proto.securityConfig(base, level);
}

const Case = struct {
    cfg: proto.Config,
    st: proto.Statement,
    ws: proto.WeightStore,
    kp: wk.KeyProof,
    proof: proto.Proof,
    built: model.Built,
    wdata: [3][]i8 = .{ &.{}, &.{}, &.{} },
    x: []i32 = &.{},

    fn deinit(self: *Case, a: std.mem.Allocator) void {
        self.proof.deinit(a);
        self.kp.deinit(a);
        self.ws.deinit(a);
        self.built.deinit(a);
        for (self.wdata) |w| a.free(w);
        a.free(self.x);
    }
};

var dummy_weights: [16]i8 = [_]i8{0} ** 16;

fn buildProduct(a: std.mem.Allocator, pool: *f.Pool, pc: proto.Config) !Case {
    var tm: proto.Timings = .{};
    const dv = [_][]const i8{&dummy_weights};
    var ws = try proto.commitWeights(a, pool, pc, &dummy_info, &dv);
    errdefer ws.deinit(a);
    var built = try model.buildProduct(a, 8, 5);
    errdefer built.deinit(a);
    var st = built.statement();
    st.weights = &dummy_info;
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var kp = try wk.prove(a, pool, pc, &ws);
    errdefer kp.deinit(a);
    const proof = try proto.prove(a, pool, pc, st, &ws, wview, &tm);
    return .{ .cfg = pc, .st = st, .ws = ws, .kp = kp, .proof = proof, .built = built };
}

const mlp_cfg = model.Mlp{ .log_t = 2, .log_d = 4, .log_f = 5 };
const mlp_infos = model.mlpWeightInfos(mlp_cfg);

fn buildMlp(a: std.mem.Allocator, pool: *f.Pool, pc0: proto.Config) !Case {
    var tm: proto.Timings = .{};
    var pc = pc0;
    pc.weight_log_cols = try proto.chooseWeightLogCols(pc, a, &mlp_infos, 2);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, mlp_infos[i].size(), 100 + i, -8, 7);
    const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var ws = try proto.commitWeights(a, pool, pc, &mlp_infos, &wv);
    errdefer ws.deinit(a);
    const x = try model.randomInput(a, @as(usize, 1) << (mlp_cfg.log_t + mlp_cfg.log_d), 9);
    var built = try model.buildMlp(a, pool, &ws, mlp_cfg, x);
    errdefer built.deinit(a);
    const st = built.statement();
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var kp = try wk.prove(a, pool, pc, &ws);
    errdefer kp.deinit(a);
    const proof = try proto.prove(a, pool, pc, st, &ws, wview, &tm);
    return .{ .cfg = pc, .st = st, .ws = ws, .kp = kp, .proof = proof, .built = built, .wdata = wdata, .x = x };
}

/// The CLI pipeline from bytes: statement -> key -> caps -> proof -> verify.
fn verifyBytes(a: std.mem.Allocator, sb: []const u8, kb: []const u8, pb: []const u8) !void {
    var sf = try wire.decodeStatement(a, sb);
    defer sf.deinit();
    var kf = try wire.decodeKey(a, kb, sf.cfg, sf.st);
    defer kf.deinit();
    try wk.verify(a, sf.cfg, kf.key, &kf.proof);
    var caps = try wire.proofCaps(a, sf.cfg, sf.st, kf.key);
    defer caps.deinit(a);
    var pf = try wire.decodeProof(a, pb, caps);
    defer pf.deinit();
    try proto.verify(a, sf.cfg, sf.st, kf.key, &pf.proof);
}

fn exercise(a: std.mem.Allocator, c: *Case, min_bits: f64) !void {
    const key = proto.weightKey(&c.ws);
    try proto.verify(a, c.cfg, c.st, key, &c.proof);
    try wk.verify(a, c.cfg, key, &c.kp);
    try testing.expectEqual(c.cfg.security, c.proof.security);

    // calculator: the level's number, all rounds added, no PoW credit
    // (a statement without weight reads is accounted without the key, as
    // tensor-bench does: nothing in it relies on the key's distance)
    const reads_weights = c.proof.weight_opening != null;
    var rep = try security.accountProof(a, c.cfg, c.st, key, &c.proof, if (reads_weights) &c.kp else null);
    defer rep.deinit();
    const s = rep.total.summary();
    std.debug.print("sec128 {s}: sum_with {d:.2} sum_without {d:.2} worst {s}\n", .{ c.cfg.security.name(), s.sum_with, s.sum_without, s.worst_without });
    try testing.expect(!rep.conditional_on_key);
    try testing.expect(s.sum_without >= min_bits);
    try testing.expect(s.sum_with >= s.sum_without);

    // wire round trip; header = MAGIC, VERSION 2, kind, degree 8, level
    const sb = try wire.encodeStatement(a, c.cfg, c.st);
    defer a.free(sb);
    const kb = try wire.encodeKey(a, key, c.kp);
    defer a.free(kb);
    const pb = try wire.encodeProof(a, c.proof);
    defer a.free(pb);
    for ([_][]const u8{ sb, kb, pb }) |b| {
        try testing.expectEqual(@as(u8, 2), b[4]);
        try testing.expectEqual(@as(u8, 8), b[6]);
    }
    try testing.expectEqual(@intFromEnum(c.cfg.security), pb[7]);
    try testing.expectEqual(@intFromEnum(c.cfg.security), sb[7]);
    // the key header carries the level the key was proven at
    try testing.expectEqual(@intFromEnum(c.cfg.security), kb[7]);
    try verifyBytes(a, sb, kb, pb);

    // runtime level check: the statement's account reaches its target ...
    try security.checkLevel(rep, c.cfg.security);
    try security.verifyAtLevel(a, c.cfg, c.st, key, &c.proof, if (reads_weights) &c.kp else null);
    // ... and a report is refused against a higher target than it reaches
    if (c.cfg.security == .bits128) try testing.expectError(error.SecurityBelowLevel, security.checkLevel(rep, .bits160));
    // a statement that reads weights, accounted without its key: refused
    if (reads_weights) {
        var cond = try security.accountProof(a, c.cfg, c.st, key, &c.proof, null);
        defer cond.deinit();
        try testing.expect(cond.conditional_on_key);
        try testing.expectError(error.SecurityBelowLevel, security.checkLevel(cond, c.cfg.security));
    }
    // key / level mismatch: a clear error, from the file header and from
    // the in-memory key proof
    {
        const kbad = try a.dupe(u8, kb);
        defer a.free(kbad);
        kbad[7] = if (c.cfg.security == .bits128) @intFromEnum(proto.SecurityLevel.bits160) else @intFromEnum(proto.SecurityLevel.bits128);
        var sf = try wire.decodeStatement(a, sb);
        defer sf.deinit();
        try testing.expectError(error.SecurityLevelMismatch, wire.decodeKey(a, kbad, sf.cfg, sf.st));
        kbad[7] = @intFromEnum(proto.SecurityLevel.custom);
        try testing.expectError(error.SecurityLevelMismatch, wire.decodeKey(a, kbad, sf.cfg, sf.st));
        kbad[7] = 9;
        try testing.expectError(error.NonCanonical, wire.decodeKey(a, kbad, sf.cfg, sf.st));
        var kp2 = c.kp;
        kp2.security = .custom;
        try testing.expectError(error.SecurityLevelMismatch, wk.verify(a, c.cfg, key, &kp2));
        try testing.expectError(error.SecurityLevelMismatch, security.verifyAtLevel(a, c.cfg, c.st, key, &c.proof, &kp2));
    }
    {
        var sf = try wire.decodeStatement(a, sb);
        defer sf.deinit();
        const sb2 = try wire.encodeStatement(a, sf.cfg, sf.st);
        defer a.free(sb2);
        try testing.expectEqualSlices(u8, sb, sb2);
        var caps = try wire.proofCaps(a, sf.cfg, sf.st, key);
        defer caps.deinit(a);
        var pf = try wire.decodeProof(a, pb, caps);
        defer pf.deinit();
        try testing.expect(wire.deepEql(pf.proof, c.proof));
        const pb2 = try wire.encodeProof(a, pf.proof);
        defer a.free(pb2);
        try testing.expectEqualSlices(u8, pb, pb2);
    }

    // header tampering: QM31 version, wrong degree, wrong level
    const bad = try a.dupe(u8, pb);
    defer a.free(bad);
    bad[4] = 1;
    try testing.expectError(error.ChallengeFieldMismatch, verifyBytes(a, sb, kb, bad));
    bad[4] = 2;
    bad[6] = 4;
    try testing.expectError(error.ChallengeFieldMismatch, verifyBytes(a, sb, kb, bad));
    bad[6] = 8;
    bad[7] = @intFromEnum(proto.SecurityLevel.custom);
    try testing.expectError(error.SecurityLevelMismatch, verifyBytes(a, sb, kb, bad));
    // a statement labelled with another level: its config fails checkSecurity
    const sbad = try a.dupe(u8, sb);
    defer a.free(sbad);
    sbad[7] = if (c.cfg.security == .bits128) @intFromEnum(proto.SecurityLevel.bits160) else @intFromEnum(proto.SecurityLevel.bits128);
    // (the key file's header still names the key's own level: refused at key decode)
    try testing.expectError(error.SecurityLevelMismatch, verifyBytes(a, sbad, kb, pb));

    // random single-bit flips in the proof body: all rejected (never accepted, never a panic)
    var prng = std.Random.DefaultPrng.init(5);
    const N = 48;
    for (0..N) |_| {
        const m = try a.dupe(u8, pb);
        defer a.free(m);
        const at = 8 + prng.random().uintLessThan(usize, m.len - 8);
        m[at] ^= @as(u8, 1) << prng.random().int(u3);
        if (verifyBytes(a, sb, kb, m)) |_| {
            std.debug.print("accepted flip at byte {d} of {d}\n", .{ at, m.len });
            return error.TestUnexpectedAccept;
        } else |_| {}
    }

    // in-memory tamper of the half of a challenge-field value that QM31
    // does not have (c1): rejected
    c.proof.witness_value.c1 = c.proof.witness_value.c1.add(f.Q4.one());
    try testing.expect(std.meta.isError(proto.verify(a, c.cfg, c.st, key, &c.proof)));
    c.proof.witness_value.c1 = c.proof.witness_value.c1.sub(f.Q4.one());
    try proto.verify(a, c.cfg, c.st, key, &c.proof);

    // the same proof and parameters with the level label stripped: the
    // transcript binds the level, so it does not verify as a .custom proof
    var other = c.cfg;
    other.security = .custom;
    var relabelled = c.proof;
    relabelled.security = .custom;
    try testing.expect(std.meta.isError(proto.verify(a, other, c.st, key, &relabelled)));
}

test "sec128: product proof at bits128 round-trips, accounts >= 128 bits, rejects tampering" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var c = try buildProduct(a, &pool, levelConfig(.bits128));
    defer c.deinit(a);
    try exercise(a, &c, 128);
}

test "sec128: MLP proof (LogUp-GKR over OM31) at bits128 and bits160" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var c = try buildMlp(a, &pool, levelConfig(.bits128));
    defer c.deinit(a);
    try exercise(a, &c, 128);
    var d = try buildMlp(a, &pool, levelConfig(.bits160));
    defer d.deinit(a);
    try exercise(a, &d, 160);
}

test "sec128: configs that do not match their level are refused" {
    var pc = levelConfig(.bits128);
    try proto.checkSecurity(pc);
    pc.pcs.n_queries -= 1;
    try testing.expectError(error.SecurityParams, proto.checkSecurity(pc));
    pc = levelConfig(.bits128);
    pc.two_level.?.inner.n_queries = 50;
    try testing.expectError(error.SecurityParams, proto.checkSecurity(pc));
    pc = levelConfig(.bits128);
    pc.two_level.?.ood = false;
    try testing.expectError(error.SecurityParams, proto.checkSecurity(pc));
    pc = levelConfig(.bits128);
    pc.weight_proximity = false;
    try testing.expectError(error.SecurityParams, proto.checkSecurity(pc));
    // prover-cost knobs are free
    pc = levelConfig(.bits128);
    pc.two_level.?.inner_work_shift = 1;
    pc.gkr_threads = 7;
    try proto.checkSecurity(pc);
}
