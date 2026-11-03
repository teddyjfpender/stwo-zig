//! Current V3 truth proof statement. It authenticates one physical proof and
//! exports its public words; an application/root must independently bind the
//! roster, statement identity, manifest and cross-proof Wire35 debt.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const V = @import("mod.zig");
const C = V.common;
const Frame = @import("frame.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const Catalog = @import("../../word16_global_execution/services/gkr_local/truth_v3_catalog.zig");
const Role = @import("../../word16_global_execution/services/gkr_local/truth_v3_role.zig").Component;
const Worker = @import("../../word16_global_execution/services/gkr_local/truth_v3_worker.zig");
const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const M = @import("../../word16_global_execution/services/gkr_local/manifest.zig");
const Fixed = @import("../../word16_global_execution/services/gkr_local/fixed_authority.zig");
const O = C.O;
const F = C.F;
pub const Public = struct {
    ordinal: u32,
    statement: [32]u8,
    manifest: [32]u8,
    claim: O,
};
pub const Words = struct {
    pub const ordinal = 0;
    pub const first_id = 1;
    pub const calls = 2;
    pub const statement = 3;
    pub const manifest = 11;
    pub const main = 19;
    pub const claim = 27;
    pub const count = 35;
};
pub fn statementWords(truth: R.Truth, public: Public, main: [32]u8) [Words.count]u32 {
    var words: [Words.count]u32 = undefined;
    words[0] = public.ordinal;
    words[1] = truth.first();
    words[2] = truth.count();
    for ([_][32]u8{ public.statement, public.manifest, main }, 0..) |digest, d| for (0..8) |i| {
        words[3 + d * 8 + i] = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    };
    for (public.claim.toM31Array(), 0..) |v, i| words[Words.claim + i] = v.v;
    return words;
}
fn roleFor(truth: R.Truth) Role {
    return .{ .truth = truth, .wire = .{ .offset = O.zero(), .coefficients = @splat(O.zero()) } };
}
pub fn shape(a: std.mem.Allocator, truth: R.Truth, config: core.pcs.PcsConfig) !V.Shape {
    try Catalog.validate(truth);
    const role = roleFor(truth);
    const descriptor = try Catalog.descriptor(truth);
    const log = descriptor.log_size;
    const split = role.compositionLogSplit();
    const logs = try a.alloc([]const u32, 4);
    const masks = try a.alloc([]const []const i32, 4);
    const widths = descriptor.widths();
    const current = [_]i32{0};
    const previous = [_]i32{ 0, -1 };
    for (0..4) |t| {
        const n = if (t == 3) @as(usize, 8) << @intCast(split) else widths[t];
        const sizes = try a.alloc(u32, n);
        @memset(sizes, log);
        logs[t] = sizes;
        const offsets = try a.alloc([]const i32, n);
        for (offsets, 0..) |*o, col| o.* = if ((t == 1 and role.previousMain(col)) or (t == 2 and role.previousInter(col))) &previous else &current;
        masks[t] = offsets;
    }
    const result = V.Shape{ .tree_column_log_sizes = logs, .mask_offsets = masks, .global_log = log, .composition_log_split = split, .pcs = config };
    try result.validate();
    return result;
}
pub const Statement = struct {
    truth: R.Truth,
    config: core.pcs.PcsConfig,
    binding: ?Frame.Binding,
    frame: Frame.Frame,
    ordinal: Frame.Word,
    first_id: F,
    calls: F,
    statement: Frame.Digest,
    manifest: Frame.Digest,
    claim: F,
    shared: Frame.Shared,
    pub fn init(ctx: *C.Context, truth: R.Truth, config: core.pcs.PcsConfig, binding: ?Frame.Binding, public: Public, witness: *const V.Proof) !Statement {
        try Catalog.validate(truth);
        var frame = Frame.Frame.init(ctx);
        const ordinal = try frame.guessU32(public.ordinal);
        const first = try frame.guessU32(truth.first());
        const calls = try frame.guessU32(truth.count());
        const statement = try frame.guessDigest(public.statement);
        const manifest = try frame.guessDigest(public.manifest);
        try frame.free_words.appendSlice(ctx.scratch(), &witness.commitments[1].words);
        const claim = try frame.guessOm(public.claim);
        if (frame.free_words.items.len != Words.count) return error.InvalidTruthLeafPublicFrame;
        const trusted_fixed = if (binding) |fixed| fixed.root else truth.key().root;
        try Frame.requireDigest(ctx, witness.commitments[0], trusted_fixed);
        return .{ .truth = truth, .config = config, .binding = binding, .frame = frame, .ordinal = ordinal.word, .first_id = first.base, .calls = calls.base, .statement = statement, .manifest = manifest, .claim = claim, .shared = try Frame.drawShared(ctx, manifest) };
    }
    pub fn mixPublic(self: *const Statement, ctx: *C.Context, channel: *C.Channel) !void {
        try Frame.mixWorkerBegin(ctx, channel, self.config, .delegation, self.ordinal, self.statement, self.binding);
    }
    pub fn nTreesBeforeChallenges(_: *const Statement) usize {
        return 2;
    }
    pub fn drawChallenges(_: *const Statement, ctx: *C.Context, channel: *C.Channel) !F {
        var adapter = Frame.Draw{ .ctx = ctx, .channel = channel };
        const bytes = Worker.drawLocal(&adapter);
        try adapter.finish();
        return bytes;
    }
    pub fn mixClaims(self: *const Statement, ctx: *C.Context, channel: *C.Channel) !void {
        try Frame.mixManifestAndClaims(ctx, channel, self.manifest, &.{self.claim});
    }
    pub fn evalComposition(self: *const Statement, ctx: *C.Context, point: V.Point, samples: []const []const []const F, alpha: F, bytes: F) !F {
        const role = roleFor(self.truth);
        const desc = try Catalog.descriptor(self.truth);
        const a = ctx.scratch();
        const fixed = try a.alloc(F, desc.shape.fixed);
        const main = try a.alloc(F, desc.shape.main);
        const prior = try a.alloc(F, desc.shape.main);
        @memset(prior, F.zero());
        const inter = try a.alloc(F, desc.shape.inter);
        const prev_inter = try a.alloc(F, desc.shape.inter);
        @memset(prev_inter, F.zero());
        for (fixed, samples[0]) |*v, s| v.* = s[0];
        for (main, samples[1], 0..) |*v, s, col| {
            v.* = s[0];
            if (role.previousMain(col)) prior[col] = s[1];
        }
        for (inter, samples[2], 0..) |*v, s, col| {
            v.* = s[0];
            if (role.previousInter(col)) prev_inter[col] = s[1];
        }
        var acc = A.evaluation.lane.PointAccumulator(F).init(alpha);
        var sink = A.evaluation.SinkFor(F){ .accumulator = &acc, .scale = try A.geometry.denominatorInverseFor(F, .{ .x = point.x, .y = point.y }, desc.log_size, desc.log_size) };
        const span = A.evaluation.CallSpanFor(F){ .first_id = self.first_id, .calls = self.calls, .nonempty = F.one() };
        try role.emitMainWithSpan(F, fixed, main, prior, span, &sink);
        try role.emitGlobalWithParameters(F, fixed, main, inter, prev_inter, .{ .span = span, .wire = self.shared.wire, .bytes = bytes, .claim = self.claim }, &sink);
        if (sink.count != desc.nConstraints()) return error.InvalidTruthLeafConstraintCount;
        return acc.finalize();
    }
};
pub const Leaf = struct { statement: Statement, verified: V.Verified, output: C.Hash };
/// Caller must activate the lane and independently admit the geometry/fixed
/// authority. This emits a graph; it does not prove/fold or accept an execution.
pub fn build(ctx: *C.Context, truth: R.Truth, config: core.pcs.PcsConfig, binding: ?Frame.Binding, public: Public, values: *const V.Captured) !Leaf {
    const geometry = try shape(ctx.scratch(), truth, config);
    const witness = try V.proof.guess(ctx, values, &geometry);
    var statement = try Statement.init(ctx, truth, config, binding, public, &witness);
    const verified = try V.verify(ctx, &geometry, &witness, &statement);
    return .{ .statement = statement, .verified = verified, .output = try statement.frame.finish() };
}
/// Fresh native physical verification plus capture; no cross-worker closure.
pub fn capture(a: std.mem.Allocator, truth: R.Truth, expected: M.ExpectedWorker, pending: *const M.PendingManifest, config: core.pcs.PcsConfig, encoded: *const Worker.TruthEncoded, fixed: ?*const Fixed.Binding, out: *V.proof.NativeCapture) !W.Proof {
    if (encoded.claims.len != 1 or expected.kind != .delegation) return error.V3TruthClaims;
    var native = try W.decodePhysical(a, encoded.bytes);
    errdefer native.deinit(a);
    const roots = native.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.V3TruthRoots;
    try pending.checkPhysicalRoots(expected.ordinal, roots[0], roots[1]);
    var channel = if (fixed) |authority| authority.begin(config, expected) else W.begin(config, expected);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, config);
    defer receiver.deinit(a);
    const d = try Catalog.descriptor(truth);
    const widths = d.widths();
    for (0..2) |t| {
        const logs = try a.alloc(u32, widths[t]);
        defer a.free(logs);
        @memset(logs, d.log_size);
        try receiver.commit(a, roots[t], logs, &channel);
    }
    const bytes = Worker.drawLocal(&channel);
    var role = Role{ .truth = truth, .wire = pending.shared.wire, .bytes = bytes, .claim = encoded.claims[0] };
    W.mixManifestAndClaims(&channel, pending.digest, encoded.claims);
    const logs = try a.alloc(u32, widths[2]);
    defer a.free(logs);
    @memset(logs, d.log_size);
    try receiver.commit(a, roots[2], logs, &channel);
    try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, &.{role.asVerifierComponent()}, &channel, &receiver, &native, out);
    return native;
}

/// Inspect only root-authenticated words. Calling this on unauthenticated JSON
/// is not verification. The caller must close the returned Wire35 debt across
/// the complete independently admitted CPU/truth manifest.
pub fn checkStatement(words: []const u32, truth: R.Truth, expected: M.ExpectedWorker, manifest: [32]u8, main: [32]u8) !O {
    if (words.len != Words.count or expected.kind != .delegation or expected.local_instances != null or
        words[Words.ordinal] != expected.ordinal or words[Words.first_id] != truth.first() or words[Words.calls] != truth.count()) return error.TruthLeafStatementMismatch;
    for ([_][32]u8{ expected.statement, manifest, main }, 0..) |digest, d| for (0..8) |i| {
        if (words[3 + d * 8 + i] != std.mem.readInt(u32, digest[4 * i ..][0..4], .little)) return error.TruthLeafStatementMismatch;
    };
    var coordinates: [8]core.fields.m31.M31 = undefined;
    for (&coordinates, words[Words.claim..][0..8]) |*out, word| {
        if (word >= core.fields.m31.Modulus) return error.NoncanonicalTruthLeafClaim;
        out.* = core.fields.m31.M31.fromCanonical(word);
    }
    return O.fromM31Array(coordinates);
}
