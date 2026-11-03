//! Classic OM31 Keccak truth: all three independently sized roles, original
//! constraint authority, local closure and exported global KIO claim. This is
//! a physical leaf; execution-wide manifest/coverage/KIO closure is external.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const V = @import("mod.zig");
const C = V.common;
const Frame = V.frame;
const R = @import("../../word16_global_execution/services/roster.zig");
const Wire = @import("../../word16_global_execution/services/wire.zig");
const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const Worker = @import("../../word16_global_execution/services/gkr_local/truth_worker.zig");
const M = @import("../../word16_global_execution/services/gkr_local/manifest.zig");
const Fixed = @import("../../word16_global_execution/services/gkr_local/fixed_authority.zig");
const Roles = @import("../../word16_global_execution/services/gkr_local/truth_components.zig");
const Role = @import("../../word16_global_execution/services/gkr_local/truth_role.zig");
const TF = @import("../../word16_global_execution/services/gkr_local/truth_fractions.zig");
const MP = @import("../../logup_gkr/mle_point.zig");
const O = C.O;
const F = C.F;
pub const Public = struct { ordinal: u32, statement: [32]u8, manifest: [32]u8, claims: [5]O };
pub const WORDS = 67;
pub fn statementWords(truth: R.Truth, public: Public, main: [32]u8) [WORDS]u32 {
    var words: [WORDS]u32 = undefined;
    words[0] = public.ordinal;
    words[1] = truth.first();
    words[2] = truth.count();
    for ([_][32]u8{ public.statement, public.manifest, main }, 0..) |digest, d| for (0..8) |i| {
        words[3 + 8 * d + i] = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    };
    for (public.claims, 0..) |claim, c| for (claim.toM31Array(), 0..) |coordinate, i| {
        words[27 + 8 * c + i] = coordinate.v;
    };
    return words;
}
fn descriptors(truth: R.Truth) ![3]Role.Shape {
    if (truth != .keccak) return error.UnsupportedClassicRecursiveTruth;
    return Roles.shapesForDeclaration(Wire.TruthDeclaration.from(truth));
}
pub fn shape(a: std.mem.Allocator, truth: R.Truth, config: core.pcs.PcsConfig) !V.Shape {
    const ds = try descriptors(truth);
    const logs = try a.alloc([]const u32, 4);
    const masks = try a.alloc([]const []const i32, 4);
    var global: u32 = 0;
    for (ds) |d| global = @max(global, d.log_size);
    for (0..3) |tree| {
        var count: usize = 0;
        for (ds) |d| count += d.widths()[tree];
        const sizes = try a.alloc(u32, count);
        const shifts = try a.alloc([]const i32, count);
        var at: usize = 0;
        for (ds) |d| for (0..d.widths()[tree]) |col| {
            sizes[at] = d.log_size;
            shifts[at] = d.shifts(tree, col);
            at += 1;
        };
        logs[tree] = sizes;
        masks[tree] = shifts;
    }
    const composition = try a.alloc(u32, 32);
    @memset(composition, global);
    logs[3] = composition;
    const current = [_]i32{0};
    const comp_masks = try a.alloc([]const i32, 32);
    @memset(comp_masks, &current);
    masks[3] = comp_masks;
    const result = V.Shape{ .tree_column_log_sizes = logs, .mask_offsets = masks, .global_log = global, .composition_log_split = 2, .pcs = config };
    try result.validate();
    return result;
}
pub const Statement = struct {
    truth: R.Truth,
    config: core.pcs.PcsConfig,
    binding: ?Frame.Binding,
    frame: Frame.Frame,
    ordinal: Frame.Word,
    first: F,
    calls: F,
    statement: Frame.Digest,
    manifest: Frame.Digest,
    claims: [5]F,
    shared: Frame.Shared,
    pub fn init(ctx: *C.Context, truth: R.Truth, config: core.pcs.PcsConfig, binding: ?Frame.Binding, public: Public, proof: *const V.Proof) !Statement {
        _ = try descriptors(truth);
        var frame = Frame.Frame.init(ctx);
        const ordinal = try frame.guessU32(public.ordinal);
        const first = try frame.guessU32(truth.first());
        const calls = try frame.guessU32(truth.count());
        const statement = try frame.guessDigest(public.statement);
        const manifest = try frame.guessDigest(public.manifest);
        try frame.free_words.appendSlice(ctx.scratch(), &proof.commitments[1].words);
        var claims: [5]F = undefined;
        for (&claims, public.claims) |*out, in| out.* = try frame.guessOm(in);
        try C.eq(ctx, claims[0].add(claims[1]).add(claims[2]), F.zero());
        try C.eq(ctx, claims[4], F.zero()); // Keccak exports KIO only.
        try Frame.requireDigest(ctx, proof.commitments[0], if (binding) |b| b.root else truth.key().root);
        return .{ .truth = truth, .config = config, .binding = binding, .frame = frame, .ordinal = ordinal.word, .first = first.base, .calls = calls.base, .statement = statement, .manifest = manifest, .claims = claims, .shared = try Frame.drawShared(ctx, manifest) };
    }
    pub fn mixPublic(self: *const Statement, ctx: *C.Context, ch: *C.Channel) !void {
        try Frame.mixWorkerBegin(ctx, ch, self.config, .keccak, self.ordinal, self.statement, self.binding);
    }
    pub fn nTreesBeforeChallenges(_: *const Statement) usize {
        return 2;
    }
    pub fn drawChallenges(_: *const Statement, ctx: *C.Context, ch: *C.Channel) !TF.ChallengesFor(F) {
        var draw = Frame.Draw{ .ctx = ctx, .channel = ch };
        const value = TF.ChallengesFor(F).draw(&draw);
        try draw.finish();
        return value;
    }
    pub fn mixClaims(self: *const Statement, ctx: *C.Context, ch: *C.Channel) !void {
        try Frame.mixManifestAndClaims(ctx, ch, self.manifest, &self.claims);
    }
    pub fn evalComposition(self: *const Statement, ctx: *C.Context, point: V.Point, samples: []const []const []const F, alpha: F, local: TF.ChallengesFor(F)) !F {
        const ds = try descriptors(self.truth);
        var global: u32 = 0;
        for (ds) |d| global = @max(global, d.log_size);
        var acc = A.evaluation.lane.PointAccumulator(F).init(alpha);
        var offsets: [3]usize = @splat(0);
        const workspace = try ctx.scratch().create(Role.Component.Workspace(F));
        for (ds, 0..) |d, index| {
            const local_point = try A.geometry.localPointFor(F, .{ .x = point.x, .y = point.y }, global, d.log_size);
            const step = core.poly.circle.canonic.CanonicCoset.new(d.log_size).coset().step;
            const last_anchor = try MP.evalIsFirstFor(F, core.poly.circle.canonic.CanonicCoset.new(d.log_size).coset(), local_point.add(.{ .x = F.fromBase(step.x), .y = F.fromBase(step.y) }));
            const Sampler = struct {
                values: []const []const []const F,
                offsets: [3]usize,
                descriptor: Role.Shape,
                last_value: F,
                pub fn last(s: @This()) !F {
                    return s.last_value;
                }
                pub fn get(s: @This(), tree: usize, col: usize, shift: i32) !F {
                    const shifts = s.descriptor.shifts(tree, col);
                    const position = std.mem.indexOfScalar(i32, shifts, shift) orelse return error.InvalidWideTruthMask;
                    if (s.values[tree][s.offsets[tree] + col].len != shifts.len) return error.InvalidWideTruthMask;
                    return s.values[tree][s.offsets[tree] + col][position];
                }
            };
            var sink = A.evaluation.SinkFor(F){ .accumulator = &acc, .scale = try A.geometry.denominatorInverseFor(F, .{ .x = point.x, .y = point.y }, global, d.log_size) };
            try Role.emitShape(d, null, F, Sampler{ .values = samples, .offsets = offsets, .descriptor = d, .last_value = last_anchor }, &sink, workspace, .{ .span = .{ .calls = if (index == 0) self.calls else F.zero(), .first_id = if (index == 0) self.first else F.one(), .nonempty = if (index == 0) F.one() else F.zero() }, .local = local, .kio = self.shared.kio, .wire = self.shared.wire, .claim = self.claims[index], .global_claim = if (index == 0) self.claims[3] else F.zero() });
            if (sink.count != d.nConstraints()) return error.WideTruthConstraintCount;
            for (d.widths(), 0..) |width, t| offsets[t] += width;
        }
        return acc.finalize();
    }
};
pub const Leaf = struct { statement: Statement, verified: V.Verified, output: C.Hash };
pub fn build(ctx: *C.Context, truth: R.Truth, config: core.pcs.PcsConfig, binding: ?Frame.Binding, public: Public, values: *const V.Captured) !Leaf {
    const geometry = try shape(ctx.scratch(), truth, config);
    const wires = try V.proof.guess(ctx, values, &geometry);
    var statement = try Statement.init(ctx, truth, config, binding, public, &wires);
    const verified = try V.verify(ctx, &geometry, &wires, &statement);
    return .{ .statement = statement, .verified = verified, .output = try statement.frame.finish() };
}
pub fn capture(a: std.mem.Allocator, truth: R.Truth, expected: M.ExpectedWorker, pending: *const M.PendingManifest, config: W.PcsConfig, encoded: *const Worker.TruthEncoded, fixed: ?*const Fixed.Binding, out: *V.proof.NativeCapture) !W.Proof {
    _ = try descriptors(truth);
    if (expected.kind != .keccak or encoded.claims.len != 5) return error.UnsupportedClassicRecursiveTruth;
    var proof = try W.decodePhysical(a, encoded.bytes);
    errdefer proof.deinit(a);
    try Worker.validateProofConfig(&proof, config);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.WideTruthRoots;
    try pending.checkPhysicalRoots(expected.ordinal, roots[0], roots[1]);
    var ch = if (fixed) |b| b.begin(config, expected) else W.begin(config, expected);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, config);
    defer receiver.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const geometry = try shape(arena.allocator(), truth, config);
    for (0..2) |t| try receiver.commit(a, roots[t], geometry.tree_column_log_sizes[t], &ch);
    const local = TF.ChallengesFor(O).draw(&ch);
    var components = try Roles.Components.init(truth, local, pending.shared, encoded.claims);
    W.mixManifestAndClaims(&ch, pending.digest, encoded.claims);
    try receiver.commit(a, roots[2], geometry.tree_column_log_sizes[2], &ch);
    try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, &components.verifiers(), &ch, &receiver, &proof, out);
    return proof;
}
pub fn checkStatement(words: []const u32, truth: R.Truth, expected: M.ExpectedWorker, manifest: [32]u8, main: [32]u8) !M.Claims {
    if (truth != .keccak or expected.kind != .keccak or words.len != WORDS or words[0] != expected.ordinal or words[1] != truth.first() or words[2] != truth.count()) return error.KeccakLeafStatementMismatch;
    for ([_][32]u8{ expected.statement, manifest, main }, 0..) |d, k| for (0..8) |i| {
        if (words[3 + 8 * k + i] != std.mem.readInt(u32, d[4 * i ..][0..4], .little)) return error.KeccakLeafStatementMismatch;
    };
    var claims: [5]O = undefined;
    for (&claims, 0..) |*claim, k| {
        var values: [8]core.fields.m31.M31 = undefined;
        for (&values, words[27 + 8 * k ..][0..8]) |*v, word| {
            if (word >= core.fields.m31.Modulus) return error.NoncanonicalKeccakLeafClaim;
            v.* = core.fields.m31.M31.fromCanonical(word);
        }
        claim.* = O.fromM31Array(values);
    }
    if (!claims[0].add(claims[1]).add(claims[2]).isZero() or !claims[4].isZero()) return error.UnclosedKeccakLeafLocalClaims;
    return .{ .ram = O.zero(), .kio = claims[3], .wire = O.zero() };
}
