//! One Word16 services TRUTH proof as a statement of the in-circuit native
//! verifier. Only the SHA-256 family (`ethereum_services_v3`) is admitted
//! today; the other families need their own `evaluatePointFor` adapters and
//! are rejected up front.
//!
//! The transcript replays, call for call, the receiver in
//! `word16_global_execution/services/{protocol,execution}.zig`:
//!
//! 1. `beginTruth`: the PCS felt, the truth header, the program and image
//!    identities, the step budget, initial and final pc/registers, and the
//!    family geometry;
//! 2. the fixed and MAIN roots;
//! 3. `drawTruth`: the shared channel seeded by the manifest digest (RAM14,
//!    Keccak IO11 and Wire35 draws, in order), then the truth channel's own
//!    tag and manifest digest; SHA-256 uses only the shared Wire35 challenge;
//! 4. `mixFelts(claims)` with slots 1 and 2 as the constant zero (the
//!    receiver's `NonzeroAbsentServiceClaim` rule);
//! 5. the interaction root, then the generic native verifier; the
//!    composition value is the SHA-256 component's own `evaluatePointFor`
//!    over the circuit lane.
//!
//! Free (per-proof) words are guessed and hashed into the leaf's output
//! digest in the fixed order of `statementWords`; layout words (family,
//! log, widths, tags) are circuit constants. The fixed root is constrained
//! to the receiver's key root. The MAIN root and the Wire35 claim leave the
//! leaf through its statement words: the manifest entry and the global
//! Wire35 sum are closed by the root receiver (`checkStatement`).
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const H = A.crypto.sha256;
const S = A.crypto.secp256k1;
const G = @import("../word16_global_execution/protocol.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const T = @import("../word16_global_execution/services/types.zig");
const lane_mod = @import("circuit_lane.zig");
const leaf_statement = @import("leaf_statement.zig");
const geometry = A.geometry;
const E = A.evaluation;

const Q = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const builder = circuit.builder;
const Context = builder.Context(Q);
const Var = builder.Var;
const U32 = builder.wrappers.U32Wrapper(Var);
const Error = builder.context.Error;
const nv = circuit.native_verifier;
const NativeChannel = nv.channel.NativeChannel;
const Point = circuit.stark_verifier.circle.Point;
const Lane = lane_mod.Lane;
const VerifyError = nv.verify.VerifyError;

/// Statement word layout (offsets into `statementWords`).
pub const Words = struct {
    pub const ORDINAL = 0;
    pub const FIRST_ID = 1;
    pub const CALLS = 2;
    pub const PROGRAM_IDENTITY = 3;
    pub const IMAGE_IDENTITY = 11;
    pub const TOTAL_STEPS = 19;
    pub const MAX_TOTAL_STEPS = 21;
    pub const INITIAL_PC = 23;
    pub const INITIAL_REGISTERS = 25;
    pub const FINAL_PC = 89;
    pub const FINAL_REGISTERS = 91;
    pub const MANIFEST_DIGEST = 155;
    pub const CLAIM = 163;
    pub const MAIN_ROOT = 167;
    pub const COUNT = 175;
};

/// Everything the leaf proves about, as the native receiver sees it.
pub const Public = struct {
    family: T.Family,
    log: u32,
    ordinal: u32,
    first_id: u32,
    calls: u32,
    expected: G.Expected,
    manifest_digest: [32]u8,
    claims: [3]Q,

    pub fn fromTruth(truth: R.Truth, ordinal: usize, expected: G.Expected, manifest: *const G.Manifest, claims: [3]Q) !Public {
        const log = switch (truth) {
            .sha256 => |t| t.setup.log,
            else => return error.UnsupportedRecursiveServiceFamily,
        };
        return .{ .family = truth.family(), .log = log, .ordinal = @intCast(ordinal), .first_id = truth.first(), .calls = truth.count(), .expected = expected, .manifest_digest = manifest.digest, .claims = claims };
    }
};

fn digestWords(d: [32]u8) [8]u32 {
    var out: [8]u32 = undefined;
    for (&out, 0..) |*w, i| w.* = std.mem.readInt(u32, d[4 * i ..][0..4], .little);
    return out;
}

/// The native statement words: the exact preimage of the leaf's output
/// digest. `main_root` is the truth proof's MAIN commitment.
pub fn statementWords(public: Public, main_root: [32]u8) [Words.COUNT]u32 {
    var out: [Words.COUNT]u32 = undefined;
    out[Words.ORDINAL] = public.ordinal;
    out[Words.FIRST_ID] = public.first_id;
    out[Words.CALLS] = public.calls;
    out[Words.PROGRAM_IDENTITY..][0..8].* = digestWords(public.expected.program_identity);
    out[Words.IMAGE_IDENTITY..][0..8].* = digestWords(public.expected.admission.image_identity);
    const u64s = [_]u64{ public.expected.total_steps, public.expected.max_total_steps, public.expected.admission.initial_pc };
    for (u64s, 0..) |v, i| {
        out[Words.TOTAL_STEPS + 2 * i] = @truncate(v);
        out[Words.TOTAL_STEPS + 2 * i + 1] = @truncate(v >> 32);
    }
    for (public.expected.admission.initial_registers, 0..) |v, i| {
        out[Words.INITIAL_REGISTERS + 2 * i] = @truncate(v);
        out[Words.INITIAL_REGISTERS + 2 * i + 1] = @truncate(v >> 32);
    }
    out[Words.FINAL_PC] = @truncate(public.expected.final_pc);
    out[Words.FINAL_PC + 1] = @truncate(public.expected.final_pc >> 32);
    for (public.expected.final_registers, 0..) |v, i| {
        out[Words.FINAL_REGISTERS + 2 * i] = @truncate(v);
        out[Words.FINAL_REGISTERS + 2 * i + 1] = @truncate(v >> 32);
    }
    out[Words.MANIFEST_DIGEST..][0..8].* = digestWords(public.manifest_digest);
    for (public.claims[0].toM31Array(), 0..) |c, i| out[Words.CLAIM + i] = c.v;
    out[Words.MAIN_ROOT..][0..8].* = digestWords(main_root);
    return out;
}

/// Blake2s of the statement words, as the circuit's eight outputs encode it.
pub fn statementDigest(words: []const u32) [8]u32 {
    var hasher = std.crypto.hash.blake2.Blake2s256.init(.{});
    for (words) |w| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, w, .little);
        hasher.update(&bytes);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digestWords(digest);
}

/// The receiver's independently derived proof shape for a SHA-256 truth of
/// `log`: never read from the proof. Trees are FIXED/MAIN/INTERACTION at the
/// truth log, then the 2n composition tree (8 columns) at the global log.
/// MAIN ACTIVE and the second interaction batch are also sampled one row back.
pub fn sha256Shape(arena: std.mem.Allocator, log: u32, config: core.pcs.PcsConfig) !nv.Shape {
    if (log == 0 or log > @import("../word16_global_execution/sha256/roster.zig").MAX_LOG) return error.InvalidSha256Geometry;
    const widths = H.layout.widths();
    const split: u32 = 1;
    const composition_columns = core.verifier_types.compositionColumnCount(split, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidSha256Geometry;
    const tree_logs = try arena.alloc([]const u32, 4);
    const offsets = try arena.alloc([]const []const i32, 4);
    const current = [_]i32{0};
    const with_previous = [_]i32{ 0, -1 };
    for (0..3) |tree| {
        const logs = try arena.alloc(u32, widths[tree]);
        @memset(logs, log);
        tree_logs[tree] = logs;
        const masks = try arena.alloc([]const i32, widths[tree]);
        for (masks, 0..) |*m, c| m.* = if ((tree == 1 and c == H.layout.ACTIVE) or (tree == 2 and c >= 4)) &with_previous else &current;
        offsets[tree] = masks;
    }
    const composition_logs = try arena.alloc(u32, composition_columns);
    @memset(composition_logs, log);
    tree_logs[3] = composition_logs;
    const composition_offsets = try arena.alloc([]const i32, composition_columns);
    @memset(composition_offsets, &current);
    offsets[3] = composition_offsets;
    const shape = nv.Shape{ .tree_column_log_sizes = tree_logs, .mask_offsets = offsets, .global_log = log, .composition_log_split = split, .pcs = config };
    try shape.validate();
    return shape;
}

fn mapError(err: anyerror) VerifyError {
    std.log.err("rv64 services truth leaf statement: {s}", .{@errorName(err)});
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.EqFailedOnEval => error.EqFailedOnEval,
        error.TooManyVars => error.TooManyVars,
        else => error.ShapeMismatch,
    };
}

pub const Statement = struct {
    arena: std.mem.Allocator,
    public: Public,
    config: core.pcs.PcsConfig,
    /// Every free word in statement order (the output digest preimage).
    free: std.ArrayListUnmanaged(U32) = .empty,
    ordinal: ?U32 = null,
    first_id: ?Var = null,
    calls: ?Var = null,
    manifest: ?[8]U32 = null,
    claim: ?Var = null,

    pub const Challenges = struct { wire: S.equations.WireFor(Var) };

    pub fn init(arena: std.mem.Allocator, public: Public, config: core.pcs.PcsConfig) !Statement {
        if (public.family != .sha256) return error.UnsupportedRecursiveServiceFamily;
        return .{ .arena = arena, .public = public, .config = config };
    }

    /// A free u32 as the channel mixes it: two guessed 16-bit limbs.
    fn guessWord(ctx: *Context, value: u32) Error!struct { word: U32, m31: Var } {
        const lo = try ctx.guessU16(Q.fromU32Unchecked(value & 0xFFFF, 0, 0, 0));
        const hi = try ctx.guessU16(Q.fromU32Unchecked(value >> 16, 0, 0, 0));
        const i = try ctx.constant(Q.fromU32Unchecked(0, 1, 0, 0));
        const shift = try ctx.constant(Q.fromBase(M31.fromCanonical(1 << 16)));
        return .{ .word = .newUnsafe(try ctx.add(lo, try ctx.mul(hi, i))), .m31 = try ctx.add(lo, try ctx.mul(hi, shift)) };
    }
    fn free1(self: *Statement, ctx: *Context, value: u32) Error!struct { word: U32, m31: Var } {
        const out = try guessWord(ctx, value);
        try self.free.append(self.arena, out.word);
        return out;
    }
    fn freeWords(self: *Statement, ctx: *Context, values: []const u32) Error![]U32 {
        const out = try self.arena.alloc(U32, values.len);
        for (out, values) |*w, v| w.* = (try self.free1(ctx, v)).word;
        return out;
    }
    fn constWords(self: *Statement, ctx: *Context, values: []const u32) Error![]U32 {
        const out = try self.arena.alloc(U32, values.len);
        for (out, values) |*w, v| w.* = try builder.wrappers.constU32(Q, ctx, v);
        return out;
    }
    fn mixU64(self: *Statement, ctx: *Context, channel: *NativeChannel, value: u64) Error!void {
        const words = try self.freeWords(ctx, &.{ @truncate(value), @truncate(value >> 32) });
        try channel.mixU32s(Q, ctx, words);
    }

    pub fn mixPublic(self: *Statement, ctx: *Context, channel: *NativeChannel) VerifyError!void {
        self.mixPublicImpl(ctx, channel) catch |err| return mapError(err);
    }
    fn mixPublicImpl(self: *Statement, ctx: *Context, channel: *NativeChannel) !void {
        const p = self.public;
        const c = self.config;
        // `PcsConfig.mixInto`: one felt (pow, blowup, queries, last layer).
        try channel.mixFelts(Q, ctx, &.{try ctx.constant(Q.fromU32Unchecked(c.pow_bits, c.fri_config.log_blowup_factor, @intCast(c.fri_config.n_queries), c.fri_config.log_last_layer_degree_bound))});
        const ordinal = try self.free1(ctx, p.ordinal);
        const first = try self.free1(ctx, p.first_id);
        const calls = try self.free1(ctx, p.calls);
        self.ordinal = ordinal.word;
        self.first_id = first.m31;
        self.calls = calls.m31;
        const head = try self.constWords(ctx, &.{ 0x57534345, 1, 1 });
        const tail = try self.constWords(ctx, &.{ @intFromEnum(p.family), 3 });
        try channel.mixU32s(Q, ctx, &.{ head[0], head[1], head[2], ordinal.word, tail[0], first.word, calls.word, tail[1] });
        try channel.mixU32s(Q, ctx, try self.freeWords(ctx, &digestWords(p.expected.program_identity)));
        try channel.mixU32s(Q, ctx, try self.freeWords(ctx, &digestWords(p.expected.admission.image_identity)));
        try self.mixU64(ctx, channel, p.expected.total_steps);
        try self.mixU64(ctx, channel, p.expected.max_total_steps);
        try self.mixU64(ctx, channel, p.expected.admission.initial_pc);
        for (p.expected.admission.initial_registers) |x| try self.mixU64(ctx, channel, x);
        try self.mixU64(ctx, channel, p.expected.final_pc);
        for (p.expected.final_registers) |x| try self.mixU64(ctx, channel, x);
        try channel.mixU32s(Q, ctx, try self.constWords(ctx, &.{ 0x53484132, p.log, H.layout.FIXED, H.layout.MAIN, H.layout.INTERACTION, H.layout.CONSTRAINTS, 35, H.layout.PROGRAM_KIND }));
    }

    pub fn nTreesBeforeChallenges(_: *Statement) usize {
        return 2;
    }

    pub fn drawChallenges(self: *Statement, ctx: *Context, channel: *NativeChannel) VerifyError!Challenges {
        return self.drawImpl(ctx, channel) catch |err| return mapError(err);
    }
    fn drawImpl(self: *Statement, ctx: *Context, channel: *NativeChannel) !Challenges {
        const manifest_values = digestWords(self.public.manifest_digest);
        const manifest_words = try self.freeWords(ctx, &manifest_values);
        self.manifest = manifest_words[0..8].*;
        // `protocol.shared`: a fresh channel seeded only by the manifest.
        var shared = try NativeChannel.init(Q, ctx);
        try shared.mixU32s(Q, ctx, try self.constWords(ctx, &.{ 0x5753434d, 1 }));
        try shared.mixU32s(Q, ctx, manifest_words);
        try shared.mixU32s(Q, ctx, try self.constWords(ctx, &.{ 0x52414d31, 14 }));
        for (0..15) |_| _ = try shared.drawSecureFelt(Q, ctx);
        try shared.mixU32s(Q, ctx, try self.constWords(ctx, &.{ 0x4b494f31, 11 }));
        for (0..1 + A.crypto.keccak.layout.IO_ARITY) |_| _ = try shared.drawSecureFelt(Q, ctx);
        try shared.mixU32s(Q, ctx, try self.constWords(ctx, &.{ 0x53574952, 35 }));
        try shared.mixU32s(Q, ctx, try self.constWords(ctx, &.{0x53575031}));
        var wire: S.equations.WireFor(Var) = undefined;
        wire.offset = try shared.drawSecureFelt(Q, ctx);
        for (&wire.coefficients) |*v| v.* = try shared.drawSecureFelt(Q, ctx);
        // `protocol.drawTruth` on the proof's own channel.
        const tag = try self.constWords(ctx, &.{ 0x57534332, 1, 1, @intFromEnum(self.public.family) });
        try channel.mixU32s(Q, ctx, &.{ tag[0], tag[1], tag[2], self.ordinal.?, tag[3] });
        try channel.mixU32s(Q, ctx, manifest_words);
        return .{ .wire = wire };
    }

    pub fn mixClaims(self: *Statement, ctx: *Context, channel: *NativeChannel) VerifyError!void {
        self.mixClaimsImpl(ctx, channel) catch |err| return mapError(err);
    }
    fn mixClaimsImpl(self: *Statement, ctx: *Context, channel: *NativeChannel) !void {
        const claim = try ctx.guess(self.public.claims[0]);
        self.claim = claim;
        // `mixFelts([claim, 0, 0])`; the canonical limbs of the live claim
        // are both what the channel absorbs and what the statement reveals.
        const limbs = try builder.blake.unpackQm31sToU32Words(Q, ctx, &.{claim});
        try self.free.appendSlice(self.arena, limbs);
        const zeros = try builder.blake.unpackQm31sToU32Words(Q, ctx, &.{ ctx.zero(), ctx.zero() });
        const words = try self.arena.alloc(U32, 12);
        @memcpy(words[0..4], limbs);
        @memcpy(words[4..], zeros);
        try channel.mixU32s(Q, ctx, words);
    }

    pub fn evalComposition(self: *Statement, ctx: *Context, oods: Point(Var), sampled: []const []const []const Var, randomness: Var, challenges: Challenges) VerifyError!Var {
        const component = H.component.Component{ .log_size = self.public.log, .public = .{ .calls = self.public.calls, .first_id = self.public.first_id }, .claim = self.public.claims[0], .wire = undefined };
        var wire: S.equations.WireFor(Lane) = undefined;
        wire.offset = Lane.wire(challenges.wire.offset);
        for (&wire.coefficients, challenges.wire.coefficients) |*w, v| w.* = Lane.wire(v);
        lane_mod.begin(ctx);
        var accumulator = A.lane.PointAccumulator(Lane).init(Lane.wire(randomness));
        var sink = E.SinkFor(Lane){ .accumulator = &accumulator };
        const result = component.evaluatePointFor(Lane, .{ .x = Lane.wire(oods.x), .y = Lane.wire(oods.y) }, self.public.log, leaf_statement.Masks{ .sampled = sampled }, .{ .calls = Lane.wire(self.calls.?), .first_id = Lane.wire(self.first_id.?), .nonempty = Lane.one() }, Lane.wire(self.claim.?), wire, &sink);
        lane_mod.finish() catch |err| return mapError(err);
        result catch |err| return mapError(err);
        return accumulator.finalize().v;
    }

    /// After `verify`: reveal the MAIN root and bind the output digest.
    pub fn finish(self: *Statement, ctx: *Context, main_root: builder.blake.HashValue(Var)) !builder.blake.HashValue(Var) {
        try self.free.appendSlice(self.arena, &main_root.words);
        if (self.free.items.len != Words.COUNT) return error.InvalidServicesTruthStatement;
        const hash = try builder.blake.blake2sU32s(Q, ctx, self.free.items, 4 * self.free.items.len);
        var outputs: [8]Var = undefined;
        for (&outputs, hash.words) |*out, word| out.* = word.get();
        ctx.setOutputs(&outputs) catch |err| switch (err) {
            error.OutputCountMismatch => unreachable,
            else => |e| return e,
        };
        return hash;
    }

    pub fn statementWordValues(self: *const Statement, ctx: *const Context) ![]u32 {
        const words = try self.arena.alloc(u32, self.free.items.len);
        for (words, self.free.items) |*word, wire| word.* = builder.ivalue.unpackU32(Q, ctx.get(wire.get()));
        return words;
    }
};

/// Native verification with proof capture, exactly as `execution.verify`
/// checks one truth (roots against key and manifest, `beginTruth`, the two
/// stage-1 commitments, `drawTruth`, claims, interaction, core verifier).
pub const Capture = core.verifier.ProofCapture(G.T.P.Hasher);
pub const NativeVerified = struct {
    capture: Capture,
    channel: G.T.P.Channel,
    pub fn deinit(self: *NativeVerified, a: std.mem.Allocator) void {
        self.capture.deinit(a);
    }
};
pub fn verifyNative(a: std.mem.Allocator, truth: R.Truth, ordinal: usize, n_cpus: usize, expected: G.Expected, manifest: *const G.Manifest, claims: [3]Q, proof: *const G.T.P.Proof) !NativeVerified {
    const pcs = &proof.commitment_scheme_proof;
    if (!std.meta.eql(pcs.config, truth.key().suite.config()) or pcs.commitments.items.len != 4) return error.CombinedPcsSuiteMismatch;
    const roots = pcs.commitments.items;
    if (n_cpus + ordinal >= manifest.roots.len) return error.InvalidCombinedOrdinal;
    const entry = manifest.roots[n_cpus + ordinal];
    if (!std.mem.eql(u8, &roots[0], &truth.key().root) or !std.mem.eql(u8, &roots[0], &entry.fixed.bytes) or !std.mem.eql(u8, &roots[1], &entry.main.bytes)) return error.CombinedStage1Mismatch;
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(G.T.P.Hasher, G.T.P.MerkleChannel).init(a, truth.key().suite.config());
    defer verifier.deinit(a);
    var channel = G.T.P.Channel{};
    P.beginTruth(&channel, truth, expected, ordinal);
    for (0..2) |tree| {
        const logs = try truth.logs(a, tree);
        defer a.free(logs);
        try verifier.commit(a, roots[tree], logs, &channel);
    }
    const ch = try P.drawTruth(&channel, manifest, truth, ordinal);
    channel.mixFelts(&claims);
    const logs = try truth.logs(a, 2);
    defer a.free(logs);
    try verifier.commit(a, roots[2], logs, &channel);
    var components = try @import("../word16_global_execution/services/air_components.zig").TruthComponents.init(truth, ch, claims);
    var buffer: [3]core.air.components.Component = undefined;
    const handles = components.verifiers(&buffer);
    var out = NativeVerified{ .capture = undefined, .channel = undefined };
    try core.verifier.verifyBorrowedWithProofCapture(G.T.P.Hasher, G.T.P.MerkleChannel, a, handles, &channel, &verifier, proof, &out.capture);
    out.channel = channel;
    return out;
}

pub const Built = struct {
    statement: Statement,
    words: []u32,
    output: [8]u32,
    gate_counts: builder.context.GateCounts,
    n_vars: u32,
    valid: bool,
    channel_digest: [32]u8,
};

/// Builds the leaf circuit (value mode) for a natively captured truth proof.
/// `ctx` must be fresh (`N_RESERVED` outputs). The caller finalizes or pads.
pub fn build(arena: std.mem.Allocator, ctx: *Context, public: Public, key_root: [32]u8, config: core.pcs.PcsConfig, proof: *const G.T.P.Proof, capture: *const Capture) !Built {
    const shape = try sha256Shape(arena, public.log, config);
    const values = try nv.proof.fromNative(arena, G.T.P.Hasher, proof, capture, &shape);
    const wires = try nv.proof.guess(Q, ctx, &values);
    try @import("native_fixed_root.zig").enforce(ctx, wires.commitments[0], key_root);
    var statement = try Statement.init(arena, public, config);
    const outcome = try nv.verify.verify(Q, ctx, &shape, &wires, &statement);
    const hash = try statement.finish(ctx, wires.commitments[1]);
    var output: [8]u32 = undefined;
    for (&output, hash.words) |*o, w| o.* = builder.ivalue.unpackU32(Q, ctx.get(w.get()));
    return .{ .statement = statement, .words = try statement.statementWordValues(ctx), .output = output, .gate_counts = ctx.gate_counts, .n_vars = ctx.circuit.n_vars, .valid = try ctx.isCircuitValid(), .channel_digest = outcome.channel.debugDigest(ctx) };
}

/// Root-receiver side of one truth leaf: every revealed word must equal the
/// receiver's own expectation (roster span, `Expected`, manifest digest and
/// MAIN root of this manifest entry). Returns the revealed Wire35 claim for
/// the global sum, which the receiver must close to zero over all leaves.
pub fn checkStatement(words: []const u32, truth: R.Truth, ordinal: usize, n_cpus: usize, expected: G.Expected, manifest: *const G.Manifest) !Q {
    if (words.len != Words.COUNT) return error.InvalidServicesTruthStatement;
    if (n_cpus + ordinal >= manifest.roots.len) return error.InvalidCombinedOrdinal;
    try manifest.check(manifest.specs);
    var claim: [4]M31 = undefined;
    for (&claim, words[Words.CLAIM..][0..4]) |*c, w| {
        if (w >= core.fields.m31.Modulus) return error.NoncanonicalSecpClaim;
        c.* = M31.fromCanonical(w);
    }
    const q = Q.fromM31Array(claim);
    const public = try Public.fromTruth(truth, ordinal, expected, manifest, .{ q, Q.zero(), Q.zero() });
    const want = statementWords(public, manifest.roots[n_cpus + ordinal].main.bytes);
    if (!std.mem.eql(u32, words, &want)) return error.ServicesTruthStatementMismatch;
    // The spec of this entry is the receiver's own `beginTruth` digest.
    var channel = G.T.P.Channel{};
    P.beginTruth(&channel, truth, expected, ordinal);
    if (!std.mem.eql(u8, &channel.digestBytes(), &manifest.specs[n_cpus + ordinal])) return error.GlobalExecutionInventoryMismatch;
    return q;
}
