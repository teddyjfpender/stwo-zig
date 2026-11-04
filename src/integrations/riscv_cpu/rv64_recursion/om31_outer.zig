//! Ordered fold of independently admitted native OM31 circuit proofs.
//! The digest binds child authority identities, child FIXED roots and public
//! outputs. Execution adjacency/manifest coverage remains the application
//! receiver's obligation.
//!
//! Fold message version 2 ("proof-independent fold topology"): the child
//! identity and the child FIXED (preprocessed) root are GUESSED, range-checked
//! u32 words instead of circuit constants. The same wires are (a) absorbed by
//! the child's in-circuit Fiat-Shamir transcript (identity in mixPublic, root
//! as commitments[0] via mixRoot) and (b) hashed into this fold's public output
//! digest. The receiver recomputes that digest from its independently rebuilt
//! child authorities (`expectedDigest`) and rejects any other output, so an
//! accepted fold binds both words to the trusted values except with a Blake2s
//! collision. The fold circuit therefore depends only on the child GEOMETRY
//! CLASS (bound AIR, row logs, FIXED column logs, output count), never on the
//! child proof or key values; see design/riscv-proving-stack/rv64-m3-topo-binding.md.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const V = @import("om31_native/mod.zig");
const C = V.common;
const F = V.F;
const Q = C.Q;
const M = core.fields.m31.M31;
const B = circuit.builder;
const Word = B.wrappers.U32Wrapper(C.Var);
const Eval = Outer.program.ForLane(F);
const List = circuit.common.component_list;
const A = @import("stwo_riscv_frontend").rv64_air;
const domain: u32 = 0x4f464c31;
/// Fold message version. 1 = constant child keys (proof-dependent topology);
/// 2 = digest-bound guessed child identity + FIXED root (class topology).
pub const version: u32 = 2;
pub const Child = struct {
    authority: *const Outer.prove.Authority,
    produced: *const Outer.prove.Produced,
    capture: *const Outer.prove.Capture,
};
pub const Graph = struct {
    ctx: C.Context,
    output_digest: [32]u8,
    pub fn deinit(self: *Graph) void {
        self.ctx.deinit();
        self.* = undefined;
    }
};
fn word(ctx: *C.Context, value: u32) !Word {
    return .newUnsafe(try ctx.constant(B.wrappers.u32Value(Q, value).get()));
}
fn digestWords(ctx: *C.Context, digest: [32]u8) ![8]Word {
    return (try B.blake.constantHash(Q, ctx, B.blake.hashValueFromDigest(Q, digest))).words;
}
fn shape(a: std.mem.Allocator, key: *const Outer.prove.Authority) !V.Shape {
    const logs = try a.alloc([]const u32, 4);
    const masks = try a.alloc([]const []const i32, 4);
    for (0..3) |t| logs[t] = try key.treeLogs(a, t);
    const composition = try a.alloc(u32, 16);
    @memset(composition, key.bound.max_evaluation_log_size - 1);
    logs[3] = composition;
    for (masks, logs) |*tree, sizes| {
        const columns = try a.alloc([]const i32, sizes.len);
        @memset(columns, &.{});
        tree.* = columns;
    }
    for (key.bound.components) |component| {
        for (component.preprocessed_indices) |idx| @constCast(masks[0])[idx] = &.{0};
        for (1..3) |t| {
            const span = try Outer.geometry.span(component, @intCast(t));
            const offsets = try Outer.geometry.offsets(a, component, @intCast(t));
            for (offsets, 0..) |offset, col| @constCast(masks[t])[span.start + col] = try a.dupe(i32, offset.items);
        }
    }
    for (@constCast(masks[3])) |*offset| offset.* = &.{0};
    const result = V.Shape{ .tree_column_log_sizes = logs, .mask_offsets = masks, .global_log = key.bound.max_evaluation_log_size - 1, .composition_log_split = 1, .pcs = try Outer.protocol.targetConfig() };
    try result.validate();
    return result;
}
const Statement = struct {
    key: *const Outer.prove.Authority,
    /// Guessed child identity words; also hashed into the fold digest.
    identity: [8]Word,
    outputs: []const C.Var,
    output_words: []const Word,
    claims: [List.N_COMPONENTS]F,
    challenges: *Challenges,
    const Challenges = struct { z: F, alpha: F };
    pub fn mixPublic(self: @This(), ctx: *C.Context, channel: *C.Channel) !void {
        try channel.mixConfig(ctx, try Outer.protocol.targetConfig());
        const marker = [_]Word{ try word(ctx, 0x434f4d38), try word(ctx, 1), try word(ctx, 8) };
        try channel.mixU32s(ctx, &marker);
        var profile: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(Outer.protocol.domainName(), &profile, .{});
        const profile_words = try digestWords(ctx, profile);
        try channel.mixU32s(ctx, &profile_words);
        const public = try ctx.scratch().alloc(Word, 9 + self.output_words.len);
        @memcpy(public[0..8], &self.identity);
        public[8] = try word(ctx, @intCast(self.outputs.len));
        @memcpy(public[9..], self.output_words);
        try channel.mixU32s(ctx, public);
    }
    pub fn nTreesBeforeChallenges(_: @This()) usize {
        return 2;
    }
    pub fn drawChallenges(self: @This(), ctx: *C.Context, channel: *C.Channel) !Challenges {
        self.challenges.* = .{ .z = try channel.draw(ctx), .alpha = try channel.draw(ctx) };
        return self.challenges.*;
    }
    fn outputTerm(ctx: *C.Context, words: []const Word, address: usize, challenges: Challenges) !F {
        var power = F.one();
        var denominator = F.zero();
        const prefix = [_]M{ M.fromCanonical(List.GATE_RELATION_ID), M.fromU64(address) };
        for (prefix) |coordinate| {
            denominator = denominator.add(power.mulM31(coordinate));
            power = power.mul(challenges.alpha);
        }
        for (words, 0..) |coordinate, i| {
            const base = try circuit.native_verifier.channel.wordToM31(Q, ctx, coordinate);
            denominator = denominator.add(power.mul(C.base(base)));
            if (i + 1 < words.len) power = power.mul(challenges.alpha);
        }
        return denominator.sub(challenges.z).inv();
    }
    pub fn mixClaims(self: @This(), ctx: *C.Context, channel: *C.Channel) !void {
        var sum = F.zero();
        for (self.claims) |claim| sum = sum.add(claim);
        for (0..self.outputs.len) |i| sum = sum.add(try outputTerm(ctx, self.output_words[4 * i ..][0..4], circuit.witness.trace.U_VAR_IDX + 1 + i, self.challenges.*));
        const u_words = try ctx.scratch().alloc(Word, 4);
        for (u_words, circuit.witness.trace.U_VALUE.toM31Array()) |*out, coordinate| out.* = try word(ctx, coordinate.v);
        sum = sum.add(try outputTerm(ctx, u_words, circuit.witness.trace.U_VAR_IDX, self.challenges.*));
        try C.eq(ctx, sum, F.zero());
        try channel.mixFelts(ctx, &self.claims);
    }
    const Read = struct {
        component: @import("stwo_cairo_frontend").witness.composition_bundle.Component,
        masks: []const []const []const F,
        offsets: [2][]std.ArrayList(i32),
        fn get(raw: *const anyopaque, tree: u8, col: u32, offset: i32) !F {
            const self: *const Read = @ptrCast(@alignCast(raw));
            if (tree == 0) {
                if (offset != 0 or col >= self.component.preprocessed_indices.len) return error.MissingOm31CircuitMask;
                const global = self.component.preprocessed_indices[col];
                if (global >= self.masks[0].len or self.masks[0][global].len != 1) return error.MissingOm31CircuitMask;
                return self.masks[0][global][0];
            }
            if (tree > 2 or col >= self.offsets[tree - 1].len) return error.MissingOm31CircuitMask;
            const span = try Outer.geometry.span(self.component, tree);
            const offsets = self.offsets[tree - 1][col].items;
            const global = span.start + col;
            if (global >= self.masks[tree].len or self.masks[tree][global].len != offsets.len) return error.MissingOm31CircuitMask;
            for (offsets, 0..) |wanted, i| if (offset == wanted) return self.masks[tree][global][i];
            return error.MissingOm31CircuitMask;
        }
    };
    pub fn evalComposition(self: @This(), ctx: *C.Context, point: V.Point, masks: []const []const []const F, randomness: F, challenges: Challenges) !F {
        const n = self.key.bound.total_constraints;
        const powers = try ctx.scratch().alloc(F, n);
        var power = F.one();
        for (powers, 0..) |*p, i| {
            p.* = power;
            if (i + 1 < powers.len) power = power.mul(randomness);
        }
        var result = F.zero();
        for (self.key.bound.components, self.claims) |component, claim| {
            const parameters = try Eval.extensionParameters(ctx.scratch(), &component, challenges.z, challenges.alpha, claim);
            const read = Read{ .component = component, .masks = masks, .offsets = .{ try Outer.geometry.offsets(ctx.scratch(), component, 1), try Outer.geometry.offsets(ctx.scratch(), component, 2) } };
            const inverse = try A.geometry.denominatorInverseFor(F, .{ .x = point.x, .y = point.y }, self.key.bound.max_evaluation_log_size - 1, component.trace_log_size);
            for (component.parts) |part| {
                const roots = try Eval.evaluate(ctx.scratch(), part.program, .{ .context = &read, .get = Read.get }, parameters);
                for (roots, 0..) |root, r| result = result.add(root.mul(inverse).mul(powers[n - 1 - component.random_coefficient_offset - part.rc_base - r]));
            }
        }
        return result;
    }
};

/// Largest fold arity (m3 uses 4; r1 is binary).
pub const max_arity = 4;
/// Binary folds keep the v2 message word `version` (byte-identical to the M3
/// baseline). Any other arity binds the child count into the version word,
/// `(arity << 8) | version`, so digests (and class keys) of different arities
/// can never share a message: 2 != 0x302 != 0x402, and the low byte still
/// names the v2 (guessed, digest-bound child key) semantics.
pub fn versionWord(arity: usize) !u32 {
    if (arity < 2 or arity > max_arity) return error.InvalidRecursiveFoldArity;
    return if (arity == 2) version else (@as(u32, @intCast(arity)) << 8) | version;
}
fn messageWords(a: std.mem.Allocator, children: []const Child) ![]u32 {
    var count: usize = 2;
    for (children) |child| count += 17 + 4 * child.produced.outputs.len;
    const words = try a.alloc(u32, count);
    errdefer a.free(words);
    words[0] = domain;
    words[1] = try versionWord(children.len);
    var at: usize = 2;
    for (children) |child| {
        if (child.produced.outputs.len != child.authority.pp.n_outputs) return error.InvalidOm31CircuitOutputCount;
        for (0..8) |i| words[at + i] = std.mem.readInt(u32, child.authority.identity[4 * i ..][0..4], .little);
        at += 8;
        const root = child.authority.fixedRoot();
        for (0..8) |i| words[at + i] = std.mem.readInt(u32, root[4 * i ..][0..4], .little);
        at += 8;
        words[at] = @intCast(child.produced.outputs.len);
        at += 1;
        for (child.produced.outputs) |output| for (output.toM31Array()) |coordinate| {
            words[at] = coordinate.v;
            at += 1;
        };
    }
    return words;
}
pub fn expectedDigest(children: []const Child) ![32]u8 {
    const a = std.heap.page_allocator;
    const words = try messageWords(a, children);
    defer a.free(words);
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    var bytes: [4]u8 = undefined;
    for (words) |w| {
        std.mem.writeInt(u32, &bytes, w, .little);
        h.update(&bytes);
    }
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return digest;
}
/// Geometry class of a v2 fold: every input that determines the fold circuit
/// topology (and hence its PP, FIXED root and authority identity). Child key
/// VALUES (identity, FIXED root) are excluded because v2 guesses them.
/// Host-only cache key; never enters a proof or transcript.
///
/// k-ary generalisation (M4 recsize port): the key hashes the fold's message
/// version word, `versionWord(children.len)`, which is `version` for binary
/// folds (so binary keys are unchanged) and binds the arity otherwise, then
/// each child's geometry in child order. Folds of different arity therefore
/// never share a class, and same-arity folds share one exactly when every
/// child position has the same geometry class.
pub fn classKey(children: []const Child) ![32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-om31-fold-class/v2\x00");
    h.update(Outer.protocol.domainName());
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, try versionWord(children.len), .little);
    h.update(&bytes);
    for (children) |child| {
        const key = child.authority;
        if (child.produced.outputs.len != key.pp.n_outputs) return error.InvalidOm31CircuitOutputCount;
        for (key.logs.toArray()) |log| {
            std.mem.writeInt(u32, &bytes, log, .little);
            h.update(&bytes);
        }
        for (key.fixed_logs) |log| {
            std.mem.writeInt(u32, &bytes, log, .little);
            h.update(&bytes);
        }
        // Full preprocessed layout (column id order + log), from which the
        // bound AIR's preprocessed_indices are derived. Honest PPs make this
        // a function of the row logs; hashing it keeps the key collision-free
        // by construction instead of by that derivation (checker hardening).
        for (key.layout.entries) |entry| {
            std.mem.writeInt(u32, &bytes, @intCast(entry.id.len), .little);
            h.update(&bytes);
            h.update(entry.id);
            std.mem.writeInt(u32, &bytes, entry.log_size, .little);
            h.update(&bytes);
        }
        std.mem.writeInt(u32, &bytes, @intCast(key.pp.n_outputs), .little);
        h.update(&bytes);
        std.mem.writeInt(u32, &bytes, @intCast(key.bound.total_constraints), .little);
        h.update(&bytes);
        std.mem.writeInt(u32, &bytes, @intCast(key.bound.max_evaluation_log_size), .little);
        h.update(&bytes);
    }
    return h.finalResult();
}
pub fn buildFold(a: std.mem.Allocator, children: []const Child) !Graph {
    return buildFoldMode(a, children, false);
}
pub fn buildFoldTraceOnly(a: std.mem.Allocator, children: []const Child) !Graph {
    return buildFoldMode(a, children, true);
}
fn buildFoldMode(a: std.mem.Allocator, children: []const Child, trace_only: bool) !Graph {
    const version_word = try versionWord(children.len);
    var ctx = if (trace_only) try C.Context.initTraceOnly(a, 8) else try C.Context.init(a, 8);
    errdefer ctx.deinit();
    ctx.assert_eq_on_eval = !trace_only;
    C.lane.begin(&ctx);
    defer C.lane.finish() catch {};
    var message: std.ArrayList(Word) = .empty;
    defer message.deinit(a);
    try message.appendSlice(a, &.{ try word(&ctx, domain), try word(&ctx, version_word) });
    for (children) |child| {
        try Outer.protocol.validateConfig(child.produced.proof.proof.commitment_scheme_proof.config);
        const geometry = try shape(ctx.scratch(), child.authority);
        // M6 diet-wire: the fold's child verifier may stop at a Merkle cap (profile constant; 0 = full paths).
        const captured = try V.proof.fromNativeCapped(ctx.scratch(), &child.produced.proof.proof, child.capture, &geometry, Outer.protocol.active().foldMerkleCapLog());
        const guessed = try V.proof.guess(&ctx, &captured, &geometry);
        // The cap shape is a profile constant (profiles DW-R6 b): never read it from the child proof.
        // `validateProof` (in guess) then pins every tree's cap to 2^capLogFor(height, cap_log).
        if (guessed.cap_log != Outer.protocol.active().foldMerkleCapLog()) return error.Om31FoldMerkleCapProfileMismatch;
        // v2: no constant child key. Guess the identity; the FIXED root is the
        // child's guessed commitments[0] wire. Both are digest-bound below.
        var identity: [8]Word = undefined;
        for (&identity, 0..) |*out, i| out.* = try B.wrappers.guessU32(Q, &ctx, B.wrappers.u32Value(Q, std.mem.readInt(u32, child.authority.identity[4 * i ..][0..4], .little)));
        const outputs = try ctx.scratch().alloc(C.Var, child.produced.outputs.len);
        for (outputs, child.produced.outputs) |*out, value| out.* = try ctx.guess(value);
        const output_words = try B.blake.unpackQm31sToU32Words(Q, &ctx, outputs);
        var claims: [List.N_COMPONENTS]F = undefined;
        for (&claims, child.produced.claims.toArray()) |*out, value| out.* = try F.guess(&ctx, value);
        var challenges: Statement.Challenges = undefined;
        _ = try V.verify(&ctx, &geometry, &guessed, Statement{ .key = child.authority, .identity = identity, .outputs = outputs, .output_words = output_words, .claims = claims, .challenges = &challenges });
        try message.appendSlice(a, &identity);
        try message.appendSlice(a, &guessed.commitments[0].words);
        try message.append(a, try word(&ctx, @intCast(outputs.len)));
        try message.appendSlice(a, output_words);
    }
    try C.lane.check();
    const digest = try B.blake.blake2sU32s(Q, &ctx, message.items, 4 * message.items.len);
    var outputs: [8]C.Var = undefined;
    for (&outputs, digest.words) |*out, w| out.* = w.get();
    try ctx.setOutputs(&outputs);
    // Native PCS verifier emits terminal arithmetic/transcript intermediates
    // that are intentionally unused; all asserted verification equalities and
    // guessed-input yield gates are retained, as in the native PCS fixtures.
    if (V.topology_fingerprint.enabled()) {
        var label: [64]u8 = undefined;
        V.topology_fingerprint.report(&ctx, try std.fmt.bufPrint(&label, "fold-{x}-{x}", .{ children[0].authority.identity[0..4], children[1].authority.identity[0..4] }), "pre_finalize");
    }
    try ctx.finalize(false);
    return .{ .ctx = ctx, .output_digest = try expectedDigest(children) };
}
