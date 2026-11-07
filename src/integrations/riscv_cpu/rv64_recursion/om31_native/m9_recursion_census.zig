//! M9 recursion-arch census (STWO_RV64_M9_RECURSION_ARCH prep; diagnostics only,
//! never proof authority). Builds the in-circuit verifier of ONE recursion
//! child (the exact `om31_outer.verifyChild` arithmetic: transcript, composition
//! at OODS, Merkle decommitment of the four trees, DEEP quotients, FRI) on a
//! synthetic, correctly shaped child proof in a trace-only context, and counts
//! raw component rows per verifier phase. Gate counts of a trace-only graph do
//! not depend on witness values, so the counts equal those of a real child of
//! the same geometry class and PCS profile.
//!
//! The per-phase verifier below mirrors `mod.zig` `verify`, `fri.zig`
//! `decommit` and `merkle.decommitTreesCapped` line by line, with snapshots
//! between phases; a test pins its totals to the production `V.verify` on the
//! same guessed proof (cap <= 5, the production limit). Variants beyond the
//! production profile (other caps, blowups, queries, fold steps, last-layer
//! degree, Merkle-node compression rounds) are what-if counts for M9.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const V = @import("mod.zig");
const C = V.common;
const F = V.F;
const Q = C.Q;
const O = C.O;
const M = core.fields.m31.M31;
const B = circuit.builder;
const native = circuit.native_verifier;
const merkle = native.merkle;
const helpers = native.fold_helpers;
const simd = B.simd;
const Point = circuit.stark_verifier.circle.Point;
const List = circuit.common.component_list;
const PPMod = circuit.common.preprocessed;
const Fin = circuit.common.finalize;
const Word = B.wrappers.U32Wrapper(C.Var);
const Base = B.wrappers.M31Wrapper(C.Var);
const A = @import("stwo_riscv_frontend").rv64_air;

/// Unpadded cells per raw row (fixed + main + 8-coordinate interaction
/// columns), the widths of `scripts/rv64_m6_diet_receipt.py` and the
/// fewer-leaves model (eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate).
pub const WIDTH = Rows{ .eq = 12, .qm31_ops = 28, .triple_xor = 73, .m31_to_u32 = 31, .blake_g_gate = 167 };

pub const Rows = struct {
    eq: u64 = 0,
    qm31_ops: u64 = 0,
    triple_xor: u64 = 0,
    m31_to_u32: u64 = 0,
    blake_g_gate: u64 = 0,
    pub fn of(ctx: *const C.Context) Rows {
        const view = PPMod.CircuitView.fromBuilder(&ctx.circuit);
        const raw = Fin.rawComponentSizes(view);
        return .{ .eq = raw.eq, .qm31_ops = raw.qm31_ops, .triple_xor = raw.triple_xor, .m31_to_u32 = raw.m31_to_u32, .blake_g_gate = raw.blake_g_gate };
    }
    pub fn sub(a: Rows, b: Rows) Rows {
        return .{ .eq = a.eq - b.eq, .qm31_ops = a.qm31_ops - b.qm31_ops, .triple_xor = a.triple_xor - b.triple_xor, .m31_to_u32 = a.m31_to_u32 - b.m31_to_u32, .blake_g_gate = a.blake_g_gate - b.blake_g_gate };
    }
    pub fn add(a: Rows, b: Rows) Rows {
        return .{ .eq = a.eq + b.eq, .qm31_ops = a.qm31_ops + b.qm31_ops, .triple_xor = a.triple_xor + b.triple_xor, .m31_to_u32 = a.m31_to_u32 + b.m31_to_u32, .blake_g_gate = a.blake_g_gate + b.blake_g_gate };
    }
    pub fn cells(self: Rows) u64 {
        return self.eq * WIDTH.eq + self.qm31_ops * WIDTH.qm31_ops + self.triple_xor * WIDTH.triple_xor + self.m31_to_u32 * WIDTH.m31_to_u32 + self.blake_g_gate * WIDTH.blake_g_gate;
    }
};

pub const Phase = enum {
    ingress, // guessed proof wires, identity, outputs, claims
    transcript, // channel absorb/draw before OODS, claims sum, sampled-value absorb, FRI roots, PoW, query bits
    composition, // AIR composition at the OODS point + reconstruction
    trace_leaf, // Merkle leaf hashes of the queried rows (trees 0..3)
    trace_path, // Merkle path nodes, cap check and cap selection (trees 0..3)
    deep, // DEEP quotient combination at every query
    fri_leaf, // FRI coset leaf hashes and in-coset node hashes
    fri_path, // FRI path nodes, cap checks
    fri_fold, // coset selection, twiddles, folding arithmetic, last layer
};
pub const N_PHASES = @typeInfo(Phase).@"enum".fields.len;

pub const Variant = struct {
    log_blowup: u32 = 1,
    n_queries: usize = 108,
    pow_bits: u32 = 20,
    fold_step: u32 = 4,
    log_last_layer: u32 = 0,
    /// Merkle cap log for trace trees and FRI layers (production m6/m7: 3).
    cap_log: u32 = 3,
    /// Commitment hash of the CHILD proof's Merkle trees and FRI layers
    /// (the Fiat-Shamir channel stays Blake2s): `blake2s` (production) or
    /// `blake3` (7-round compression, same G function; census-only gadget).
    hash: HashKind = .blake2s,
    /// FRI layer leaves hold the whole 2^fold_step coset (one leaf hash, no
    /// in-coset nodes) instead of LOG_PACKED_LEAF_SIZE = 2 packs.
    fri_coset_leaf: bool = false,
    /// Sibling circuits proven as ONE batch proof (shared trees, one FRI);
    /// the parent verifies it once. 1 = production (one proof per circuit).
    batch: usize = 1,
    pub fn config(self: Variant) !core.pcs.ForField(O).PcsConfig {
        var fri = try core.fri.ForField(O).FriConfig.init(self.log_last_layer, self.log_blowup, self.n_queries);
        fri.fold_step = self.fold_step;
        return .{ .pow_bits = self.pow_bits, .fri_config = fri };
    }
};

pub const HashKind = enum { blake2s, blake3 };
/// Commitment hash used by the phased decommitment (set by `measureChild`).
var active_hash: HashKind = .blake2s;

pub const Census = struct {
    phases: [N_PHASES]Rows = @splat(.{}),
    /// Hash invocations by kind (a leaf hash may span several compressions).
    trace_leaf_hashes: u64 = 0,
    trace_path_nodes: u64 = 0,
    fri_leaf_hashes: u64 = 0,
    fri_path_nodes: u64 = 0,
    lifting_log: u32 = 0,
    n_fri_layers: usize = 0,
    pub fn total(self: Census) Rows {
        var out = Rows{};
        for (self.phases) |p| out = out.add(p);
        return out;
    }
};

const Meter = struct {
    ctx: *C.Context,
    census: *Census,
    last: Rows,
    fn init(ctx: *C.Context, census: *Census) Meter {
        return .{ .ctx = ctx, .census = census, .last = Rows.of(ctx) };
    }
    fn mark(self: *Meter, phase: Phase) void {
        const now = Rows.of(self.ctx);
        const i = @intFromEnum(phase);
        self.census.phases[i] = self.census.phases[i].add(now.sub(self.last));
        self.last = now;
    }
};

/// A verifier-only child authority of the given padded component sizes,
/// exactly as `root_verify.VerifierKey.authority` rebuilds one.
pub const Child = struct {
    stub: PPMod.PreprocessedCircuit,
    key: Outer.prove.Authority,
    pub fn deinit(self: *Child) void {
        self.key.deinit();
    }
};
var empty_column: [0]M = .{};
pub fn childAuthority(a: std.mem.Allocator, out: *Child, padded: Fin.ComponentSizes, n_outputs: usize) !void {
    const layout = try PPMod.ColumnLayout.fromComponentSizes(padded);
    out.stub = .{ .columns = undefined, .first_permutation_row = 0, .n_outputs = n_outputs };
    for (&out.stub.columns, layout.entries) |*column, entry| column.* = .{ .id = entry.id, .values = &empty_column };
    out.key = try Outer.prove.Authority.initVerifier(a, &out.stub, layout, @splat(0));
}

/// `om31_outer.shape` with an explicit PCS config (the original reads the
/// process profile).
pub fn shape(a: std.mem.Allocator, key: *const Outer.prove.Authority, pcs: core.pcs.ForField(O).PcsConfig) !V.Shape {
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
    const result = V.Shape{ .tree_column_log_sizes = logs, .mask_offsets = masks, .global_log = key.bound.max_evaluation_log_size - 1, .composition_log_split = 1, .pcs = pcs };
    try result.validate();
    return result;
}

fn zeroHash(ctx: *C.Context) !C.Hash {
    return B.blake.guessHash(Q, ctx, B.blake.hashValueFromDigest(Q, @splat(0)));
}
fn hashes(ctx: *C.Context, n: usize) ![]const C.Hash {
    const out = try ctx.scratch().alloc(C.Hash, n);
    for (out) |*h| h.* = try zeroHash(ctx);
    return out;
}
fn felts(ctx: *C.Context, n: usize) ![]const F {
    const out = try ctx.scratch().alloc(F, n);
    for (out) |*v| v.* = try F.guess(ctx, O.zero());
    return out;
}
fn capLen(height: u32, cap_log: u32) usize {
    const cl = merkle.capLogFor(height, cap_log);
    return if (cl == 0) 0 else @as(usize, 1) << @intCast(cl);
}

/// A guessed child proof of `geometry` (all-zero values), in the wire order of
/// `proof.guessImpl`. Caps follow `validateProof` (every tree taller than the
/// cap carries one), without its production `cap_log <= 5` limit.
pub fn syntheticProof(ctx: *C.Context, geometry: *const V.Shape, cap_log: u32) !V.Proof {
    const a = ctx.scratch();
    const n_trees = geometry.nTrees();
    const nq = geometry.nQueries();
    const roots = try hashes(ctx, n_trees);
    const sampled = try a.alloc([]const []const F, n_trees);
    const queried = try a.alloc([]const []const Base, n_trees);
    const auth = try a.alloc([]const []const C.Hash, n_trees);
    for (0..n_trees) |t| {
        const columns = try a.alloc([]const F, geometry.nColumns(t));
        const base_columns = try a.alloc([]const Base, geometry.nColumns(t));
        for (columns, base_columns, 0..) |*samples, *bases, col| {
            samples.* = try felts(ctx, geometry.sampleCount(t, col));
            const b = try a.alloc(Base, nq);
            for (b) |*wire| wire.* = try B.wrappers.guessM31(Q, ctx, B.wrappers.m31Value(Q, M.zero()));
            bases.* = b;
        }
        sampled[t] = columns;
        queried[t] = base_columns;
        if (geometry.nColumns(t) == 0) {
            auth[t] = &.{};
        } else {
            const cl = merkle.capLogFor(geometry.treeHeight(t), cap_log);
            const paths = try a.alloc([]const C.Hash, nq);
            for (paths) |*p| p.* = try hashes(ctx, geometry.treeHeight(t) - cl);
            auth[t] = paths;
        }
    }
    const caps = try a.alloc([]const C.Hash, if (cap_log == 0) 0 else n_trees);
    for (caps, 0..) |*cap, t| cap.* = try hashes(ctx, if (geometry.nColumns(t) == 0) 0 else capLen(geometry.treeHeight(t), cap_log));
    var buffer: [64]u32 = undefined;
    const steps = geometry.foldSteps(&buffer);
    const layers = try a.alloc(V.proof.Layer, steps.len);
    var log = geometry.liftingLogSize();
    for (layers, steps) |*out, step| {
        log -= step;
        const cl = merkle.capLogFor(log, cap_log);
        const cosets = try a.alloc([]const F, nq);
        for (cosets) |*c| c.* = try felts(ctx, @as(usize, 1) << @intCast(step));
        const paths = try a.alloc([]const C.Hash, nq);
        for (paths) |*p| p.* = try hashes(ctx, log - cl);
        out.* = .{ .commitment = try zeroHash(ctx), .cosets = cosets, .auth_paths = paths, .cap = try hashes(ctx, capLen(log, cap_log)) };
    }
    const nonce = [2]Word{ try B.wrappers.guessU32(Q, ctx, B.wrappers.u32Value(Q, 0)), try B.wrappers.guessU32(Q, ctx, B.wrappers.u32Value(Q, 0)) };
    return .{ .cap_log = cap_log, .caps = caps, .commitments = roots, .sampled_values = sampled, .queried_values = queried, .auth_paths = auth, .pow_nonce = nonce, .layers = layers, .last_layer_coefs = try felts(ctx, geometry.nLastLayerCoefficients()) };
}

// ---------------------------------------------------------------------------
// The child statement: a copy of `om31_outer.Statement` (private there), with
// the PCS config passed in instead of read from the process profile.

fn word(ctx: *C.Context, value: u32) !Word {
    return .newUnsafe(try ctx.constant(B.wrappers.u32Value(Q, value).get()));
}
fn digestWords(ctx: *C.Context, digest: [32]u8) ![8]Word {
    return (try B.blake.constantHash(Q, ctx, B.blake.hashValueFromDigest(Q, digest))).words;
}
const Eval = Outer.program.ForLane(F);
pub const Statement = struct {
    key: *const Outer.prove.Authority,
    pcs: core.pcs.PcsConfig,
    identity: [8]Word,
    outputs: []const C.Var,
    output_words: []const Word,
    claims: [List.N_COMPONENTS]F,
    challenges: *Challenges,
    pub const Challenges = struct { z: F, alpha: F };
    pub fn mixPublic(self: @This(), ctx: *C.Context, channel: *C.Channel) !void {
        try channel.mixConfig(ctx, self.pcs);
        const marker = [_]Word{ try word(ctx, 0x434f4d38), try word(ctx, 1), try word(ctx, 8) };
        try channel.mixU32s(ctx, &marker);
        var profile: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash("stwo/circuit/native-om31/m9-recursion-census/lens-v1", &profile, .{});
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
            const b = try native.channel.wordToM31(Q, ctx, coordinate);
            denominator = denominator.add(power.mul(C.base(b)));
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

pub const Wires = struct { identity: [8]Word, outputs: []const C.Var, output_words: []const Word, claims: [List.N_COMPONENTS]F };
pub fn guessWires(ctx: *C.Context, n_outputs: usize) !Wires {
    var w: Wires = undefined;
    for (&w.identity) |*out| out.* = try B.wrappers.guessU32(Q, ctx, B.wrappers.u32Value(Q, 0));
    const outputs = try ctx.scratch().alloc(C.Var, n_outputs);
    for (outputs) |*out| out.* = try ctx.guess(Q.zero());
    w.outputs = outputs;
    w.output_words = try B.blake.unpackQm31sToU32Words(Q, ctx, outputs);
    for (&w.claims) |*out| out.* = try F.guess(ctx, O.zero());
    return w;
}

// ---------------------------------------------------------------------------
// Phased verifier: `mod.zig` `verify` with snapshots.

/// `mod.zig` `verify` with phase snapshots; identical gate emission order.
pub fn verifyPhased(ctx: *C.Context, geometry: *const V.Shape, witness: *const V.Proof, statement: anytype, census: *Census, coset_leaf: bool) !void {
    var meter = Meter.init(ctx, census);
    var channel = try C.Channel.init(ctx);
    try statement.mixPublic(ctx, &channel);
    const before = statement.nTreesBeforeChallenges();
    const composition_tree = geometry.compositionTree();
    for (witness.commitments[0..before]) |root| try channel.mixRoot(ctx, root);
    const challenges = try statement.drawChallenges(ctx, &channel);
    try statement.mixClaims(ctx, &channel);
    for (witness.commitments[before..composition_tree]) |root| try channel.mixRoot(ctx, root);
    const randomness = try channel.draw(ctx);
    try channel.mixRoot(ctx, witness.commitments[composition_tree]);
    const point = V.pointFromSeed(try channel.draw(ctx));
    meter.mark(.transcript);
    const actual = try statement.evalComposition(ctx, point, witness.sampled_values, randomness, challenges);
    try C.eq(ctx, actual, try V.reconstructComposition(ctx, witness.sampled_values[composition_tree], point, geometry.global_log, geometry.composition_log_split));
    meter.mark(.composition);
    var count: usize = 0;
    for (witness.sampled_values) |tree| for (tree) |column| {
        count += column.len;
    };
    const sampled = try ctx.scratch().alloc(F, count);
    var at: usize = 0;
    for (witness.sampled_values) |tree| for (tree) |column| {
        @memcpy(sampled[at..][0..column.len], column);
        at += column.len;
    };
    try channel.mixFelts(ctx, sampled);
    const alpha = try channel.draw(ctx);
    const alphas = try V.fri.commit(ctx, &channel, witness);
    try channel.raw.inner.pow(Q, ctx, geometry.pcs.pow_bits, witness.pow_nonce);
    const lifting = geometry.liftingLogSize();
    census.lifting_log = lifting;
    const drawn = try channel.raw.inner.drawQueryBits(Q, ctx, lifting, geometry.nQueries());
    const queries = try native.fri.queriesFromBits(Q, ctx, drawn, lifting);
    meter.mark(.transcript);
    const logs = try ctx.scratch().alloc([]const u32, geometry.nTrees());
    for (logs, 0..) |*out, tree| out.* = try geometry.extendedLogSizes(ctx.scratch(), tree);
    try decommitTreesPhased(ctx, &meter, logs, lifting, witness, queries.unpacked);
    const plan = try V.shape.SamplePlan.init(ctx.scratch(), geometry);
    const input = try V.deep.friInput(ctx, &plan, point, witness.sampled_values, alpha, queries.points, witness.queried_values);
    meter.mark(.deep);
    try friDecommitPhased(ctx, &meter, witness, lifting, geometry.pcs.fri_config, input, queries, alphas, coset_leaf);
    try C.lane.check();
    meter.mark(.fri_fold);
}

// ---------------------------------------------------------------------------
// Commitment hashing. Blake2s = the production gadgets (`merkle.zig`); the
// production cross-check pins it. Blake3 = standard 7-round compression with
// the BLAKE3 message permutation and flags, built from the same `blakeGGate`
// (BLAKE3's G is BLAKE2s' G: rotations 16, 12, 8, 7); chunk chaining and
// parent nodes as in the BLAKE3 tree mode. Census-only: gate counts are exact,
// values are never assigned (trace-only).

const blake3_iv = [8]u32{ 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };
const blake3_perm = [16]u8{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 };
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
fn blake3Compress(ctx: *C.Context, cv: [8]Word, block_in: [16]Word, counter: u64, block_len: u32, flags: u32) ![8]Word {
    var v: [16]Word = undefined;
    @memcpy(v[0..8], &cv);
    for (0..4) |i| v[8 + i] = try B.wrappers.constU32(Q, ctx, blake3_iv[i]);
    v[12] = try B.wrappers.constU32(Q, ctx, @truncate(counter));
    v[13] = try B.wrappers.constU32(Q, ctx, @truncate(counter >> 32));
    v[14] = try B.wrappers.constU32(Q, ctx, block_len);
    v[15] = try B.wrappers.constU32(Q, ctx, flags);
    var m = block_in;
    const columns = [8][4]usize{ .{ 0, 4, 8, 12 }, .{ 1, 5, 9, 13 }, .{ 2, 6, 10, 14 }, .{ 3, 7, 11, 15 }, .{ 0, 5, 10, 15 }, .{ 1, 6, 11, 12 }, .{ 2, 7, 8, 13 }, .{ 3, 4, 9, 14 } };
    for (0..7) |round| {
        for (columns, 0..) |idx, g| {
            const out = try B.blake.blakeGGate(Q, ctx, v[idx[0]], v[idx[1]], v[idx[2]], v[idx[3]], m[2 * g], m[2 * g + 1]);
            for (idx, out) |index, w| v[index] = w;
        }
        if (round + 1 < 7) {
            var next: [16]Word = undefined;
            for (&next, blake3_perm) |*dst, src| dst.* = m[src];
            m = next;
        }
    }
    const zero = try B.wrappers.constU32(Q, ctx, 0);
    var out: [8]Word = undefined;
    for (&out, 0..) |*w, i| w.* = try B.blake.tripleXor(Q, ctx, v[i], v[i + 8], zero);
    return out;
}
fn blake3Words(ctx: *C.Context, words: []const Word) !C.Hash {
    const zero = try B.wrappers.constU32(Q, ctx, 0);
    const chunk_words = 256;
    const n_chunks = @max(1, std.math.divCeil(usize, words.len, chunk_words) catch unreachable);
    var cvs = try ctx.scratch().alloc([8]Word, n_chunks);
    for (0..n_chunks) |c| {
        const chunk = words[@min(words.len, c * chunk_words)..@min(words.len, (c + 1) * chunk_words)];
        const n_blocks = @max(1, std.math.divCeil(usize, chunk.len, 16) catch unreachable);
        var cv: [8]Word = undefined;
        for (&cv, blake3_iv) |*w, iv| w.* = try B.wrappers.constU32(Q, ctx, iv);
        for (0..n_blocks) |b| {
            var block: [16]Word = @splat(zero);
            const part = chunk[@min(chunk.len, 16 * b)..@min(chunk.len, 16 * (b + 1))];
            @memcpy(block[0..part.len], part);
            var flags: u32 = 0;
            if (b == 0) flags |= CHUNK_START;
            if (b + 1 == n_blocks) flags |= CHUNK_END;
            if (n_chunks == 1 and b + 1 == n_blocks) flags |= ROOT;
            cv = try blake3Compress(ctx, cv, block, c, @intCast(4 * part.len), flags);
        }
        cvs[c] = cv;
    }
    var n = n_chunks;
    while (n > 1) {
        var i: usize = 0;
        var o: usize = 0;
        while (i < n) : (i += 2) {
            if (i + 1 == n) {
                cvs[o] = cvs[i];
            } else {
                var block: [16]Word = undefined;
                @memcpy(block[0..8], &cvs[i]);
                @memcpy(block[8..16], &cvs[i + 1]);
                var key: [8]Word = undefined;
                for (&key, blake3_iv) |*w, iv| w.* = try B.wrappers.constU32(Q, ctx, iv);
                cvs[o] = try blake3Compress(ctx, key, block, 0, 64, PARENT | (if (n <= 2) ROOT else 0));
            }
            o += 1;
        }
        n = o;
    }
    return .{ .words = cvs[0] };
}
fn leafWords(ctx: *C.Context, words: []const Word) !C.Hash {
    return switch (active_hash) {
        .blake2s => merkle.hashLeafWords(Q, ctx, words),
        .blake3 => blake3Words(ctx, words),
    };
}
fn leafM31s(ctx: *C.Context, values: []const Base) !C.Hash {
    const words = try ctx.scratch().alloc(Word, values.len);
    for (words, values) |*w, value| w.* = try B.blake.m31ToU32(Q, ctx, value.get());
    return leafWords(ctx, words);
}
fn leafQm31s(ctx: *C.Context, values: []const C.Var) !C.Hash {
    return leafWords(ctx, try B.blake.unpackQm31sToU32Words(Q, ctx, values));
}
fn leafRow(ctx: *C.Context, tree_values: []const []const Base, order: []const usize, q: usize) !C.Hash {
    const row = try ctx.scratch().alloc(Base, order.len);
    for (row, order) |*value, column| value.* = tree_values[column][q];
    return leafM31s(ctx, row);
}
fn node(ctx: *C.Context, left: C.Hash, right: C.Hash) !C.Hash {
    switch (active_hash) {
        .blake2s => return merkle.hashNode(Q, ctx, left, right),
        .blake3 => {
            var block: [16]Word = undefined;
            @memcpy(block[0..8], &left.words);
            @memcpy(block[8..], &right.words);
            var key: [8]Word = undefined;
            for (&key, blake3_iv) |*w, iv| w.* = try B.wrappers.constU32(Q, ctx, iv);
            return .{ .words = try blake3Compress(ctx, key, block, 0, 64, PARENT) };
        },
    }
}
fn merkleNode(ctx: *C.Context, n: C.Hash, sibling: C.Hash, bit: C.Var) !C.Hash {
    var left: C.Hash = undefined;
    var right: C.Hash = undefined;
    for (n.words, sibling.words, &left.words, &right.words) |a, b, *l, *r| {
        const flipped = try B.ops.condFlipU32(Q, ctx, bit, a, b);
        l.* = flipped[0];
        r.* = flipped[1];
    }
    return node(ctx, left, right);
}
fn verifyPath(ctx: *C.Context, leaf: C.Hash, bits: []const C.Var, siblings: []const C.Hash, root: C.Hash) !void {
    var n = leaf;
    for (bits, siblings) |bit, sibling| n = try merkleNode(ctx, n, sibling, bit);
    for (n.words, root.words) |x, y| try ctx.eq(x.get(), y.get());
}
fn verifyCap(ctx: *C.Context, cap: []const C.Hash, root: C.Hash) !void {
    const layer = try ctx.scratch().dupe(C.Hash, cap);
    var n = layer.len;
    while (n > 1) {
        n /= 2;
        for (0..n) |i| layer[i] = try node(ctx, layer[2 * i], layer[2 * i + 1]);
    }
    for (layer[0].words, root.words) |x, y| try ctx.eq(x.get(), y.get());
}
fn verifyPathToCap(ctx: *C.Context, leaf: C.Hash, bits: []const C.Var, siblings: []const C.Hash, cap: []const C.Hash) !void {
    var n = leaf;
    for (bits[0..siblings.len], siblings) |bit, sibling| n = try merkleNode(ctx, n, sibling, bit);
    const expected = try merkle.selectHash(Q, ctx, cap, bits[siblings.len..]);
    for (n.words, expected.words) |x, y| try ctx.eq(x.get(), y.get());
}

/// `merkle.decommitTreesCapped` (cap_log 0 = `decommitTrees`), split into
/// leaf hashing and path work.
fn decommitTreesPhased(ctx: *C.Context, meter: *Meter, log_sizes: []const []const u32, lifting_log: u32, witness: *const V.Proof, query_bits: []const []const C.Var) !void {
    const n_queries = if (query_bits.len == 0) 0 else query_bits[0].len;
    const scratch = ctx.scratch();
    const bits_for_query = try scratch.alloc(C.Var, lifting_log);
    for (log_sizes, witness.queried_values, witness.auth_paths, witness.commitments, 0..) |tree_logs, tree_values, tree_paths, root, t| {
        if (tree_logs.len == 0) continue;
        const height = merkle.treeHeight(tree_logs);
        const cl = merkle.capLogFor(height, witness.cap_log);
        const cap: []const C.Hash = if (witness.cap_log == 0) &.{} else witness.caps[t];
        if (cl != 0) {
            try verifyCap(ctx, cap, root);
            meter.census.trace_path_nodes += cap.len - 1;
        }
        meter.mark(.trace_path);
        const order = try merkle.columnPermutation(scratch, tree_logs);
        for (0..n_queries) |q| {
            const leaf = try leafRow(ctx, tree_values, order, q);
            meter.mark(.trace_leaf);
            meter.census.trace_leaf_hashes += 1;
            for (bits_for_query, query_bits) |*bit, column_bits| bit.* = column_bits[q];
            const position_bits = try merkle.treePositionBits(scratch, bits_for_query, height, lifting_log);
            if (tree_paths[q].len != height - cl) return error.ShapeMismatch;
            if (cl == 0) {
                try verifyPath(ctx, leaf, position_bits, tree_paths[q], root);
            } else {
                try verifyPathToCap(ctx, leaf, position_bits, tree_paths[q], cap);
            }
            meter.census.trace_path_nodes += tree_paths[q].len;
            meter.mark(.trace_path);
        }
    }
}

fn hashLeaf(ctx: *C.Context, values: []const F) !C.Hash {
    const halves = try ctx.scratch().alloc(C.Var, 2 * values.len);
    for (values, 0..) |v, i| {
        halves[2 * i] = v.c0.v;
        halves[2 * i + 1] = v.c1.v;
    }
    return leafQm31s(ctx, halves);
}
fn select(ctx: *C.Context, values: []const F, bits: []const C.Var) !F {
    const c0 = try ctx.scratch().alloc(C.Var, values.len);
    const c1 = try ctx.scratch().alloc(C.Var, values.len);
    for (values, c0, c1) |value, *x, *y| {
        x.* = value.c0.v;
        y.* = value.c1.v;
    }
    return F.wire(try B.select.selectByIndex(Q, ctx, c0, bits), try B.select.selectByIndex(Q, ctx, c1, bits));
}
fn fold(ctx: *C.Context, values: []const F, twiddles: []const []C.Var, alphas: []const F) !F {
    const v = try ctx.scratch().dupe(F, values);
    for (alphas, twiddles) |alpha, tw| for (tw, 0..) |t, i| {
        v[i] = v[2 * i].add(v[2 * i + 1]).add(alpha.mul(v[2 * i].sub(v[2 * i + 1]).mul(C.base(t))));
    };
    return v[0];
}
fn foldCoefficients(values: []const F, factors: []const F) F {
    if (values.len == 1) return values[0];
    const half = values.len / 2;
    return foldCoefficients(values[0..half], factors[1..]).add(foldCoefficients(values[half..], factors[1..]).mul(factors[0]));
}
fn evalLine(ctx: *C.Context, coefficients: []const F, x: F) !F {
    const factors = try ctx.scratch().alloc(F, std.math.log2_int(usize, coefficients.len));
    var p = x;
    for (factors) |*f| {
        f.* = p;
        p = C.doubleX(p);
    }
    return foldCoefficients(coefficients, factors);
}

/// `fri.zig` `decommit`, split into coset hashing, path and folding work.
fn friDecommitPhased(ctx: *C.Context, meter: *Meter, proof: *const V.Proof, lifting_log: u32, config: core.fri.FriConfig, input: []const F, queries: V.fri.Queries, alphas: []const F, coset_leaf: bool) !void {
    const a = ctx.scratch();
    const degree_log = lifting_log - config.log_blowup_factor;
    var step_buffer: [64]u32 = undefined;
    const steps = core.fri.allFoldSteps(degree_log - config.log_last_layer_degree_bound, config.fold_step, &step_buffer);
    if (steps.len != proof.layers.len) return error.ShapeMismatch;
    meter.census.n_fri_layers = steps.len;
    var values = try a.dupe(F, input);
    var bits = queries.unpacked;
    var packed_bits = queries.bits;
    var base_point: Point(simd.Simd) = undefined;
    var doublings: usize = 0;
    const query_bits = try a.alloc(C.Var, lifting_log);
    const alpha_powers = try a.alloc(F, config.fold_step);
    for (proof.layers, steps, 0..) |layer, step_u32, layer_index| {
        const step: usize = step_u32;
        const layer_log = bits.len;
        const size = @as(usize, 1) << @intCast(step);
        const coset_bits = helpers.splitOff(simd.Simd, &packed_bits, step);
        if (layer_index == 0) {
            base_point = try helpers.circleTranslateToBasePoint(Q, ctx, queries.points, coset_bits);
            doublings = step - 1;
        } else {
            const p = try circuit.stark_verifier.circle.repeatedDoublePointSimd(Q, ctx, base_point, doublings);
            base_point = try helpers.translateToBasePoint(Q, ctx, p, coset_bits);
            doublings = step;
        }
        const twiddles = if (layer_index == 0) try helpers.circleComputeTwiddlesFromBasePoint(Q, ctx, base_point, step) else try helpers.computeTwiddlesFromBasePoint(Q, ctx, base_point, step);
        const position = helpers.splitOff([]const C.Var, &bits, step);
        const pack = layer_log >= core.fri.LOG_PACKED_LEAF_SIZE and step > 1;
        const pack_log: usize = if (coset_leaf) step else core.fri.LOG_PACKED_LEAF_SIZE;
        const width: usize = if (coset_leaf) size else if (pack) 1 << core.fri.LOG_PACKED_LEAF_SIZE else 1;
        const nfolds = step - if (coset_leaf or pack) pack_log else 0;
        const leaves = try a.alloc(C.Hash, size / width);
        alpha_powers[0] = alphas[layer_index];
        for (alpha_powers[1..step], 0..) |*power, i| power.* = alpha_powers[i].square();
        const next = try a.alloc(F, queries.n_queries);
        const per_fold = try a.alloc([]C.Var, step);
        const cap_log: usize = if (layer.cap.len == 0) 0 else std.math.log2_int(usize, layer.cap.len);
        meter.mark(.fri_fold);
        if (cap_log != 0) {
            try verifyCap(ctx, layer.cap, layer.commitment);
            meter.census.fri_path_nodes += layer.cap.len - 1;
        }
        meter.mark(.fri_path);
        for (layer.cosets, layer.auth_paths, values, next, 0..) |coset, path, value, *out, q| {
            if (coset.len != size or path.len + cap_log != bits.len) return error.ShapeMismatch;
            for (position, query_bits[0..step]) |column, *bit| bit.* = column[q];
            try C.eq(ctx, value, try select(ctx, coset, query_bits[0..step]));
            meter.mark(.fri_fold);
            for (leaves, 0..) |*leaf, i| leaf.* = try hashLeaf(ctx, coset[i * width ..][0..width]);
            for (0..nfolds) |f| for (0..@as(usize, 1) << @intCast(nfolds - f - 1)) |i| {
                leaves[i] = try node(ctx, leaves[2 * i], leaves[2 * i + 1]);
                meter.census.fri_leaf_hashes += 1;
            };
            meter.census.fri_leaf_hashes += leaves.len;
            meter.mark(.fri_leaf);
            for (bits, query_bits[0..bits.len]) |column, *bit| bit.* = column[q];
            if (cap_log == 0) {
                try verifyPath(ctx, leaves[0], query_bits[0..bits.len], path, layer.commitment);
            } else {
                try verifyPathToCap(ctx, leaves[0], query_bits[0..bits.len], path, layer.cap);
            }
            meter.census.fri_path_nodes += path.len;
            meter.mark(.fri_path);
            for (per_fold, twiddles) |*dst, src| {
                dst.* = try a.alloc(C.Var, src.len);
                for (dst.*, src) |*t, packed_t| t.* = try simd.unpackIdx(Q, ctx, packed_t, q);
            }
            out.* = try fold(ctx, coset, per_fold, alpha_powers[0..step]);
            meter.mark(.fri_fold);
        }
        values = next;
    }
    if (bits.len != config.log_last_layer_degree_bound + config.log_blowup_factor) return error.ShapeMismatch;
    if (config.log_last_layer_degree_bound == 0) {
        for (values) |value| try C.eq(ctx, value, proof.last_layer_coefs[0]);
        return;
    }
    const last_point = try circuit.stark_verifier.circle.repeatedDoublePointSimd(Q, ctx, base_point, doublings);
    const xs = try simd.unpack(Q, ctx, last_point.x);
    for (values, xs) |value, x| try C.eq(ctx, value, try evalLine(ctx, proof.last_layer_coefs, C.base(x)));
}

pub const Result = struct { census: Census, total: Rows };

/// B sibling circuits of one class proven as ONE outer proof: trees 0..2 hold
/// the B copies' columns side by side (lifted, one path per query), one
/// composition tree (16 columns), one FRI. Census-only geometry.
pub fn batchShape(a: std.mem.Allocator, one: *const V.Shape, copies: usize) !V.Shape {
    const logs = try a.alloc([]const u32, one.nTrees());
    const masks = try a.alloc([]const []const i32, one.nTrees());
    for (0..one.nTrees()) |t| {
        if (t == one.compositionTree()) {
            logs[t] = one.tree_column_log_sizes[t];
            masks[t] = one.mask_offsets[t];
            continue;
        }
        const n = one.tree_column_log_sizes[t].len;
        const l = try a.alloc(u32, n * copies);
        const m = try a.alloc([]const i32, n * copies);
        for (0..copies) |i| {
            @memcpy(l[i * n ..][0..n], one.tree_column_log_sizes[t]);
            @memcpy(m[i * n ..][0..n], one.mask_offsets[t]);
        }
        logs[t] = l;
        masks[t] = m;
    }
    const result = V.Shape{ .tree_column_log_sizes = logs, .mask_offsets = masks, .global_log = one.global_log, .composition_log_split = one.composition_log_split, .pcs = one.pcs };
    try result.validate();
    return result;
}
/// The batch statement: every copy's public input and LogUp claim, one set of
/// challenges, the sum of the copies' compositions under one randomness.
const BatchStatement = struct {
    inner: []const Statement,
    widths: [3]usize,
    pub fn mixPublic(self: @This(), ctx: *C.Context, channel: *C.Channel) !void {
        for (self.inner) |s| try s.mixPublic(ctx, channel);
    }
    pub fn nTreesBeforeChallenges(_: @This()) usize {
        return 2;
    }
    pub fn drawChallenges(self: @This(), ctx: *C.Context, channel: *C.Channel) !Statement.Challenges {
        const c = try self.inner[0].drawChallenges(ctx, channel);
        for (self.inner[1..]) |s| s.challenges.* = c;
        return c;
    }
    pub fn mixClaims(self: @This(), ctx: *C.Context, channel: *C.Channel) !void {
        for (self.inner) |s| try s.mixClaims(ctx, channel);
    }
    pub fn evalComposition(self: @This(), ctx: *C.Context, point: V.Point, masks: []const []const []const F, randomness: F, challenges: Statement.Challenges) !F {
        var total = F.zero();
        for (self.inner, 0..) |s, i| {
            var view: [4][]const []const F = undefined;
            for (0..3) |t| view[t] = masks[t][i * self.widths[t] ..][0..self.widths[t]];
            view[3] = masks[3];
            total = total.add(try s.evalComposition(ctx, point, &view, randomness, challenges));
        }
        return total;
    }
};

/// One child verification (or one batch of `variant.batch` sibling children)
/// of a node with `padded` component sizes and `n_outputs` public outputs.
/// `production` additionally runs the unmodified `V.verify` on an identical
/// fresh graph and returns its rows (valid for blake2s, batch 1, no coset
/// leaves, cap_log <= 5).
pub fn measureChild(a: std.mem.Allocator, padded: Fin.ComponentSizes, n_outputs: usize, variant: Variant, production: ?*Rows) !Result {
    var child: Child = undefined;
    try childAuthority(a, &child, padded, n_outputs);
    defer child.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const one = try shape(arena.allocator(), &child.key, try variant.config());
    const geometry = if (variant.batch > 1) try batchShape(arena.allocator(), &one, variant.batch) else one;
    active_hash = variant.hash;
    defer active_hash = .blake2s;
    var result = Result{ .census = .{}, .total = .{} };
    {
        var ctx = try C.Context.initTraceOnly(a, 8);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        C.lane.begin(&ctx);
        defer C.lane.finish() catch {};
        const start = Rows.of(&ctx);
        const statements = try arena.allocator().alloc(Statement, variant.batch);
        const challenges = try arena.allocator().alloc(Statement.Challenges, variant.batch);
        for (statements, challenges) |*st, *ch| {
            const wires = try guessWires(&ctx, n_outputs);
            st.* = .{ .key = &child.key, .pcs = try variant.config(), .identity = wires.identity, .outputs = wires.outputs, .output_words = wires.output_words, .claims = wires.claims, .challenges = ch };
        }
        const guessed = try syntheticProof(&ctx, &geometry, variant.cap_log);
        result.census.phases[@intFromEnum(Phase.ingress)] = Rows.of(&ctx).sub(start);
        if (variant.batch > 1) {
            const widths = [3]usize{ one.tree_column_log_sizes[0].len, one.tree_column_log_sizes[1].len, one.tree_column_log_sizes[2].len };
            try verifyPhased(&ctx, &geometry, &guessed, BatchStatement{ .inner = statements, .widths = widths }, &result.census, variant.fri_coset_leaf);
        } else {
            try verifyPhased(&ctx, &geometry, &guessed, statements[0], &result.census, variant.fri_coset_leaf);
        }
        result.total = Rows.of(&ctx).sub(start);
    }
    if (production) |out| {
        if (variant.batch != 1 or variant.hash != .blake2s or variant.fri_coset_leaf) return error.NotAProductionVariant;
        var ctx = try C.Context.initTraceOnly(a, 8);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        C.lane.begin(&ctx);
        defer C.lane.finish() catch {};
        const start = Rows.of(&ctx);
        const wires = try guessWires(&ctx, n_outputs);
        const guessed = try syntheticProof(&ctx, &geometry, variant.cap_log);
        var challenges: Statement.Challenges = undefined;
        const statement = Statement{ .key = &child.key, .pcs = try variant.config(), .identity = wires.identity, .outputs = wires.outputs, .output_words = wires.output_words, .claims = wires.claims, .challenges = &challenges };
        _ = try V.verify(&ctx, &geometry, &guessed, statement);
        out.* = Rows.of(&ctx).sub(start);
    }
    return result;
}

/// Rows of one Merkle node under `kind` (the gadget the verifier uses).
pub fn nodeRowsFor(a: std.mem.Allocator, kind: HashKind) !Rows {
    var ctx = try C.Context.initTraceOnly(a, 8);
    defer ctx.deinit();
    ctx.assert_eq_on_eval = false;
    C.lane.begin(&ctx);
    defer C.lane.finish() catch {};
    active_hash = kind;
    defer active_hash = .blake2s;
    const l = try zeroHash(&ctx);
    const r = try zeroHash(&ctx);
    const before = Rows.of(&ctx);
    _ = try node(&ctx, l, r);
    return Rows.of(&ctx).sub(before);
}

/// Raw rows of one Blake2s compression (10 rounds x 8 G gates), measured.
pub fn gRowsPerCompression(a: std.mem.Allocator) !u64 {
    var ctx = try C.Context.initTraceOnly(a, 8);
    defer ctx.deinit();
    ctx.assert_eq_on_eval = false;
    C.lane.begin(&ctx);
    defer C.lane.finish() catch {};
    const l = try zeroHash(&ctx);
    const r = try zeroHash(&ctx);
    const before = Rows.of(&ctx);
    _ = try merkle.hashNode(Q, &ctx, l, r);
    return Rows.of(&ctx).sub(before).blake_g_gate;
}
pub fn nodeRows(a: std.mem.Allocator) !Rows {
    var ctx = try C.Context.initTraceOnly(a, 8);
    defer ctx.deinit();
    ctx.assert_eq_on_eval = false;
    C.lane.begin(&ctx);
    defer C.lane.finish() catch {};
    const l = try zeroHash(&ctx);
    const r = try zeroHash(&ctx);
    const bit = try ctx.guess(Q.zero());
    const before = Rows.of(&ctx);
    _ = try merkle.merkleNode(Q, &ctx, l, r, bit);
    return Rows.of(&ctx).sub(before);
}
