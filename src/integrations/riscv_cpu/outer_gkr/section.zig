//! Outer LogUp-GKR proof section: CPU reference prover, CPU reference verifier (the receiver's
//! authority), strict wire codec. Profile `outer_gkr_om31_strict_v1` (profile.zig).
//!
//! Transcript (continues the outer proof's raw-Blake OM31 channel at the hook point):
//!   mixU32s(class.header())  ->  mixFelts([salt])  ->  batched LogUp-GKR (shared verifier_kernel)
//! Every GKR draw is STRICT: the eight raw words of the Blake draw must all be < 2p, otherwise the
//! section is rejected (never redrawn). Accepted draws equal the raw-mod OM31 channel's values, so
//! the existing CPU and CUDA provers are unchanged; the prover re-salts on the rare rejection
//! (probability <= 8 * 2^-31 per draw, about 2^-19 per leaf section).
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const P = @import("profile.zig");
const M31 = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const Raw = core.channel.raw_mod_m31;
pub const RawChannel = Raw.Om31Channel;
const L = engine.lookups;
pub const G = L.gkr_verifier.ForField(O);
pub const GP = L.gkr_prover.ForField(O);
const Fast = L.gkr_prover_fast.ForField(O);
pub const CpuStats = struct {
    build_ns: u64 = 0,
    sumcheck_ns: u64 = 0,
    peak_layer_bytes: u64 = 0,
    unit_instances: u64 = 0,
    unit_facts: u64 = 0,
};
const Poly = L.utils.UnivariatePoly(O);
const MleBase = L.mle.MleFor(O, M31);
const MleSecure = L.mle.MleFor(O, O);
pub const TWO_P: u32 = 2 * core.fields.m31.Modulus;
pub const MAX_SALT_ATTEMPTS: u32 = 64;

/// Native strict channel: same digest/draw arithmetic as `raw_mod_m31.Om31Channel`, plus the
/// rejection predicate. The verifier kernel's channel interface is infallible, so the rejection is
/// latched and checked by the caller before anything derived from the transcript is trusted.
pub const StrictChannel = struct {
    inner: RawChannel,
    rejected: bool = false,
    draws: u32 = 0,
    pub fn mixFelts(self: *StrictChannel, values: []const O) void {
        self.inner.mixFelts(values);
    }
    pub fn mixU32s(self: *StrictChannel, values: []const u32) void {
        self.inner.mixU32s(values);
    }
    pub fn drawSecureFelt(self: *StrictChannel) O {
        const words = self.inner.drawU32s();
        for (words) |w| if (w >= TWO_P) {
            self.rejected = true;
        };
        self.draws += 1;
        return O.fromM31Array(Raw.reduceWords(words));
    }
};
pub fn admissibleDraw(words: [8]u32) bool {
    for (words) |w| if (w >= TWO_P) return false;
    return true;
}

pub const Section = struct {
    class: *const P.Class,
    salt: O,
    proof: G.GkrBatchProof,
    pub fn deinit(self: *Section, a: std.mem.Allocator) void {
        self.proof.deinit(a);
        self.* = undefined;
    }
};

pub const VerifyError = error{
    OuterGkrShapeMismatch,
    OuterGkrDrawRejected,
    OuterGkrRootPole,
    OuterGkrClosureMismatch,
    OuterGkrTerminalMismatch,
    NonCanonicalOuterGkrWord,
    MalformedOuterGkrSection,
    OuterGkrClassMismatch,
};

/// Strict structural admission against the class constants (never inferred from the proof).
pub fn checkShape(class: *const P.Class, proof: *const G.GkrBatchProof) VerifyError!void {
    const layers = class.layers();
    if (proof.sumcheck_proofs.len != layers or proof.layer_masks_by_instance.len != class.instances.len or proof.output_claims_by_instance.len != class.instances.len)
        return error.OuterGkrShapeMismatch;
    for (proof.sumcheck_proofs, 0..) |sc, depth| {
        if (sc.round_polys.len != depth) return error.OuterGkrShapeMismatch;
        for (sc.round_polys) |poly| {
            const c = poly.coeffsSlice();
            if (c.len != P.COEFFICIENTS_PER_ROUND or c[P.COEFFICIENTS_PER_ROUND - 1].isZero()) return error.OuterGkrShapeMismatch;
        }
    }
    for (class.instances, proof.layer_masks_by_instance, proof.output_claims_by_instance) |inst, masks, roots| {
        if (masks.len != inst.variables() or roots.len != 2) return error.OuterGkrShapeMismatch;
        for (masks) |mask| if (mask.columns.len != 2) return error.OuterGkrShapeMismatch;
    }
}

pub fn mixHeader(channel: anytype, class: *const P.Class, salt: O) !void {
    var buf: [12 + P.MAX_INSTANCES]u32 = undefined;
    channel.mixU32s(try class.header(&buf));
    channel.mixFelts(&.{salt});
}

pub const Verified = struct {
    artifact: G.GkrArtifact,
    /// Sum over instances of n_root / d_root (each d_root checked nonzero). The outer verifier adds
    /// the classic components' claimed sums and the public bus term and requires zero.
    root_sum: O,
    draws: u32,
    pub fn deinit(self: *Verified, a: std.mem.Allocator) void {
        self.artifact.deinit(a);
    }
};

/// The CPU reference verifier. `channel` is the outer transcript at the hook point and is advanced
/// past the section only on success.
pub fn verify(a: std.mem.Allocator, channel: *RawChannel, section: *const Section) !Verified {
    try section.class.validate();
    try checkShape(section.class, &section.proof);
    var strict = StrictChannel{ .inner = channel.* };
    try mixHeader(&strict, section.class, section.salt);
    const gates = [_]G.Gate{.LogUp} ** P.MAX_INSTANCES;
    var artifact = G.partiallyVerifyBatch(a, gates[0..section.class.instances.len], &section.proof, &strict) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return err,
    };
    errdefer artifact.deinit(a);
    if (strict.rejected) return error.OuterGkrDrawRejected;
    for (artifact.n_variables_by_instance, section.class.instances) |n, inst| if (n != inst.variables()) return error.OuterGkrShapeMismatch;
    // V2 carry quotients require every row coordinate outside {0,1}. The
    // guard is receiver-derived from the actual transcript's final point.
    if (section.class.binding_version == .cyclic_eq_v2) {
        const MP = @import("../logup_gkr/mle_point.zig");
        for (section.class.instances) |inst| {
            _ = try MP.MleEvalPointFor(O).init(artifact.ood_point[artifact.ood_point.len - inst.row_log ..]);
        }
    }
    var root_sum = O.zero();
    for (section.proof.output_claims_by_instance) |root| {
        if (root[1].isZero()) return error.OuterGkrRootPole;
        root_sum = root_sum.add(root[0].mul(root[1].inv() catch return error.OuterGkrRootPole));
    }
    channel.* = strict.inner;
    return .{ .artifact = artifact, .root_sum = root_sum, .draws = strict.draws };
}

pub fn requireClosure(verified: *const Verified, external_sum: O) VerifyError!void {
    if (!verified.root_sum.add(external_sum).isZero()) return error.OuterGkrClosureMismatch;
}

/// Terminal binding (M02): the final claims must equal the authenticated input evaluations. In the
/// outer verifier these come from the eq/prefix binding columns through the outer PCS (OODS).
pub fn requireTerminal(verified: *const Verified, expected: []const [2]O) VerifyError!void {
    if (expected.len != verified.artifact.claims_to_verify_by_instance.len) return error.OuterGkrTerminalMismatch;
    for (verified.artifact.claims_to_verify_by_instance, expected) |claims, want| {
        if (claims.len != 2 or !claims[0].eql(want[0]) or !claims[1].eql(want[1])) return error.OuterGkrTerminalMismatch;
    }
}

// --------------------------------------------------------------------------------------------
// Deterministic synthetic inputs (identical generator in tests/cuda/rv64/outer_gkr_bench.cu).

pub const Rng = struct {
    s: u64,
    pub fn init(seed: u64, instance: usize) Rng {
        return .{ .s = seed ^ (0x9E3779B97F4A7C15 *% (@as(u64, instance) + 1)) };
    }
    pub fn next(self: *Rng) u64 {
        self.s +%= 0x9E3779B97F4A7C15;
        var z = self.s;
        z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
        z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
        return z ^ (z >> 31);
    }
    pub fn numerator(self: *Rng) u32 {
        return @intCast(self.next() % 7 + 1);
    }
    pub fn coordinate(self: *Rng) u32 {
        return @intCast((self.next() >> 32) % core.fields.m31.Modulus);
    }
};
pub const Inputs = struct {
    numerators: [][]M31,
    denominators: [][]O,
    pub fn deinit(self: *Inputs, a: std.mem.Allocator) void {
        for (self.numerators) |n| a.free(n);
        for (self.denominators) |d| a.free(d);
        a.free(self.numerators);
        a.free(self.denominators);
    }
};
/// Instance i, entry j: n = rng%7+1 (base), d = 8 coordinates rng>>32 % p. `balanced` rewrites
/// d[0][0] so that the total rational sum is zero (closure holds with no external term).
pub fn synthetic(a: std.mem.Allocator, class: *const P.Class, seed: u64, balanced: bool) !Inputs {
    const k = class.instances.len;
    var out = Inputs{ .numerators = try a.alloc([]M31, k), .denominators = try a.alloc([]O, k) };
    var made: usize = 0;
    errdefer {
        for (out.numerators[0..made], out.denominators[0..made]) |n, d| {
            a.free(n);
            a.free(d);
        }
        a.free(out.numerators);
        a.free(out.denominators);
    }
    for (class.instances, 0..) |inst, i| {
        const count = @as(usize, 1) << @intCast(inst.variables());
        const n = try a.alloc(M31, count);
        const d = a.alloc(O, count) catch |e| {
            a.free(n);
            return e;
        };
        var rng = Rng.init(seed, i);
        for (n, d) |*nv, *dv| {
            nv.* = M31.fromCanonical(rng.numerator());
            var c: [8]M31 = undefined;
            for (&c) |*x| x.* = M31.fromCanonical(rng.coordinate());
            dv.* = O.fromM31Array(c);
        }
        out.numerators[i] = n;
        out.denominators[i] = d;
        made += 1;
    }
    if (balanced) {
        var rest = O.zero();
        for (out.numerators, out.denominators, 0..) |n, d, i| for (n, d, 0..) |nv, dv, j| {
            if (i == 0 and j == 0) continue;
            rest = rest.add(O.fromBase(nv).mul(try dv.inv()));
        };
        // n00 / d00 = -rest  =>  d00 = n00 / (-rest).
        out.denominators[0][0] = O.fromBase(out.numerators[0][0]).mul(try rest.neg().inv());
    }
    return out;
}
pub fn terminalExpected(a: std.mem.Allocator, inputs: *const Inputs, verified: *const Verified) ![][2]O {
    const out = try a.alloc([2]O, inputs.numerators.len);
    errdefer a.free(out);
    for (out, inputs.numerators, inputs.denominators, 0..) |*e, n, d, i| {
        const nv = verified.artifact.n_variables_by_instance[i];
        const point = verified.artifact.ood_point[verified.artifact.ood_point.len - nv ..];
        e.* = .{ try (try MleBase.initBorrowed(n)).evalAtPoint(a, point), try (try MleSecure.initBorrowed(d)).evalAtPoint(a, point) };
    }
    return out;
}

/// CPU producer: clone-free packed traversal on the caller's bounded pool.
/// The independent reference remains available to differential tests. Neither
/// path mutates borrowed facts or changes the verifier/transcript construction.
pub fn proveCpu(a: std.mem.Allocator, channel: *const RawChannel, class: *const P.Class, inputs: *const Inputs) !Section {
    return proveCpuWithStats(a, channel, class, inputs, null);
}
pub fn proveCpuWithStats(a: std.mem.Allocator, channel: *const RawChannel, class: *const P.Class, inputs: *const Inputs, stats: ?*CpuStats) !Section {
    if (stats) |out| out.* = .{};
    return proveCpuImpl(true, a, channel, class, inputs, stats);
}
pub fn proveCpuReferenceForTesting(a: std.mem.Allocator, channel: *const RawChannel, class: *const P.Class, inputs: *const Inputs) !Section {
    if (!@import("builtin").is_test) return error.TestOnly;
    return proveCpuImpl(false, a, channel, class, inputs, null);
}
/// Checked property of the actual borrowed values, not a family declaration.
pub fn unitNumerators(values: []const M31) bool {
    comptime std.debug.assert(@sizeOf(M31) == @sizeOf(u32));
    const words: [*]const u32 = @ptrCast(values.ptr);
    return std.mem.allEqual(u32, words[0..values.len], 1);
}
fn proveCpuImpl(comptime optimized: bool, a: std.mem.Allocator, channel: *const RawChannel, class: *const P.Class, inputs: *const Inputs, stats: ?*CpuStats) !Section {
    try class.validate();
    if (inputs.numerators.len != class.instances.len or inputs.denominators.len != class.instances.len) return error.OuterGkrShapeMismatch;
    const Layer = if (optimized) Fast.Input else GP.Layer;
    const layers = try a.alloc(Layer, class.instances.len);
    defer a.free(layers);
    for (layers, class.instances, inputs.numerators, inputs.denominators) |*l, inst, n, d| {
        const count = @as(usize, 1) << @intCast(inst.variables());
        if (n.len != count or d.len != count) return error.OuterGkrShapeMismatch;
        // This is a checked specialization of the actual immutable facts,
        // never an assertion inferred from a producer tag or family name.
        // A unit MLE remains exactly one under every sumcheck fold, so the
        // existing singles kernel needs no numerator buffers or arithmetic.
        const unit = optimized and unitNumerators(n);
        l.* = if (optimized) .{ .num = if (unit) .ones else .{ .base = n }, .den = d, .owned = false } else .{ .LogUpMultiplicities = .{ .numerators = try MleBase.initBorrowed(n), .denominators = try MleSecure.initBorrowed(d) } };
        if (unit) if (stats) |out| {
            out.unit_instances += 1;
            out.unit_facts += count;
        };
    }
    const workers = if (engine.work_pool.currentScopedPool()) |pool| @min(engine.lookups.row_work.MAX_SHARDS, pool.availableWorkers()) else 1;
    var salt_value: u32 = 0;
    while (salt_value < MAX_SALT_ATTEMPTS) : (salt_value += 1) {
        const salt = O.fromBase(M31.fromCanonical(salt_value));
        var prover_channel = channel.*;
        try mixHeader(&prover_channel, class, salt);
        var attempt: Fast.Stats = .{};
        var result = if (optimized) try Fast.proveBatch(a, &prover_channel, layers, .{ .threads = @max(1, workers), .use_scoped_pool = true }, if (stats != null) &attempt else null) else try GP.proveBatch(a, &prover_channel, layers);
        if (stats) |out| {
            out.build_ns += attempt.build_ns;
            out.sumcheck_ns += attempt.sumcheck_ns;
            out.peak_layer_bytes = @max(out.peak_layer_bytes, attempt.peak_layer_bytes);
        }
        result.artifact.deinit(a);
        var section = Section{ .class = class, .salt = salt, .proof = result.proof };
        // Admission replay: strict draws and constant shape, exactly what the receiver runs.
        var replay = channel.*;
        if (verify(a, &replay, &section)) |v| {
            var owned = v;
            owned.deinit(a);
            return section;
        } else |err| switch (err) {
            error.OuterGkrDrawRejected, error.OuterGkrShapeMismatch, error.DegenerateEvalPoint => section.deinit(a),
            else => {
                section.deinit(a);
                return err;
            },
        }
    }
    return error.OuterGkrSaltExhausted;
}

// --------------------------------------------------------------------------------------------
// Wire codec (u32 little-endian words, canonical M31 coordinates only).
//   [MAGIC, VERSION, class_id, n_instances, n_layers] salt[8] roots[16 * n]
//   for depth in 0..L: rounds[depth][4 coefficients][8], masks[active][2 cols][2 sides][8]
// `active` = instances with variables >= L - depth, in class order (same as the CUDA readback).

pub fn wordCount(class: *const P.Class) usize {
    const l = class.layers();
    var n: usize = 5 + 8 + 16 * class.instances.len;
    for (0..l) |depth| {
        n += depth * 32;
        for (class.instances) |inst| n += if (inst.variables() >= l - depth) 32 else 0;
    }
    return n;
}
fn put(out: []u32, at: *usize, v: O) void {
    for (v.toM31Array()) |c| {
        out[at.*] = c.v;
        at.* += 1;
    }
}
fn take(words: []const u32, at: *usize) !O {
    if (at.* + 8 > words.len) return error.MalformedOuterGkrSection;
    var c: [8]M31 = undefined;
    for (&c) |*x| {
        const w = words[at.*];
        if (w >= core.fields.m31.Modulus) return error.NonCanonicalOuterGkrWord;
        x.* = M31.fromCanonical(w);
        at.* += 1;
    }
    return O.fromM31Array(c);
}
pub fn encode(a: std.mem.Allocator, section: *const Section) ![]u32 {
    const class = section.class;
    try checkShape(class, &section.proof);
    const l = class.layers();
    const out = try a.alloc(u32, wordCount(class));
    errdefer a.free(out);
    out[0..5].* = .{ P.MAGIC, class.version(), class.id, @intCast(class.instances.len), l };
    var at: usize = 5;
    put(out, &at, section.salt);
    for (section.proof.output_claims_by_instance) |root| for (root) |v| put(out, &at, v);
    for (0..l) |depth| {
        for (section.proof.sumcheck_proofs[depth].round_polys) |poly| for (poly.coeffsSlice()) |c| put(out, &at, c);
        for (class.instances, 0..) |inst, i| {
            const v = inst.variables();
            if (v < l - depth) continue;
            const mask = section.proof.layer_masks_by_instance[i][v - (l - depth)];
            for (mask.columns) |col| for (col) |x| put(out, &at, x);
        }
    }
    std.debug.assert(at == out.len);
    return out;
}
/// `expected` is the class the RECEIVER derives from the verified node's statement/VK (never from the
/// proof): the wire's class id must equal it, so an honest section of another class (e.g. the scaled
/// test class) is refused instead of being verified against its own, prover-chosen constants.
pub fn decode(a: std.mem.Allocator, expected: *const P.Class, words: []const u32) !Section {
    if (words.len < 5 or words[0] != P.MAGIC or words[1] != expected.version()) return error.MalformedOuterGkrSection;
    if (words[2] != expected.id) return error.OuterGkrClassMismatch;
    const class = expected;
    try class.validate();
    const l = class.layers();
    if (words[3] != class.instances.len or words[4] != l or words.len != wordCount(class)) return error.MalformedOuterGkrSection;
    var at: usize = 5;
    const salt = try take(words, &at);
    const k = class.instances.len;
    // Build with all-empty owned slices first so every error path can deinit uniformly.
    var proof = G.GkrBatchProof{ .sumcheck_proofs = try a.alloc(L.sumcheck.ForField(O).SumcheckProof, l), .layer_masks_by_instance = &.{}, .output_claims_by_instance = &.{} };
    for (proof.sumcheck_proofs) |*s| s.* = .{ .round_polys = &.{} };
    proof.layer_masks_by_instance = a.alloc([]G.GkrMask, k) catch |e| {
        a.free(proof.sumcheck_proofs);
        return e;
    };
    @memset(proof.layer_masks_by_instance, &.{});
    proof.output_claims_by_instance = a.alloc([]O, k) catch |e| {
        a.free(proof.sumcheck_proofs);
        a.free(proof.layer_masks_by_instance);
        return e;
    };
    @memset(proof.output_claims_by_instance, &.{});
    errdefer proof.deinit(a);
    for (class.instances, 0..) |inst, i| {
        proof.output_claims_by_instance[i] = try a.alloc(O, 2);
        for (proof.output_claims_by_instance[i]) |*v| v.* = try take(words, &at);
        proof.layer_masks_by_instance[i] = try a.alloc(G.GkrMask, inst.variables());
        for (proof.layer_masks_by_instance[i]) |*m| m.* = .{ .columns = &.{} };
    }
    for (0..l) |depth| {
        proof.sumcheck_proofs[depth].round_polys = try a.alloc(Poly, depth);
        for (proof.sumcheck_proofs[depth].round_polys) |*poly| poly.* = Poly.initOwned(&.{});
        for (proof.sumcheck_proofs[depth].round_polys) |*poly| {
            const coeffs = try a.alloc(O, P.COEFFICIENTS_PER_ROUND);
            poly.* = .{ .coeffs = coeffs, .len = coeffs.len, .owns_coeffs = true };
            for (coeffs) |*c| c.* = try take(words, &at);
        }
        for (class.instances, 0..) |inst, i| {
            const v = inst.variables();
            if (v < l - depth) continue;
            const cols = try a.alloc([2]O, 2);
            proof.layer_masks_by_instance[i][v - (l - depth)] = .{ .columns = cols };
            for (cols) |*col| for (col) |*x| {
                x.* = try take(words, &at);
            };
        }
    }
    if (at != words.len) return error.MalformedOuterGkrSection;
    var section = Section{ .class = class, .salt = salt, .proof = proof };
    try checkShape(class, &section.proof);
    return section;
}
pub fn sectionBytes(class: *const P.Class) usize {
    return 4 * wordCount(class);
}

/// The 9-word CUDA traversal seed (digest[8], draws) after the header and salt are mixed.
pub fn deviceSeed(channel: *const RawChannel, class: *const P.Class, salt: O) ![9]u32 {
    var c = channel.*;
    try mixHeader(&c, class, salt);
    var out: [9]u32 = undefined;
    for (0..8) |i| out[i] = std.mem.readInt(u32, c.inner.digest[4 * i ..][0..4], .little);
    out[8] = c.inner.n_draws;
    return out;
}
/// Bench/test starting transcript (in production: the outer channel at the hook point).
pub fn benchChannel() RawChannel {
    var c = RawChannel.init();
    c.mixU32s(&.{ 0x4f47_4b52, 0x42454e43 });
    return c;
}
