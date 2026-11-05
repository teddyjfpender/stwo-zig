//! Native LogUp-GKR v1 section (`rv64-m5-native-gkr/v1`): CPU reference prover, CPU reference verifier
//! (the native receiver's authority), binding-column reference and strict wire codec. Stream native-gkr.
//! Argument: design/riscv-proving-stack/rv64-native-gkr.md. Reuses the outer-gkr strict channel and the
//! shared engine GKR prover/verifier kernels unchanged (outer-gkr = recursion-side twin of this section).
//!
//! Transcript (continues the native proof's raw-Blake OM31 channel right after the MAIN commitment and
//! the stage-two shared draw, i.e. at the point where M4 draws its classic interaction elements):
//!   mixU32s(identity[8]) mixU32s(scope words) mixU32s(roster.header) mixFelts([salt])
//!   -> batched LogUp-GKR over the roster (strict draws)
//!   -> gamma, rho_g (strict) for the binding columns, then the INTER commitment (binding pairs only).
//! Closure: local roots sum to zero inside the proof (projective, poles refused); the ram/kio/wire roots
//! are summed per relation and EXPOSED as the proof's physical global claims, which the execution
//! receiver closes across all proofs of the block exactly like M4's classic claimed sums.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const R = @import("roster.zig");
const OS = @import("../../../outer_gkr/section.zig");
const M31 = core.fields.m31.M31;
const O = core.fields.om31.OM31;
pub const RawChannel = OS.RawChannel;
pub const StrictChannel = OS.StrictChannel;
const G = engine.lookups.gkr_verifier.ForField(O);
const GP = engine.lookups.gkr_prover.ForField(O);
const MleBase = engine.lookups.mle.MleFor(O, M31);
const MleSecure = engine.lookups.mle.MleFor(O, O);
const Poly = engine.lookups.utils.UnivariatePoly(O);

pub const VERSION_NAME = "rv64-m5-native-gkr/v1";
pub const IDENTITY_DOMAIN = "stwo/rv64/native-gkr/om31-strict-draw/lane-major/v1";
pub const MAGIC: u32 = 0x4b47564e; // "NVGK"
pub const VERSION: u32 = 1;
pub const COEFFICIENTS_PER_ROUND: usize = 4;
pub const MAX_SALT_ATTEMPTS: u32 = 64;

pub fn identityWords() [8]u32 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(IDENTITY_DOMAIN, &digest, .{});
    var out: [8]u32 = undefined;
    for (&out, 0..) |*w, i| w.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    return out;
}

/// Per-proof scope mixed before the roster: statement, FIXED root, MAIN root, ordinal and the 32-byte
/// shared-challenge seed (chi) from which RAM/KIO/Wire elements are drawn.
pub const Scope = struct {
    statement: [32]u8,
    fixed: [32]u8,
    main: [32]u8,
    shared: [32]u8,
    ordinal: u32,
    fn words(bytes: [32]u8) [8]u32 {
        var out: [8]u32 = undefined;
        for (&out, 0..) |*w, i| w.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
        return out;
    }
};

pub const Section = struct {
    salt: O,
    proof: G.GkrBatchProof,
    pub fn deinit(self: *Section, a: std.mem.Allocator) void {
        self.proof.deinit(a);
        self.* = undefined;
    }
};

pub fn mixHeader(a: std.mem.Allocator, channel: anytype, roster: *const R.Roster, scope: *const Scope, salt: O) !void {
    channel.mixU32s(&identityWords());
    channel.mixU32s(&.{ MAGIC, VERSION, scope.ordinal });
    for ([_][32]u8{ scope.statement, scope.fixed, scope.main, scope.shared }) |b| channel.mixU32s(&Scope.words(b));
    const header = try roster.header(a);
    defer a.free(header);
    channel.mixU32s(header);
    channel.mixFelts(&.{salt});
}

/// Strict structural admission against the roster (class constants, never inferred from the proof).
pub fn checkShape(roster: *const R.Roster, proof: *const G.GkrBatchProof) !void {
    const layers = roster.layers();
    if (proof.sumcheck_proofs.len != layers or proof.layer_masks_by_instance.len != roster.instances.len or proof.output_claims_by_instance.len != roster.instances.len)
        return error.NativeGkrShapeMismatch;
    for (proof.sumcheck_proofs, 0..) |sc, depth| {
        if (sc.round_polys.len != depth) return error.NativeGkrShapeMismatch;
        for (sc.round_polys) |poly| {
            const c = poly.coeffsSlice();
            if (c.len != COEFFICIENTS_PER_ROUND or c[COEFFICIENTS_PER_ROUND - 1].isZero()) return error.NativeGkrShapeMismatch;
        }
    }
    for (roster.instances, proof.layer_masks_by_instance, proof.output_claims_by_instance) |inst, masks, roots| {
        if (masks.len != inst.variables() or roots.len != 2) return error.NativeGkrShapeMismatch;
        for (masks) |mask| if (mask.columns.len != 2) return error.NativeGkrShapeMismatch;
    }
}

pub const GlobalClaims = struct {
    ram: O = O.zero(),
    kio: O = O.zero(),
    wire: O = O.zero(),
    pub fn at(self: *GlobalClaims, kind: R.Kind) *O {
        return switch (kind) {
            .ram => &self.ram,
            .kio => &self.kio,
            .wire => &self.wire,
            .local => unreachable,
        };
    }
};

pub const Verified = struct {
    artifact: G.GkrArtifact,
    global: GlobalClaims,
    draws: u32,
    pub fn deinit(self: *Verified, a: std.mem.Allocator) void {
        self.artifact.deinit(a);
    }
};

/// CPU reference verifier. `channel` is advanced past the section only on success. On success the
/// local relations are closed; `global` holds the per-relation physical claims the execution receiver
/// must close across proofs; the terminal claims still need the binding check (`requireBinding`).
pub fn verify(a: std.mem.Allocator, channel: *RawChannel, roster: *const R.Roster, scope: *const Scope, section: *const Section) !Verified {
    try roster.validate();
    try checkShape(roster, &section.proof);
    var strict = StrictChannel{ .inner = channel.* };
    try mixHeader(a, &strict, roster, scope, section.salt);
    var gates: [R.MAX_INSTANCES]G.Gate = undefined;
    @memset(gates[0..roster.instances.len], .LogUp);
    var artifact = try G.partiallyVerifyBatch(a, gates[0..roster.instances.len], &section.proof, &strict);
    errdefer artifact.deinit(a);
    if (strict.rejected) return error.NativeGkrDrawRejected;
    for (artifact.n_variables_by_instance, roster.instances) |n, inst| if (n != inst.variables()) return error.NativeGkrShapeMismatch;
    // Local closure: projective sum n/d over local roots, every root denominator nonzero.
    var ln = O.zero();
    var ld = O.one();
    var global = GlobalClaims{};
    for (roster.instances, section.proof.output_claims_by_instance) |inst, root| {
        if (root[1].isZero()) return error.NativeGkrRootPole;
        if (inst.kind == .local) {
            ln = ln.mul(root[1]).add(root[0].mul(ld));
            ld = ld.mul(root[1]);
        } else {
            const slot = global.at(inst.kind);
            slot.* = slot.add(root[0].mul(try root[1].inv()));
        }
    }
    if (!ln.isZero()) return error.NativeGkrLocalUnclosed;
    channel.* = strict.inner;
    return .{ .artifact = artifact, .global = global, .draws = strict.draws };
}

// ------------------------------------------------------------------------------------------------
// Binding columns (one eq + one weighted prefix per component; outer-gkr binding.zig, native roster).

pub const BindingChallenges = struct { gamma: O, rho: [R.MAX_INSTANCES]O };
/// Drawn strictly right after the section, before the INTER commitment (late binding).
pub fn drawBinding(channel: *RawChannel, roster: *const R.Roster) !BindingChallenges {
    var strict = StrictChannel{ .inner = channel.* };
    var out = BindingChallenges{ .gamma = strict.drawSecureFelt(), .rho = undefined };
    for (out.rho[0..roster.instances.len]) |*r| r.* = strict.drawSecureFelt();
    if (strict.rejected) return error.NativeGkrDrawRejected;
    channel.* = strict.inner;
    return out;
}
/// Verifier side: the final prefix value of component `c`, from the GKR terminal claims.
pub fn expectedBoundary(roster: *const R.Roster, component: usize, claims: []const []const O, ch: *const BindingChallenges) O {
    var acc = O.zero();
    for (roster.instances, 0..) |inst, g| {
        if (inst.component != component) continue;
        acc = acc.add(ch.rho[g].mul(claims[g][0].add(ch.gamma.mul(claims[g][1]))));
    }
    return acc;
}

pub const Inputs = OS.Inputs;
pub const Columns = struct {
    eq: []O,
    prefix: []O,
    pub fn deinit(self: *Columns, a: std.mem.Allocator) void {
        a.free(self.eq);
        a.free(self.prefix);
    }
};
pub const eqTable = @import("../../../outer_gkr/binding.zig").eqTable;
/// Prover side (what the AIR enforces row by row): E[row] = eq(z_row, row),
/// Pre[row+1] = Pre[row] + E[row] * sum_g rho_g sum_lane w_g(lane) (n_g + gamma d_g)[lane * 2^r + row].
/// Padded lanes of a group carry exactly (0, 1); they are part of the inputs and of the GKR leaves.
pub fn bindingColumns(a: std.mem.Allocator, roster: *const R.Roster, component: usize, point: []const O, inputs: *const Inputs, ch: *const BindingChallenges) !Columns {
    const r = roster.components[component].row_log;
    const rows = @as(usize, 1) << @intCast(r);
    const eq = try eqTable(a, point[point.len - r ..]);
    errdefer a.free(eq);
    const v = try a.alloc(O, rows);
    defer a.free(v);
    @memset(v, O.zero());
    for (roster.instances, 0..) |inst, g| {
        if (inst.component != component) continue;
        const n_g = inst.variables();
        const w = try eqTable(a, point[point.len - n_g .. point.len - r]);
        defer a.free(w);
        for (0..rows) |row| {
            var acc = O.zero();
            for (w, 0..) |wl, lane| {
                const idx = lane * rows + row;
                acc = acc.add(wl.mul(O.fromBase(inputs.numerators[g][idx]).add(ch.gamma.mul(inputs.denominators[g][idx]))));
            }
            v[row] = v[row].add(ch.rho[g].mul(acc));
        }
    }
    const prefix = try a.alloc(O, rows + 1);
    prefix[0] = O.zero();
    for (0..rows) |row| prefix[row + 1] = prefix[row].add(eq[row].mul(v[row]));
    return .{ .eq = eq, .prefix = prefix };
}
/// The receiver's terminal check for every component (in the AIR this is the prefix boundary constraint
/// against the OODS-authenticated binding columns; here the reference recomputes the columns).
pub fn requireBinding(a: std.mem.Allocator, roster: *const R.Roster, verified: *const Verified, inputs: *const Inputs, ch: *const BindingChallenges) !void {
    for (roster.components, 0..) |c, i| {
        if (!c.present()) continue;
        var cols = try bindingColumns(a, roster, i, verified.artifact.ood_point, inputs, ch);
        defer cols.deinit(a);
        const want = expectedBoundary(roster, i, verified.artifact.claims_to_verify_by_instance, ch);
        if (!cols.prefix[cols.prefix.len - 1].eql(want)) return error.NativeGkrBindingMismatch;
    }
}

// ------------------------------------------------------------------------------------------------
// Deterministic synthetic fractions (tests, corpus, real-shape timing). Lane-major, padding (0, 1).

/// Lane-major inputs. Real lanes: n in 1..7 (or -1), random OM31 d. Padded lanes: exactly (0, 1).
/// Local fractions are balanced (sum 0 over all local instances); global sums are whatever they are.
pub fn syntheticInputs(a: std.mem.Allocator, roster: *const R.Roster, seed: u64) !Inputs {
    const k = roster.instances.len;
    var out = Inputs{ .numerators = try a.alloc([]M31, k), .denominators = try a.alloc([]O, k) };
    for (roster.instances, 0..) |inst, i| {
        const facts: usize = @intCast(inst.facts());
        const rows = @as(usize, 1) << @intCast(inst.row_log);
        out.numerators[i] = try a.alloc(M31, facts);
        out.denominators[i] = try a.alloc(O, facts);
        var rng = OS.Rng.init(seed, i);
        for (0..facts) |idx| {
            const lane = idx / rows;
            if (lane >= inst.terms) {
                out.numerators[i][idx] = M31.zero();
                out.denominators[i][idx] = O.one();
                continue;
            }
            out.numerators[i][idx] = if (rng.next() % 5 == 0) M31.zero().sub(M31.one()) else M31.fromCanonical(rng.numerator());
            var c: [8]M31 = undefined;
            for (&c) |*x| x.* = M31.fromCanonical(rng.coordinate());
            out.denominators[i][idx] = O.fromM31Array(c);
        }
    }
    // Balance the local relation: rewrite the denominator of the first local fact (lane 0, row 0).
    var first: ?usize = null;
    var rest = O.zero();
    for (roster.instances, 0..) |inst, i| {
        if (inst.kind != .local) continue;
        if (first == null) first = i;
        for (out.numerators[i], out.denominators[i], 0..) |n, d, j| {
            if (i == first.? and j == 0) continue;
            rest = rest.add(O.fromBase(n).mul(try d.inv()));
        }
    }
    const f = first.?;
    out.numerators[f][0] = M31.fromCanonical(3);
    out.denominators[f][0] = O.fromBase(M31.fromCanonical(3)).mul(try rest.neg().inv());
    return out;
}
pub fn globalSums(roster: *const R.Roster, inputs: *const Inputs) !GlobalClaims {
    var g = GlobalClaims{};
    for (roster.instances, 0..) |inst, i| {
        if (inst.kind == .local) continue;
        for (inputs.numerators[i], inputs.denominators[i]) |n, d| g.at(inst.kind).* = g.at(inst.kind).add(O.fromBase(n).mul(try d.inv()));
    }
    return g;
}

// ------------------------------------------------------------------------------------------------
// CPU reference prover (fixtures, tests, corpus). Production: shared CUDA traversal (outer-gkr route).

pub fn proveCpu(a: std.mem.Allocator, channel: *const RawChannel, roster: *const R.Roster, scope: *const Scope, inputs: *const Inputs) !Section {
    try roster.validate();
    if (inputs.numerators.len != roster.instances.len) return error.NativeGkrInputShape;
    const layers = try a.alloc(GP.Layer, roster.instances.len);
    defer a.free(layers);
    for (layers, inputs.numerators, inputs.denominators, roster.instances) |*l, n, d, inst| {
        if (n.len != inst.facts() or d.len != inst.facts()) return error.NativeGkrInputShape;
        l.* = .{ .LogUpMultiplicities = .{ .numerators = try MleBase.initBorrowed(n), .denominators = try MleSecure.initBorrowed(d) } };
    }
    var salt_value: u32 = 0;
    while (salt_value < MAX_SALT_ATTEMPTS) : (salt_value += 1) {
        const salt = O.fromBase(M31.fromCanonical(salt_value));
        var prover_channel = channel.*;
        try mixHeader(a, &prover_channel, roster, scope, salt);
        var result = try GP.proveBatch(a, &prover_channel, layers);
        result.artifact.deinit(a);
        var section = Section{ .salt = salt, .proof = result.proof };
        var replay = channel.*;
        if (verify(a, &replay, roster, scope, &section)) |v| {
            var owned = v;
            owned.deinit(a);
            return section;
        } else |err| switch (err) {
            error.NativeGkrDrawRejected, error.NativeGkrShapeMismatch => section.deinit(a),
            else => {
                section.deinit(a);
                return err;
            },
        }
    }
    return error.NativeGkrSaltExhausted;
}

// ------------------------------------------------------------------------------------------------
// Wire codec (u32 LE words, canonical M31 only; length is a class constant):
//   [MAGIC, VERSION, n_instances, n_layers] salt[8] roots[16n]
//   for depth in 0..L: rounds[depth][4][8], masks of active instances (variables >= L - depth)[2][2][8]
pub fn wordCount(roster: *const R.Roster) usize {
    const l = roster.layers();
    var n: usize = 4 + 8 + 16 * roster.instances.len;
    for (0..l) |depth| {
        n += depth * 32;
        for (roster.instances) |inst| n += if (inst.variables() >= l - depth) 32 else 0;
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
    if (at.* + 8 > words.len) return error.MalformedNativeGkrSection;
    var c: [8]M31 = undefined;
    for (&c) |*x| {
        const w = words[at.*];
        if (w >= core.fields.m31.Modulus) return error.NonCanonicalNativeGkrWord;
        x.* = M31.fromCanonical(w);
        at.* += 1;
    }
    return O.fromM31Array(c);
}
pub fn encode(a: std.mem.Allocator, roster: *const R.Roster, section: *const Section) ![]u32 {
    try checkShape(roster, &section.proof);
    const l = roster.layers();
    const out = try a.alloc(u32, wordCount(roster));
    errdefer a.free(out);
    out[0..4].* = .{ MAGIC, VERSION, @intCast(roster.instances.len), l };
    var at: usize = 4;
    put(out, &at, section.salt);
    for (section.proof.output_claims_by_instance) |root| for (root) |v| put(out, &at, v);
    for (0..l) |depth| {
        for (section.proof.sumcheck_proofs[depth].round_polys) |poly| for (poly.coeffsSlice()) |c| put(out, &at, c);
        for (roster.instances, 0..) |inst, i| {
            const v = inst.variables();
            if (v < l - depth) continue;
            const mask = section.proof.layer_masks_by_instance[i][v - (l - depth)];
            for (mask.columns) |col| for (col) |x| put(out, &at, x);
        }
    }
    std.debug.assert(at == out.len);
    return out;
}
/// The roster is the one the RECEIVER derives from the proof's verified class (never from the wire).
pub fn decode(a: std.mem.Allocator, roster: *const R.Roster, words: []const u32) !Section {
    try roster.validate();
    const l = roster.layers();
    if (words.len < 4 or words[0] != MAGIC or words[1] != VERSION) return error.MalformedNativeGkrSection;
    if (words[2] != roster.instances.len or words[3] != l or words.len != wordCount(roster)) return error.MalformedNativeGkrSection;
    var at: usize = 4;
    const salt = try take(words, &at);
    const k = roster.instances.len;
    var proof = G.GkrBatchProof{ .sumcheck_proofs = try a.alloc(engine.lookups.sumcheck.ForField(O).SumcheckProof, l), .layer_masks_by_instance = &.{}, .output_claims_by_instance = &.{} };
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
    for (roster.instances, 0..) |inst, i| {
        proof.output_claims_by_instance[i] = try a.alloc(O, 2);
        for (proof.output_claims_by_instance[i]) |*v| v.* = try take(words, &at);
        proof.layer_masks_by_instance[i] = try a.alloc(G.GkrMask, inst.variables());
        for (proof.layer_masks_by_instance[i]) |*m| m.* = .{ .columns = &.{} };
    }
    for (0..l) |depth| {
        proof.sumcheck_proofs[depth].round_polys = try a.alloc(Poly, depth);
        for (proof.sumcheck_proofs[depth].round_polys) |*poly| poly.* = Poly.initOwned(&.{});
        for (proof.sumcheck_proofs[depth].round_polys) |*poly| {
            const coeffs = try a.alloc(O, COEFFICIENTS_PER_ROUND);
            poly.* = .{ .coeffs = coeffs, .len = coeffs.len, .owns_coeffs = true };
            for (coeffs) |*c| c.* = try take(words, &at);
        }
        for (roster.instances, 0..) |inst, i| {
            const v = inst.variables();
            if (v < l - depth) continue;
            const cols = try a.alloc([2]O, 2);
            proof.layer_masks_by_instance[i][v - (l - depth)] = .{ .columns = cols };
            for (cols) |*col| for (col) |*x| {
                x.* = try take(words, &at);
            };
        }
    }
    if (at != words.len) return error.MalformedNativeGkrSection;
    var section = Section{ .salt = salt, .proof = proof };
    try checkShape(roster, &section.proof);
    return section;
}
