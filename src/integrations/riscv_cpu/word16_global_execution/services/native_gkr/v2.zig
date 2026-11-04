//! Native LogUp-GKR section of `rv64-m6-native/v2` profile v2-gkr (M6-INTERFACES NF4). Stream native-format.
//! Additive over the frozen v1 reference (`section.zig`, `rv64-m5-native-gkr/v1`): v1 bytes and its NG
//! corpus are unchanged. This file closes the open review items of rv64-native-gkr.md section 9:
//!   * local lookup elements: drawn strictly inside the section, right after the salt and before any GKR
//!     draw (`drawLocalElements`), so the fractions the GKR proves depend on the full scope + roster;
//!   * characteristic / bits gate: `requireNativeGkrSecurity` (outer-gkr's requireSecurity pattern with
//!     the M4 per-relation multiplicity masses from the receiver's source bounds);
//!   * roster authority: `requireEmitterCounts` asserts that every component's term counts equal the
//!     emitters' counts (a group smaller than its emitter is refused, not only a missing one);
//!   * 128 instances (CUDA batch_max_oracles 64 -> 128 is required before the GPU route can run v2).
//! Status: reference level (CPU prover/verifier); the native AIR binding, GPU projection and receiver
//! wiring of v2-gkr are not built, and the selector `m6-native-v2-gkr` is refused (native_policy.zig).
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const R = @import("roster.zig");
const S = @import("section.zig");
const Cand = @import("../../../word16_execution/om31_security_candidate.zig");
const M31 = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const G = engine.lookups.gkr_verifier.ForField(O);
const GP = engine.lookups.gkr_prover.ForField(O);
const MleBase = engine.lookups.mle.MleFor(O, M31);
const MleSecure = engine.lookups.mle.MleFor(O, O);

pub const VERSION_NAME = "rv64-m6-native/v2+native-gkr";
pub const IDENTITY_DOMAIN = "stwo/rv64/native-gkr/om31-strict-draw/lane-major/v2";
pub const VERSION: u32 = 2;
pub const MAX_INSTANCES: usize = 128;
/// Production local relations (gkr_local/fractions.zig, byte_pair included) = canon-native LOCAL_RELATIONS.
pub const LOCAL_RELATIONS: usize = 10;
/// Bits target (= outer-gkr profile.REQUIRED_BITS, rv64-m7-profiles.md 4.3).
pub const REQUIRED_BITS: u16 = 151;
/// Largest per-query tuple a native fraction compresses (sponge.call RAM queries: 58; an overbound, see
/// rv64-native-gkr.md section 9 ledger wording).
pub const MAX_TUPLE_ARITY: u64 = 58;

pub fn identityWords() [8]u32 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(IDENTITY_DOMAIN, &digest, .{});
    var out: [8]u32 = undefined;
    for (&out, 0..) |*w, i| w.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    return out;
}

/// v2 roster admission: the v1 rules with the v2 instance bound.
pub fn validate(roster: *const R.Roster) !void {
    if (roster.instances.len == 0 or roster.instances.len > MAX_INSTANCES) return error.NativeGkrRosterShape;
    if (roster.instances.len <= R.MAX_INSTANCES) return roster.validate();
    // > 64 instances: v1 validate refuses on size alone; re-run its per-instance rules here.
    var previous: ?R.Instance = null;
    for (roster.instances) |inst| {
        if (inst.component >= roster.components.len) return error.NativeGkrRosterShape;
        const c = roster.components[inst.component];
        if (inst.row_log != c.row_log or inst.terms == 0 or inst.terms != c.terms[@intFromEnum(inst.kind)]) return error.NativeGkrRosterShape;
        if (inst.lane_log != R.laneLog(inst.terms) or inst.lane_log > R.MAX_LANE_LOG) return error.NativeGkrRosterShape;
        if (inst.row_log < 1 or inst.variables() > R.MAX_VARIABLES) return error.NativeGkrRosterShape;
        if (previous) |p| if (p.component > inst.component or (p.component == inst.component and @intFromEnum(p.kind) >= @intFromEnum(inst.kind))) return error.NativeGkrRosterOrder;
        previous = inst;
    }
    for (roster.components, 0..) |c, ci| {
        var want: usize = 0;
        for (c.terms) |t| want += @intFromBool(t != 0);
        var got: usize = 0;
        for (roster.instances) |inst| got += @intFromBool(inst.component == ci);
        if (got != want) return error.NativeGkrRosterShape;
    }
}

/// Roster authority (review item 3): the receiver derives the roster from the emitters; every component's
/// four term counts must equal the emitter census exactly (fractions.zig / global_cpu.queriesFor / truth
/// catalogues), in receiver component order.
pub fn requireEmitterCounts(roster: *const R.Roster, emitter: []const [R.KINDS]u32) !void {
    if (emitter.len != roster.components.len) return error.NativeGkrEmitterRoster;
    for (roster.components, emitter) |c, e| if (!std.mem.eql(u32, &c.terms, &e)) return error.NativeGkrEmitterTermCount;
}

/// Per-relation multiplicity masses of ONE native proof, from the receiver's M4 source bounds
/// (multiplicity-weighted, padding included): every local relation and the three global relations.
pub const RelationMasses = struct { local: [LOCAL_RELATIONS]u64, ram: u64, kio: u64, wire: u64 };

/// Security gate (review item 1; outer-gkr requireSecurity pattern). Fails closed.
///   bits: the outer-gkr ledger (sumcheck rounds, instance mix, layer binding, tuple compression, poles) over
///         `native_proofs` proofs of this roster's size, at the raw-modulo OM31 point probability, >= 151 bits;
///   characteristic: every relation's multiplicity mass < p (a LogUp sum over M31 cannot tell m from m + p).
pub fn requireNativeGkrSecurity(roster: *const R.Roster, native_proofs: u64, masses: RelationMasses) !void {
    try validate(roster);
    const facts = Cand.OuterGkrFacts{ .outer_proofs = native_proofs, .instances = roster.instances.len, .max_variables = roster.layers(), .max_tuple_arity = MAX_TUPLE_ARITY };
    try Cand.requireOuterGkrBits(facts, REQUIRED_BITS);
    for (masses.local) |m| try Cand.requireOuterGkrCharacteristic(facts, m);
    for ([_]u64{ masses.ram, masses.kio, masses.wire }) |m| try Cand.requireOuterGkrCharacteristic(facts, m);
}

pub fn mixHeader(a: std.mem.Allocator, channel: anytype, roster: *const R.Roster, scope: *const S.Scope, salt: O) !void {
    channel.mixU32s(&identityWords());
    channel.mixU32s(&.{ S.MAGIC, VERSION, scope.ordinal });
    for ([_][32]u8{ scope.statement, scope.fixed, scope.main, scope.shared }) |b| {
        var w: [8]u32 = undefined;
        for (&w, 0..) |*x, i| x.* = std.mem.readInt(u32, b[4 * i ..][0..4], .little);
        channel.mixU32s(&w);
    }
    const header = try roster.header(a);
    defer a.free(header);
    channel.mixU32s(header);
    channel.mixFelts(&.{salt});
}

/// The local relations' lookup elements (z_r, alpha_r), r = 0..LOCAL_RELATIONS-1, in fractions.zig Relation
/// order. Drawn strictly here and nowhere else (review item 2).
pub const LocalElements = struct { z: [LOCAL_RELATIONS]O, alpha: [LOCAL_RELATIONS]O };
pub fn drawLocalElements(strict: *S.StrictChannel) LocalElements {
    var out: LocalElements = undefined;
    for (&out.z, &out.alpha) |*z, *alpha| {
        z.* = strict.drawSecureFelt();
        alpha.* = strict.drawSecureFelt();
    }
    return out;
}

pub const Verified = struct {
    artifact: G.GkrArtifact,
    global: S.GlobalClaims,
    elements: LocalElements,
    draws: u32,
    pub fn deinit(self: *Verified, a: std.mem.Allocator) void {
        self.artifact.deinit(a);
    }
};

/// CPU reference verifier of the v2 section. `channel` advances only on success.
pub fn verify(a: std.mem.Allocator, channel: *S.RawChannel, roster: *const R.Roster, scope: *const S.Scope, section: *const S.Section) !Verified {
    try validate(roster);
    try S.checkShape(roster, &section.proof);
    var strict = S.StrictChannel{ .inner = channel.* };
    try mixHeader(a, &strict, roster, scope, section.salt);
    const elements = drawLocalElements(&strict);
    var gates: [MAX_INSTANCES]G.Gate = undefined;
    @memset(gates[0..roster.instances.len], .LogUp);
    var artifact = try G.partiallyVerifyBatch(a, gates[0..roster.instances.len], &section.proof, &strict);
    errdefer artifact.deinit(a);
    if (strict.rejected) return error.NativeGkrDrawRejected;
    for (artifact.n_variables_by_instance, roster.instances) |n, inst| if (n != inst.variables()) return error.NativeGkrShapeMismatch;
    var ln = O.zero();
    var ld = O.one();
    var global = S.GlobalClaims{};
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
    return .{ .artifact = artifact, .global = global, .elements = elements, .draws = strict.draws };
}

/// CPU reference prover. `builder.build(a, roster, elements) !S.Inputs` projects the fractions AFTER the
/// local elements are drawn (a re-salt redraws them and re-projects: the leaves depend on the elements).
pub fn proveCpu(a: std.mem.Allocator, channel: *const S.RawChannel, roster: *const R.Roster, scope: *const S.Scope, builder: anytype) !S.Section {
    try validate(roster);
    var salt_value: u32 = 0;
    while (salt_value < S.MAX_SALT_ATTEMPTS) : (salt_value += 1) {
        const salt = O.fromBase(M31.fromCanonical(salt_value));
        var strict = S.StrictChannel{ .inner = channel.* };
        try mixHeader(a, &strict, roster, scope, salt);
        const elements = drawLocalElements(&strict);
        if (strict.rejected) continue;
        var inputs = try builder.build(a, roster, elements);
        defer inputs.deinit(a);
        if (inputs.numerators.len != roster.instances.len) return error.NativeGkrInputShape;
        const layers = try a.alloc(GP.Layer, roster.instances.len);
        defer a.free(layers);
        for (layers, inputs.numerators, inputs.denominators, roster.instances) |*l, n, d, inst| {
            if (n.len != inst.facts() or d.len != inst.facts()) return error.NativeGkrInputShape;
            l.* = .{ .LogUpMultiplicities = .{ .numerators = try MleBase.initBorrowed(n), .denominators = try MleSecure.initBorrowed(d) } };
        }
        var prover_channel = strict.inner;
        var result = try GP.proveBatch(a, &prover_channel, layers);
        result.artifact.deinit(a);
        var section = S.Section{ .salt = salt, .proof = result.proof };
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

// ------------------------------------------------------------------------------------------------ tests
const testing = std.testing;
fn toySpecs() [4]R.ComponentSpec {
    return .{
        .{ .origin = .{ 0, 0 }, .row_log = 5, .terms = .{ 6, 0, 0, 0 } },
        .{ .origin = .{ 0, 13 }, .row_log = 4, .terms = .{ 4, 2, 0, 0 } },
        .{ .origin = .{ 1, 0 }, .row_log = 3, .terms = .{ 2, 1, 1, 0 } },
        .{ .origin = .{ 1, 1 }, .row_log = 3, .terms = .{ 0, 0, 0, 0 } },
    };
}
fn toyScope() S.Scope {
    return .{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .shared = @splat(4), .ordinal = 3 };
}
/// Synthetic fractions that depend on the drawn local elements (as real local fractions do): the
/// synthetic generator is reseeded from z_0, so a different element draw gives different leaves while the
/// local relation stays closed.
const ElementBuilder = struct {
    seed: u64,
    seen: *?LocalElements,
    pub fn build(self: ElementBuilder, a: std.mem.Allocator, roster: *const R.Roster, e: LocalElements) !S.Inputs {
        self.seen.* = e;
        return S.syntheticInputs(a, roster, self.seed ^ @as(u64, e.z[0].toM31Array()[0].v));
    }
};
test "native GKR v2: local elements drawn in-section after the salt; prove/verify; scope and identity bound" {
    const a = testing.allocator;
    var roster = try R.derive(a, &toySpecs());
    defer roster.deinit();
    const scope = toyScope();
    var ch = S.RawChannel.init();
    ch.mixU32s(&.{ 0x4e47_4b52, 2 });
    var seen: ?LocalElements = null;
    var section = try proveCpu(a, &ch, &roster, &scope, ElementBuilder{ .seed = 7, .seen = &seen });
    defer section.deinit(a);
    var replay = ch;
    var v = try verify(a, &replay, &roster, &scope, &section);
    defer v.deinit(a);
    // The verifier re-derives exactly the elements the prover projected with.
    try testing.expect(std.meta.eql(seen.?, v.elements));
    // v2 identity differs from v1: a v2 section never verifies under the v1 verifier.
    try testing.expect(!std.mem.eql(u32, &identityWords(), &S.identityWords()));
    var replay_v1 = ch;
    if (S.verify(a, &replay_v1, &roster, &scope, &section)) |w| {
        var owned = w;
        owned.deinit(a);
        return error.TestUnexpectedResult;
    } else |_| {}
    // Another ordinal (scope) moves the elements and is refused.
    var other = scope;
    other.ordinal += 1;
    var replay2 = ch;
    try testing.expect(std.meta.isError(verify(a, &replay2, &roster, &other, &section)));
}
test "corpus NV09 native GKR v2: a component whose term count is smaller than its emitter's is refused" {
    const a = testing.allocator;
    var roster = try R.derive(a, &toySpecs());
    defer roster.deinit();
    var emitter: [4][R.KINDS]u32 = undefined;
    for (roster.components, &emitter) |c, *e| e.* = c.terms;
    try requireEmitterCounts(&roster, &emitter);
    emitter[1][1] = 3; // the emitter emits 3 RAM terms, the roster carries 2
    try testing.expectError(error.NativeGkrEmitterTermCount, requireEmitterCounts(&roster, &emitter));
    try testing.expectError(error.NativeGkrEmitterRoster, requireEmitterCounts(&roster, emitter[0..3]));
}
test "corpus NV10 native GKR v2: security gate (bits >= 151, every relation mass < p) fails closed" {
    const a = testing.allocator;
    var roster = try R.derive(a, &toySpecs());
    defer roster.deinit();
    var masses = RelationMasses{ .local = @splat(1 << 20), .ram = 1 << 24, .kio = 1 << 20, .wire = 0 };
    try requireNativeGkrSecurity(&roster, 28, masses);
    masses.local[9] = core.fields.m31.Modulus; // one local relation at p: m and m + p collide
    try testing.expectError(error.Om31CandidateCharacteristicWrap, requireNativeGkrSecurity(&roster, 28, masses));
    masses.local[9] = 1;
    masses.ram = core.fields.m31.Modulus - 1;
    try requireNativeGkrSecurity(&roster, 28, masses);
    masses.ram += 1;
    try testing.expectError(error.Om31CandidateCharacteristicWrap, requireNativeGkrSecurity(&roster, 28, masses));
}
test "native GKR v2 roster admits 128 instances (CPU-0 of 24628607 reaches 64 under v1) and refuses 129" {
    const a = testing.allocator;
    var specs: [43]R.ComponentSpec = undefined;
    for (&specs, 0..) |*s, i| s.* = .{ .origin = .{ 0, @intCast(i) }, .row_log = 4, .terms = .{ 3, 2, 1, 0 } };
    var roster = try deriveV2(a, &specs);
    defer roster.deinit();
    try testing.expectEqual(@as(usize, 129), roster.instances.len);
    try testing.expectError(error.NativeGkrRosterShape, validate(&roster));
    var roster128 = try deriveV2(a, specs[0..42]);
    defer roster128.deinit();
    try testing.expectEqual(@as(usize, 126), roster128.instances.len);
    try validate(&roster128);
}
/// v1 `derive` without its 64-instance validate (tests of the v2 bound).
fn deriveV2(a: std.mem.Allocator, specs: []const R.ComponentSpec) !R.Roster {
    const components = try a.dupe(R.ComponentSpec, specs);
    errdefer a.free(components);
    var list = std.ArrayList(R.Instance).empty;
    errdefer list.deinit(a);
    for (components, 0..) |c, i| for (c.terms, 0..) |t, k| if (t != 0) {
        try list.append(a, .{ .component = @intCast(i), .kind = @enumFromInt(k), .row_log = c.row_log, .lane_log = R.laneLog(t), .terms = t });
    };
    return .{ .allocator = a, .components = components, .instances = try list.toOwnedSlice(a) };
}
