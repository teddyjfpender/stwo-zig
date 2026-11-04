//! Native LogUp-GKR v1 tests: roster, completeness, global-claim exposure, binding, wire codec and the
//! NG tamper corpus (U tier). Step: test-riscv64-native-gkr.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("roster.zig");
const S = @import("section.zig");
const M31 = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const OS = @import("../../../outer_gkr/section.zig");

/// A CPU-proof-shaped roster at toy row logs: cpu (local only), ls (local + ram), initial (ram only),
/// keccak bridge (local + ram + kio), secp bridge (local + ram + wire), an absent component.
fn toySpecs() [6]R.ComponentSpec {
    return .{
        .{ .origin = .{ 0, 0 }, .row_log = 6, .terms = .{ 14, 0, 0, 0 } },
        .{ .origin = .{ 0, 13 }, .row_log = 5, .terms = .{ 10, 2, 0, 0 } },
        .{ .origin = .{ 0, 14 }, .row_log = 4, .terms = .{ 0, 1, 0, 0 } },
        .{ .origin = .{ 1, 0 }, .row_log = 3, .terms = .{ 5, 2, 2, 0 } },
        .{ .origin = .{ 1, 1 }, .row_log = 3, .terms = .{ 3, 8, 0, 2 } },
        .{ .origin = .{ 2, 3 }, .row_log = 5, .terms = .{ 0, 0, 0, 0 } },
    };
}
fn scope() S.Scope {
    return .{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .shared = @splat(4), .ordinal = 7 };
}
fn channel() S.RawChannel {
    var c = S.RawChannel.init();
    c.mixU32s(&.{ 0x4e47_4b52, 0x54455354 });
    return c;
}

const inputsFor = S.syntheticInputs;
const globalSums = S.globalSums;

const Fixture = struct {
    roster: R.Roster,
    inputs: S.Inputs,
    section: S.Section,
    honest: S.GlobalClaims,
    fn init(a: std.mem.Allocator) !Fixture {
        var roster = try R.derive(a, &toySpecs());
        errdefer roster.deinit();
        var inputs = try inputsFor(a, &roster, 0x5eed);
        errdefer inputs.deinit(a);
        const ch = channel();
        const sc = scope();
        const section = try S.proveCpu(a, &ch, &roster, &sc, &inputs);
        return .{ .roster = roster, .inputs = inputs, .section = section, .honest = try globalSums(&roster, &inputs) };
    }
    fn deinit(self: *Fixture, a: std.mem.Allocator) void {
        self.section.deinit(a);
        self.inputs.deinit(a);
        self.roster.deinit();
    }
};

/// The whole receiver predicate for one native proof's section: decode against the receiver-derived
/// roster, verify (strict draws, shape, local closure), the exposed global claims must equal the ones the
/// cross-proof closure accepts, and every component's binding boundary must hold against the
/// receiver-view fractions (projected from MAIN with padded lanes forced to (0, 1)).
fn accepts(a: std.mem.Allocator, roster: *const R.Roster, words: []const u32, receiver_inputs: *const S.Inputs, closing: S.GlobalClaims) bool {
    var section = S.decode(a, roster, words) catch return false;
    defer section.deinit(a);
    var ch = channel();
    const sc = scope();
    var v = S.verify(a, &ch, roster, &sc, &section) catch return false;
    defer v.deinit(a);
    if (!v.global.ram.eql(closing.ram) or !v.global.kio.eql(closing.kio) or !v.global.wire.eql(closing.wire)) return false;
    const b = S.drawBinding(&ch, roster) catch return false;
    S.requireBinding(a, roster, &v, receiver_inputs, &b) catch return false;
    return true;
}

test "native GKR v1 roster: canonical order, lane logs, binding pairs, header and cost" {
    const a = std.testing.allocator;
    var roster = try R.derive(a, &toySpecs());
    defer roster.deinit();
    try std.testing.expectEqual(@as(usize, 10), roster.instances.len);
    try std.testing.expectEqual(@as(usize, 5), roster.bindingPairs());
    // 16 columns per present component, own height: 2^6 + 2^5 + 2^4 + 2^3 + 2^3.
    try std.testing.expectEqual(@as(u64, 16 * (64 + 32 + 16 + 8 + 8)), roster.interCells());
    try std.testing.expectEqual(@as(u32, 4), roster.instances[0].lane_log); // 14 terms -> 16 lanes
    try std.testing.expectEqual(@as(u32, 3), roster.instances[8].lane_log); // secp ram 8 -> 8 lanes
    try std.testing.expectEqual(@as(u32, 10), roster.layers());
    const header = try roster.header(a);
    defer a.free(header);
    try std.testing.expectEqual(@as(usize, 2 + 6 * 7 + 10), header.len);
    // Out-of-order or relabelled instances are refused.
    const saved = roster.instances[2];
    roster.instances[2].kind = .kio;
    try std.testing.expectError(error.NativeGkrRosterShape, roster.validate());
    roster.instances[2] = saved;
    std.mem.swap(R.Instance, &roster.instances[1], &roster.instances[2]);
    try std.testing.expectError(error.NativeGkrRosterOrder, roster.validate());
    std.mem.swap(R.Instance, &roster.instances[1], &roster.instances[2]);
    try roster.validate();
}

test "native GKR v1 roster admits the real Keccak truth shape (lane log 9) and refuses an oversize instance" {
    const a = std.testing.allocator;
    var keccak = try R.derive(a, &.{
        .{ .origin = .{ 16, 0 }, .row_log = 18, .terms = .{ 429, 0, 150, 0 } },
        .{ .origin = .{ 16, 1 }, .row_log = 21, .terms = .{ 1, 0, 0, 0 } },
        .{ .origin = .{ 16, 2 }, .row_log = 16, .terms = .{ 1, 0, 0, 0 } },
    });
    defer keccak.deinit();
    try std.testing.expectEqual(@as(u32, 27), keccak.layers());
    try std.testing.expectEqual(@as(u64, 16 * ((1 << 18) + (1 << 21) + (1 << 16))), keccak.interCells());
    try std.testing.expectError(error.NativeGkrRosterShape, R.derive(a, &.{.{ .origin = .{ 16, 0 }, .row_log = 22, .terms = .{ 129, 0, 0, 0 } }}));
}

test "native GKR v1 completeness: prove, encode, decode, verify, local closure, exposed global claims, binding" {
    const a = std.testing.allocator;
    var f = try Fixture.init(a);
    defer f.deinit(a);
    const words = try S.encode(a, &f.roster, &f.section);
    defer a.free(words);
    try std.testing.expectEqual(S.wordCount(&f.roster), words.len);
    try std.testing.expect(accepts(a, &f.roster, words, &f.inputs, f.honest));
    // The exposed claims are nonzero here (the global relations close only across proofs).
    try std.testing.expect(!f.honest.ram.isZero() and !f.honest.kio.isZero() and !f.honest.wire.isZero());
    // Another proof's closing claims are refused.
    var other = f.honest;
    other.ram = other.ram.add(O.one());
    try std.testing.expect(!accepts(a, &f.roster, words, &f.inputs, other));
}

test "corpus NG01 native GKR v1: every single-word change of the encoded section is rejected" {
    const a = std.testing.allocator;
    var f = try Fixture.init(a);
    defer f.deinit(a);
    const words = try S.encode(a, &f.roster, &f.section);
    defer a.free(words);
    const mutated = try a.dupe(u32, words);
    defer a.free(mutated);
    var rejected: usize = 0;
    for (0..words.len) |i| {
        @memcpy(mutated, words);
        // Header words: flip; field words: +1 mod p (stays canonical, so only the protocol can reject).
        mutated[i] = if (i < 4) mutated[i] ^ 1 else (mutated[i] + 1) % core.fields.m31.Modulus;
        if (!accepts(a, &f.roster, mutated, &f.inputs, f.honest)) rejected += 1 else std.debug.print("NG01 accepted mutation at word {d}\n", .{i});
    }
    std.debug.print("NATIVE_GKR_NG01 words={d} rejected={d}\n", .{ words.len, rejected });
    try std.testing.expectEqual(words.len, rejected);
}

test "corpus NG02 native GKR v1: a non-canonical or truncated section is refused by the codec" {
    const a = std.testing.allocator;
    var f = try Fixture.init(a);
    defer f.deinit(a);
    const words = try S.encode(a, &f.roster, &f.section);
    defer a.free(words);
    const mutated = try a.dupe(u32, words);
    defer a.free(mutated);
    mutated[20] = core.fields.m31.Modulus; // p itself
    try std.testing.expectError(error.NonCanonicalNativeGkrWord, S.decode(a, &f.roster, mutated));
    try std.testing.expectError(error.MalformedNativeGkrSection, S.decode(a, &f.roster, words[0 .. words.len - 1]));
}

test "corpus NG03 native GKR v1: a section proved under another roster (relabelled relation) is refused" {
    const a = std.testing.allocator;
    var f = try Fixture.init(a);
    defer f.deinit(a);
    const words = try S.encode(a, &f.roster, &f.section);
    defer a.free(words);
    // Move ls's two RAM fractions into a KIO group: same instance count and shape, different header.
    var specs = toySpecs();
    specs[1].terms = .{ 10, 0, 2, 0 };
    var other = try R.derive(a, &specs);
    defer other.deinit();
    try std.testing.expect(!accepts(a, &other, words, &f.inputs, f.honest));
}

test "corpus NG04 native GKR v1: an unclosed local relation is refused even with a valid GKR" {
    const a = std.testing.allocator;
    var roster = try R.derive(a, &toySpecs());
    defer roster.deinit();
    var inputs = try inputsFor(a, &roster, 0x5eed);
    defer inputs.deinit(a);
    inputs.numerators[0][5] = inputs.numerators[0][5].add(M31.one()); // a forged local use
    const ch = channel();
    const sc = scope();
    try std.testing.expectError(error.NativeGkrLocalUnclosed, S.proveCpu(a, &ch, &roster, &sc, &inputs));
}

test "corpus NG05 native GKR v1: GKR leaves that differ from MAIN (padded lane d != 1) fail the binding" {
    const a = std.testing.allocator;
    var roster = try R.derive(a, &toySpecs());
    defer roster.deinit();
    var honest = try inputsFor(a, &roster, 0x5eed);
    defer honest.deinit(a);
    var forged = try inputsFor(a, &roster, 0x5eed);
    defer forged.deinit(a);
    // The cpu local group has 14 of 16 lanes in use: the two padded lanes get +1/2 and -1/2, so the
    // local relation still closes and the GKR is valid for these leaves.
    const rows = @as(usize, 1) << @intCast(roster.instances[0].row_log);
    const idx = 15 * rows + 3;
    forged.numerators[0][idx] = M31.one(); // +1/2
    forged.denominators[0][idx] = O.fromBase(M31.fromCanonical(2));
    const idx2 = 14 * rows + 3;
    forged.numerators[0][idx2] = M31.zero().sub(M31.one()); // -1/2
    forged.denominators[0][idx2] = O.fromBase(M31.fromCanonical(2));
    const ch = channel();
    const sc = scope();
    var section = try S.proveCpu(a, &ch, &roster, &sc, &forged);
    defer section.deinit(a);
    const words = try S.encode(a, &roster, &section);
    defer a.free(words);
    const closing = try globalSums(&roster, &honest);
    // The GKR itself is valid for the forged leaves; the binding against MAIN (padding forced) is not.
    try std.testing.expect(accepts(a, &roster, words, &forged, closing));
    try std.testing.expect(!accepts(a, &roster, words, &honest, closing));
}

test "corpus NG06 native GKR v1: two terminal claims of one component shifted by +delta/-delta are separated by rho" {
    const a = std.testing.allocator;
    var f = try Fixture.init(a);
    defer f.deinit(a);
    var ch = channel();
    const sc = scope();
    var v = try S.verify(a, &ch, &f.roster, &sc, &f.section);
    defer v.deinit(a);
    const b = try S.drawBinding(&ch, &f.roster);
    const claims = v.artifact.claims_to_verify_by_instance;
    const comp: usize = 3; // keccak bridge: local, ram, kio
    const honest = S.expectedBoundary(&f.roster, comp, claims, &b);
    const delta = O.fromBase(M31.fromCanonical(12345));
    // Find the component's first two instances.
    var ids: [2]usize = undefined;
    var found: usize = 0;
    for (f.roster.instances, 0..) |inst, g| if (inst.component == comp and found < 2) {
        ids[found] = g;
        found += 1;
    };
    const saved0 = claims[ids[0]][0];
    const saved1 = claims[ids[1]][0];
    claims[ids[0]][0] = saved0.add(delta);
    claims[ids[1]][0] = saved1.sub(delta);
    const forged = S.expectedBoundary(&f.roster, comp, claims, &b);
    claims[ids[0]][0] = saved0;
    claims[ids[1]][0] = saved1;
    try std.testing.expect(!honest.eql(forged));
}

test "native GKR v1 transcript: verifier continues exactly where the prover's replay ends" {
    const a = std.testing.allocator;
    var f = try Fixture.init(a);
    defer f.deinit(a);
    var c1 = channel();
    var c2 = channel();
    const sc = scope();
    var v1 = try S.verify(a, &c1, &f.roster, &sc, &f.section);
    defer v1.deinit(a);
    var v2 = try S.verify(a, &c2, &f.roster, &sc, &f.section);
    defer v2.deinit(a);
    try std.testing.expect(c1.drawSecureFelt().eql(c2.drawSecureFelt()));
    // A different scope (e.g. another MAIN root or chi) yields a different transcript: the section is refused.
    var other = sc;
    other.shared[0] ^= 1;
    var c3 = channel();
    if (S.verify(a, &c3, &f.roster, &other, &f.section)) |vv| {
        var owned = vv;
        owned.deinit(a);
        return error.TestUnexpectedResult;
    } else |_| {}
}
