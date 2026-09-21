//! Canonical compact-Poseidon equation identity, separate from source provenance.
//! Authenticates the executable specialization against canonical typed lowering,
//! then preserves the ordered protocol digest. Typed commutative equivalence is
//! a separate admission check, never a replacement for the manifest identity.
const std = @import("std");
const air = @import("poseidon2_universal_equations_v1.zig");
const typed = @import("../lang/typed_poseidon2_compact.zig");
const symbolic = @import("../extract/symbolic.zig");
const expression = @import("../extract/canonical_digest.zig");
const native_relations = @import("../relation_challenges.zig");
const S = symbolic.Scalar;
const Hash = std.crypto.hash.sha2.Sha256;
pub const FORMAT_VERSION: u32 = 2;
pub const Digest = [32]u8;

pub const CANONICAL_DIGEST = hexDigest("e37c589fabffa3711c41c6cb259e68303543bc36edcef3d5be5caec7459f8ddf");
/// Only this reviewed historical implementation identity has a compatibility
/// mapping. It authorizes the same canonical equations, never arbitrary source.
pub const LEGACY_SOURCE_DIGEST = hexDigest("48302838137c822fe11fcafb652257046c41834f2ee1c818d93bf09a166f2871");
pub const Compatibility = enum { canonical_only, allow_reviewed_legacy };

pub fn validateAdmission(allocator: std.mem.Allocator, identity: Digest, compatibility: Compatibility) !void {
    const canonical = std.mem.eql(u8, &identity, &CANONICAL_DIGEST);
    const legacy = compatibility == .allow_reviewed_legacy and std.mem.eql(u8, &identity, &LEGACY_SOURCE_DIGEST);
    if (!canonical and !legacy) return error.UnadmittedCompactPoseidonIdentity;
    const actual = try compute(allocator);
    if (!std.mem.eql(u8, &actual, &CANONICAL_DIGEST)) return error.CompactPoseidonSemanticMismatch;
}

fn hexDigest(comptime text: []const u8) Digest {
    var bytes: Digest = undefined;
    _ = std.fmt.hexToBytes(&bytes, text) catch @compileError("invalid compact Poseidon identity pin");
    return bytes;
}

pub fn compute(allocator: std.mem.Allocator) !Digest {
    return computeImpl(air, true, allocator);
}

fn computeForAir(comptime Air: type, allocator: std.mem.Allocator) !Digest {
    return computeImpl(Air, false, allocator);
}

fn computeImpl(comptime Air: type, comptime typed_authority: bool, allocator: std.mem.Allocator) !Digest {
    var definition: typed.Definition = if (typed_authority) try typed.Definition.init(allocator) else undefined;
    defer if (typed_authority) definition.deinit();
    var arena = symbolic.Arena.initRecoverable(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();
    var main: [Air.N_MAIN_COLUMNS]S = undefined;
    for (&main) |*value| value.* = arena.column("main");
    const first = arena.column("is_first");
    var sums: [Air.N_SUMS]S = undefined;
    var previous: [Air.N_SUMS]S = undefined;
    var claims: [Air.N_SUMS]S = undefined;
    for (&sums) |*value| value.* = arena.column("interaction_current");
    for (&previous) |*value| value.* = arena.column("interaction_previous");
    for (&claims) |*value| value.* = arena.column("claimed_sum");
    var relations: Relations = undefined;
    inline for (std.meta.fields(native_relations.Relations)) |field| {
        const z = arena.column(field.name ++ ".z");
        const alpha = arena.column(field.name ++ ".alpha");
        @field(relations, field.name) = .{ .z = z, .alpha = alpha };
    }
    const direct = Air.evaluateGeneric(S, main);
    const lookups = Air.entriesGeneric(S, main);
    const interaction = Air.interactionConstraintsGeneric(S, main, first, sums, previous, claims, &relations);
    if (typed_authority) {
        var expected = try definition.evaluate(S, allocator, main);
        var typed_interaction: [Air.N_SUMS]S = undefined;
        for (&typed_interaction, 0..) |*root, index| root.* = @import("../logup_equations.zig").pairConstraintGeneric(S, sums[index], previous[index], first, claims[index], try expected.lookups.pairWith(index, &relations));
        var comparison = try @import("../extract/provider_equivalence.zig").Comparison.init(allocator, &arena);
        defer comparison.deinit();
        comparison.roots(&direct, &expected.direct) catch return error.CompactPoseidonSpecializationMismatch;
        comparison.lookups(lookups, expected.lookups) catch return error.CompactPoseidonSpecializationMismatch;
        comparison.roots(&interaction, &typed_interaction) catch return error.CompactPoseidonSpecializationMismatch;
    }
    try arena.checkAllocation();
    const digests = try expression.expressions(allocator, arena.nodes.items, arena.names.items.len);
    defer allocator.free(digests);
    var hash = Hash.init(.{});
    hash.update("stwo-zig/compact-poseidon-equations/v2\x00");
    for ([_]u32{ FORMAT_VERSION, expression.FORMAT_VERSION, @import("stwo_core").fields.m31.Modulus, Air.SCHEMA_VERSION, Air.WIDTH, Air.N_MAIN_COLUMNS, Air.N_INTERACTION_COLUMNS, Air.N_SUMS, Air.N_CONSTRAINTS, Air.MAX_CONSTRAINT_DEGREE, @intFromBool(Air.BINDS_ACTIVE_SELECTOR) }) |value| word(&hash, value);
    // Input positions have fixed roles, even if an input is currently unused.
    word(&hash, @intCast(arena.names.items.len));
    for (arena.names.items) |name| {
        word(&hash, @intCast(name.len));
        hash.update(name);
    }
    hash.update("direct\x00");
    word(&hash, direct.len);
    for (direct) |root| hash.update(&digests[root.id]);
    hash.update("lookups\x00");
    word(&hash, @intCast(lookups.len));
    word(&hash, @intCast(lookups.batch_size));
    for (lookups.entries[0..lookups.len]) |entry| {
        try entry.validate();
        const domain = @tagName(entry.domain);
        word(&hash, @intCast(domain.len));
        hash.update(domain);
        word(&hash, @intFromEnum(entry.domain));
        word(&hash, @intFromEnum(entry.role));
        word(&hash, entry.access_ordinal orelse 0);
        word(&hash, entry.arity);
        hash.update(&digests[entry.numerator.id]);
        for (entry.values[0..entry.arity]) |value| hash.update(&digests[value.id]);
    }
    hash.update("interaction\x00");
    word(&hash, interaction.len);
    for (interaction) |root| hash.update(&digests[root.id]);
    return hash.finalResult();
}

fn word(hash: *Hash, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}

// Expand challenge powers exactly as the native relation constructor, then
// record the same generic combination used by native secure-field evaluation.
const Relation = @import("../extract/symbolic_relations.zig").Relation;
const Relations = @import("../extract/symbolic_relations.zig").Relations;

test "compact Poseidon canonical identity records production equations deterministically" {
    const first = try compute(std.testing.allocator);
    const second = try compute(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &first, &second);
    try std.testing.expectEqualSlices(u8, &CANONICAL_DIGEST, &first);
    std.debug.print("COMPACT_POSEIDON_CANONICAL_V2={x}\n", .{first});
}

test "canonical relation combination matches native extension-field challenges" {
    const Q = @import("stwo_core").fields.qm31.QM31;
    const z = Q.fromU32Unchecked(3, 7, 11, 19);
    const alpha = Q.fromU32Unchecked(23, 29, 31, 37);
    inline for (.{ 1, 2, 3, 4, 5, 7, 16, 32 }) |arity| {
        var values: [arity]Q = undefined;
        for (&values, 0..) |*value, i| value.* = Q.fromU32Unchecked(@intCast(i * 13 + 1), @intCast(i * 17 + 2), @intCast(i * 19 + 3), @intCast(i * 23 + 4));
        const actual = (Relation(Q){ .z = z, .alpha = alpha }).combine(values);
        const expected = native_relations.RelationElements(arity).init(z, alpha).combine(values);
        try std.testing.expect(actual.eql(expected));
    }
}

const Mutation = enum { direct, lookup_numerator, lookup_order, interaction, geometry };
fn Mutated(comptime mutation: Mutation) type {
    return struct {
        pub const WIDTH = air.WIDTH;
        pub const N_MAIN_COLUMNS = air.N_MAIN_COLUMNS;
        pub const N_INTERACTION_COLUMNS = air.N_INTERACTION_COLUMNS;
        pub const N_SUMS = air.N_SUMS;
        pub const N_CONSTRAINTS = air.N_CONSTRAINTS;
        pub const SCHEMA_VERSION = air.SCHEMA_VERSION;
        pub const BINDS_ACTIVE_SELECTOR = air.BINDS_ACTIVE_SELECTOR;
        pub const MAX_CONSTRAINT_DEGREE = air.MAX_CONSTRAINT_DEGREE + @as(u32, @intFromBool(mutation == .geometry));
        pub fn evaluateGeneric(comptime Scalar: type, main: [N_MAIN_COLUMNS]Scalar) [N_CONSTRAINTS]Scalar {
            var roots = air.evaluateGeneric(Scalar, main);
            if (mutation == .direct) roots[0] = roots[0].add(Scalar.one());
            return roots;
        }
        pub fn entriesGeneric(comptime Scalar: type, main: [N_MAIN_COLUMNS]Scalar) @import("../lookups/entry.zig").Builder(Scalar).List {
            var entries = air.entriesGeneric(Scalar, main);
            if (mutation == .lookup_numerator) entries.entries[0].numerator = entries.entries[0].numerator.neg();
            if (mutation == .lookup_order) std.mem.swap(@TypeOf(entries.entries[0]), &entries.entries[0], &entries.entries[1]);
            return entries;
        }
        pub fn interactionConstraintsGeneric(comptime Scalar: type, main: [N_MAIN_COLUMNS]Scalar, first: Scalar, sums: [N_SUMS]Scalar, previous: [N_SUMS]Scalar, claims: [N_SUMS]Scalar, relations: anytype) [N_SUMS]Scalar {
            var roots = air.interactionConstraintsGeneric(Scalar, main, first, sums, previous, claims, relations);
            if (mutation == .interaction) roots[0] = roots[0].add(Scalar.one());
            return roots;
        }
    };
}

test "canonical Poseidon identity changes for constraints lookups interactions and geometry" {
    const expected = try compute(std.testing.allocator);
    inline for (comptime std.meta.tags(Mutation)) |mutation| {
        const changed = try computeForAir(Mutated(mutation), std.testing.allocator);
        try std.testing.expect(!std.mem.eql(u8, &expected, &changed));
        if (mutation != .geometry) try std.testing.expectError(error.CompactPoseidonSpecializationMismatch, computeImpl(Mutated(mutation), true, std.testing.allocator));
    }
}

test "canonical Poseidon admission requires explicit legacy compatibility" {
    const allocator = std.testing.allocator;
    try validateAdmission(allocator, CANONICAL_DIGEST, .canonical_only);
    try validateAdmission(allocator, LEGACY_SOURCE_DIGEST, .allow_reviewed_legacy);
    try std.testing.expectError(error.UnadmittedCompactPoseidonIdentity, validateAdmission(allocator, LEGACY_SOURCE_DIGEST, .canonical_only));
    var corrupted = LEGACY_SOURCE_DIGEST;
    corrupted[0] ^= 1;
    try std.testing.expectError(error.UnadmittedCompactPoseidonIdentity, validateAdmission(allocator, corrupted, .allow_reviewed_legacy));
}
