//! Canonical shared-provider challenge admission and immutable receipt encoding.
const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const base_relations = @import("../../air/relation_challenges.zig");
const relation = @import("../../air/lang/relation.zig");
const universal = @import("universal_challenges.zig");
pub const Error = universal.Error || relation.Error || error{ChallengeBindingMismatch};

pub const SHARED_RELATION_BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-shared-provider-relations/v1\x00";
/// Stable, caller-owned challenge storage for the two native providers.
///
/// The shipped base Merkle relation has a known 4-vs-18 arity gap and is
/// intentionally initialized to its deterministic dummy value.  No adapter
/// in this module exposes a Merkle component.  Every other base relation has
/// exact universal geometry and is copied from the corresponding `(z, alpha)`
/// draw, preserving the original alpha-power convention.
pub const SharedProviderRelations = struct {
    native: base_relations.Relations,
    registry_order_digest: [32]u8,

    pub fn init(
        source: *const universal.UniversalRelations,
    ) Error!SharedProviderRelations {
        try source.validate();
        // Every exact-schema arity, canonical limb, and cached alpha power is
        // checked while copying. Avoid rebuilding all twelve power tables a
        // second time on this common admission path.
        return SharedProviderRelations.initFromValidatedSource(source);
    }

    /// Validates the copied challenge representation without retaining the
    /// much larger universal bundle. This catches mutable-alias drift in both
    /// `(z, alpha)` and the cached alpha powers before component type erasure.
    pub fn validate(self: *const SharedProviderRelations) Error!void {
        if (!std.mem.eql(
            u8,
            &self.registry_order_digest,
            &relation.registryOrderDigest(),
        )) return error.ChallengeBindingMismatch;
        try validateNativeElement(2, &self.native.registers_state);
        try validateNativeElement(7, &self.native.memory_access);
        try validateNativeElement(5, &self.native.program_access);
        const dummy_merkle = base_relations.RelationElements(4).dummy();
        if (!relationEql(
            4,
            &self.native.merkle,
            &dummy_merkle,
        )) return error.ChallengeBindingMismatch;
        try validateNativeElement(16, &self.native.poseidon2);
        try validateNativeElement(32, &self.native.poseidon2_io);
        try validateNativeElement(4, &self.native.bitwise);
        try validateNativeElement(1, &self.native.range_check_20);
        try validateNativeElement(2, &self.native.range_check_8_11);
        try validateNativeElement(3, &self.native.range_check_8_8_4);
        try validateNativeElement(2, &self.native.range_check_8_8);
        try validateNativeElement(2, &self.native.range_check_m31);
    }

    /// Canonical cold-path receipt used by adapters to detect any mutation of
    /// their caller-owned relation storage between admission and binding.
    pub fn identityDigest(self: *const SharedProviderRelations) Error![32]u8 {
        try self.validate();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(SHARED_RELATION_BINDING_DOMAIN);
        hash.update(&self.registry_order_digest);
        hashRelation(&hash, &self.native.registers_state);
        hashRelation(&hash, &self.native.memory_access);
        hashRelation(&hash, &self.native.program_access);
        hashRelation(&hash, &self.native.merkle);
        hashRelation(&hash, &self.native.poseidon2);
        hashRelation(&hash, &self.native.poseidon2_io);
        hashRelation(&hash, &self.native.bitwise);
        hashRelation(&hash, &self.native.range_check_20);
        hashRelation(&hash, &self.native.range_check_8_11);
        hashRelation(&hash, &self.native.range_check_8_8_4);
        hashRelation(&hash, &self.native.range_check_8_8);
        hashRelation(&hash, &self.native.range_check_m31);
        return hash.finalResult();
    }

    pub fn validateAgainst(
        self: *const SharedProviderRelations,
        source: *const universal.UniversalRelations,
    ) Error!void {
        try source.validate();
        try self.validate();
        if (!std.mem.eql(
            u8,
            &self.registry_order_digest,
            &source.registry_order_digest,
        )) return error.ChallengeBindingMismatch;
        const expected = try SharedProviderRelations.initFromValidatedSource(source);
        if (!nativeRelationsEql(&self.native, &expected.native))
            return error.ChallengeBindingMismatch;
    }

    fn initFromValidatedSource(
        source: *const universal.UniversalRelations,
    ) Error!SharedProviderRelations {
        return .{
            .native = .{
                .registers_state = try relationElements(2, source, .registers_state),
                .memory_access = try relationElements(7, source, .memory_access),
                .program_access = try relationElements(5, source, .program_access),
                .merkle = base_relations.RelationElements(4).dummy(),
                .poseidon2 = try relationElements(16, source, .poseidon2),
                .poseidon2_io = try relationElements(32, source, .poseidon2_io),
                .bitwise = try relationElements(4, source, .bitwise),
                .range_check_20 = try relationElements(1, source, .range_check_20),
                .range_check_8_11 = try relationElements(2, source, .range_check_8_11),
                .range_check_8_8_4 = try relationElements(3, source, .range_check_8_8_4),
                .range_check_8_8 = try relationElements(2, source, .range_check_8_8),
                .range_check_m31 = try relationElements(2, source, .range_check_m31),
            },
            .registry_order_digest = source.registry_order_digest,
        };
    }
};

fn relationElements(
    comptime arity: usize,
    source: *const universal.UniversalRelations,
    domain: relation.Domain,
) Error!base_relations.RelationElements(arity) {
    const schema = try relation.requireExactUniversalSchema(domain);
    const element = source.get(domain);
    if (schema.fields.len != arity or element.arity != arity)
        return error.ChallengeBindingMismatch;
    if (!secureIsCanonical(&element.z) or !secureIsCanonical(&element.alpha))
        return error.ChallengeBindingMismatch;
    for (element.alpha_powers[0..arity]) |*power| {
        if (!secureIsCanonical(power)) return error.ChallengeBindingMismatch;
    }
    const result = base_relations.RelationElements(arity).init(
        element.z,
        element.alpha,
    );
    for (0..arity) |index| {
        if (!secureEql(&result.alpha_powers[index], &element.alpha_powers[index]))
            return error.ChallengeBindingMismatch;
    }
    return result;
}

fn validateNativeElement(
    comptime arity: usize,
    element: *const base_relations.RelationElements(arity),
) Error!void {
    if (!secureIsCanonical(&element.z) or !secureIsCanonical(&element.alpha))
        return error.ChallengeBindingMismatch;
    for (&element.alpha_powers) |*power| {
        if (!secureIsCanonical(power)) return error.ChallengeBindingMismatch;
    }
    const expected = base_relations.RelationElements(arity).init(
        element.z,
        element.alpha,
    );
    if (!relationEql(arity, element, &expected))
        return error.ChallengeBindingMismatch;
}

fn nativeRelationsEql(
    lhs: *const base_relations.Relations,
    rhs: *const base_relations.Relations,
) bool {
    return relationEql(2, &lhs.registers_state, &rhs.registers_state) and
        relationEql(7, &lhs.memory_access, &rhs.memory_access) and
        relationEql(5, &lhs.program_access, &rhs.program_access) and
        relationEql(4, &lhs.merkle, &rhs.merkle) and
        relationEql(16, &lhs.poseidon2, &rhs.poseidon2) and
        relationEql(32, &lhs.poseidon2_io, &rhs.poseidon2_io) and
        relationEql(4, &lhs.bitwise, &rhs.bitwise) and
        relationEql(1, &lhs.range_check_20, &rhs.range_check_20) and
        relationEql(2, &lhs.range_check_8_11, &rhs.range_check_8_11) and
        relationEql(3, &lhs.range_check_8_8_4, &rhs.range_check_8_8_4) and
        relationEql(2, &lhs.range_check_8_8, &rhs.range_check_8_8) and
        relationEql(2, &lhs.range_check_m31, &rhs.range_check_m31);
}

fn relationEql(
    comptime arity: usize,
    lhs: *const base_relations.RelationElements(arity),
    rhs: *const base_relations.RelationElements(arity),
) bool {
    if (!secureEql(&lhs.z, &rhs.z) or !secureEql(&lhs.alpha, &rhs.alpha))
        return false;
    for (0..arity) |index| {
        if (!secureEql(&lhs.alpha_powers[index], &rhs.alpha_powers[index]))
            return false;
    }
    return lhs.alpha_powers.len == arity;
}

pub fn secureEql(lhs: *const QM31, rhs: *const QM31) bool {
    return lhs.c0.a.v == rhs.c0.a.v and
        lhs.c0.b.v == rhs.c0.b.v and
        lhs.c1.a.v == rhs.c1.a.v and
        lhs.c1.b.v == rhs.c1.b.v;
}

pub fn secureIsCanonical(value: *const QM31) bool {
    return value.c0.a.v < m31.Modulus and
        value.c0.b.v < m31.Modulus and
        value.c1.a.v < m31.Modulus and
        value.c1.b.v < m31.Modulus;
}

fn hashRelation(hash: anytype, element: anytype) void {
    hashInt(hash, u8, element.alpha_powers.len);
    hashSecure(hash, &element.z);
    hashSecure(hash, &element.alpha);
    for (&element.alpha_powers) |*power| hashSecure(hash, power);
}

fn hashSecure(hash: anytype, value: *const QM31) void {
    hashInt(hash, u32, value.c0.a.v);
    hashInt(hash, u32, value.c0.b.v);
    hashInt(hash, u32, value.c1.a.v);
    hashInt(hash, u32, value.c1.b.v);
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
