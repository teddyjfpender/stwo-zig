//! Exact 47-relation challenge bundle for the recursion universal AIR.
//!
//! The draw schedule and tuple arities are authenticated by
//! `relation.universal_descriptors`, not inferred from the currently shipped
//! VM schemas. In particular, the exact registry retains Merkle arity 18 and
//! universal adapters fail closed while the local VM Merkle ABI remains 4.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const relation = @import("../../air/lang/relation.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const RELATION_COUNT: usize = relation.UNIVERSAL_RELATION_COUNT;
pub const MAX_ARITY: usize = 33;
pub const CHALLENGES_PER_RELATION: usize = 2;
pub const DRAW_COUNT: usize = RELATION_COUNT * CHALLENGES_PER_RELATION;

/// Canonical identity of the exact relation order consumed by every universal
/// recursion challenge bundle.  Integration manifests use this narrow export
/// instead of reaching through the frontend module boundary to the typed-AIR
/// registry implementation.
pub fn registryOrderDigest() [32]u8 {
    return relation.registryOrderDigest();
}

pub const Error = error{
    InvalidArity,
    RegistryOrderMismatch,
} || relation.Error;

/// Uniform storage keeps relation selection branch-free in the hot row loop.
/// Only `alpha_powers[0..arity]` is semantically live.
pub const Elements = struct {
    z: QM31,
    alpha: QM31,
    alpha_powers: [MAX_ARITY]QM31,
    arity: u8,

    pub fn init(arity: u8, z: QM31, alpha: QM31) Elements {
        std.debug.assert(arity > 0 and arity <= MAX_ARITY);
        var power = QM31.one();
        var powers: [MAX_ARITY]QM31 = undefined;
        for (&powers) |*slot| {
            slot.* = power;
            power = power.mul(alpha);
        }
        return .{
            .z = z,
            .alpha = alpha,
            .alpha_powers = powers,
            .arity = arity,
        };
    }

    pub fn combineBase(self: *const Elements, values: []const M31) Error!QM31 {
        if (values.len != self.arity) return error.InvalidArity;
        var result = QM31.zero();
        for (values, self.alpha_powers[0..values.len]) |value, power| {
            result = result.add(power.mulM31(value));
        }
        return result.sub(self.z);
    }

    pub fn combineSecure(self: *const Elements, values: []const QM31) Error!QM31 {
        if (values.len != self.arity) return error.InvalidArity;
        var result = QM31.zero();
        for (values, self.alpha_powers[0..values.len]) |value, power| {
            result = result.add(power.mul(value));
        }
        return result.sub(self.z);
    }
};

pub const UniversalRelations = struct {
    format_version: u16,
    registry_order_digest: [32]u8,
    elements: [RELATION_COUNT]Elements,

    /// One bulk allocation replaces 47 tiny allocations. Blake2s channel
    /// consumption remains byte-for-byte equivalent to 47 pair draws; the
    /// equivalence test below protects that optimization.
    pub fn draw(
        allocator: std.mem.Allocator,
        channel: anytype,
    ) !UniversalRelations {
        try validateRegistryOrder();
        const values = try channel.drawSecureFelts(allocator, DRAW_COUNT);
        defer allocator.free(values);
        if (values.len != DRAW_COUNT) return error.RegistryOrderMismatch;
        return fromDraws(values);
    }

    pub fn dummy() UniversalRelations {
        var draws: [DRAW_COUNT]QM31 = undefined;
        for (0..RELATION_COUNT) |index| {
            draws[2 * index] = QM31.fromU32Unchecked(1, 2, 3, 4);
            draws[2 * index + 1] = QM31.fromU32Unchecked(4, 3, 2, 1);
        }
        return fromDraws(&draws);
    }

    pub fn validate(self: *const UniversalRelations) Error!void {
        try validateRegistryOrder();
        if (self.format_version != FORMAT_VERSION or
            !std.mem.eql(
                u8,
                &self.registry_order_digest,
                &registryOrderDigest(),
            ))
        {
            return error.RegistryOrderMismatch;
        }
        for (self.elements, relation.universal_descriptors) |element, descriptor| {
            if (element.arity != descriptor.arity)
                return error.RegistryOrderMismatch;
        }
    }

    pub fn get(
        self: *const UniversalRelations,
        domain: relation.Domain,
    ) *const Elements {
        return &self.elements[@intFromEnum(domain)];
    }

    /// Admission path for an exact universal adapter. This rejects the known
    /// base Merkle ABI gap instead of padding or truncating tuples.
    pub fn getExact(
        self: *const UniversalRelations,
        domain: relation.Domain,
    ) Error!*const Elements {
        try self.validate();
        _ = try relation.requireExactUniversalSchema(domain);
        return self.get(domain);
    }

    pub fn fromDraws(values: []const QM31) UniversalRelations {
        std.debug.assert(values.len == DRAW_COUNT);
        var elements: [RELATION_COUNT]Elements = undefined;
        for (&elements, relation.universal_descriptors, 0..) |
            *element,
            descriptor,
            index,
        | {
            element.* = Elements.init(
                descriptor.arity,
                values[2 * index],
                values[2 * index + 1],
            );
        }
        return .{
            .format_version = FORMAT_VERSION,
            .registry_order_digest = registryOrderDigest(),
            .elements = elements,
        };
    }
};

fn validateRegistryOrder() Error!void {
    const actual = std.fmt.bytesToHex(registryOrderDigest(), .lower);
    if (!std.mem.eql(u8, &actual, relation.REGISTRY_ORDER_DIGEST_HEX))
        return error.RegistryOrderMismatch;
}

test "R-012 universal challenges use exact 47-relation descriptor geometry" {
    const relations = UniversalRelations.dummy();
    try relations.validate();
    try std.testing.expectEqual(@as(usize, 47), relations.elements.len);
    try std.testing.expectEqual(
        @as(u8, 18),
        relations.get(.merkle).arity,
    );
    try std.testing.expectEqual(
        @as(u8, 33),
        relations.get(.recursion_query_bits).arity,
    );
    try std.testing.expectError(
        error.UniversalSchemaMismatch,
        relations.getExact(.merkle),
    );
    _ = try relations.getExact(.recursion_wire);
}

test "R-012 universal challenge bulk draw is transcript-equivalent to 47 pair draws" {
    const Blake2sChannel = stwo_core.channel.blake2s.Blake2sChannel;
    const allocator = std.testing.allocator;
    var actual_channel = Blake2sChannel{};
    var oracle_channel = Blake2sChannel{};

    const actual = try UniversalRelations.draw(allocator, &actual_channel);
    var oracle_draws: [DRAW_COUNT]QM31 = undefined;
    for (0..RELATION_COUNT) |index| {
        const pair = try oracle_channel.drawSecureFelts(allocator, 2);
        defer allocator.free(pair);
        oracle_draws[2 * index] = pair[0];
        oracle_draws[2 * index + 1] = pair[1];
    }
    const expected = UniversalRelations.fromDraws(&oracle_draws);
    for (actual.elements, expected.elements) |lhs, rhs| {
        try std.testing.expect(lhs.z.eql(rhs.z));
        try std.testing.expect(lhs.alpha.eql(rhs.alpha));
        try std.testing.expectEqual(lhs.arity, rhs.arity);
    }
    try std.testing.expect(
        actual_channel.drawSecureFelt().eql(oracle_channel.drawSecureFelt()),
    );
}

test "R-012 universal challenge bundle rejects seal and arity mutation" {
    var relations = UniversalRelations.dummy();
    relations.registry_order_digest[0] ^= 1;
    try std.testing.expectError(error.RegistryOrderMismatch, relations.validate());

    relations = UniversalRelations.dummy();
    relations.elements[@intFromEnum(relation.Domain.recursion_step)].arity -= 1;
    try std.testing.expectError(error.RegistryOrderMismatch, relations.validate());
}

test "R-012 universal challenge combine uses exact alpha-power convention" {
    const relations = UniversalRelations.dummy();
    const element = relations.get(.recursion_statement_word);
    const values = [_]M31{
        M31.fromU64(11),
        M31.fromU64(22),
        M31.fromU64(33),
    };
    const expected = QM31.fromBase(values[0])
        .add(element.alpha.mulM31(values[1]))
        .add(element.alpha.square().mulM31(values[2]))
        .sub(element.z);
    try std.testing.expect((try element.combineBase(&values)).eql(expected));
    try std.testing.expectError(
        error.InvalidArity,
        element.combineBase(values[0..2]),
    );
}

comptime {
    if (MAX_ARITY != @import("../../air/lang/effects.zig").MAX_ARITY)
        @compileError("universal challenge storage must track typed effect arity");
}
