//! Stark-V-compatible LogUp relation challenges.
//!
//! Pinned Stark-V draws one `(z, alpha)` pair per relation, in schema order.
//! A tuple `(v_0, ..., v_n)` combines as
//! `v_0 + alpha*v_1 + ... + alpha^n*v_n - z`.
//! There is no relation-ID term and challenges are not shared across buses.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const RELATION_COUNT: usize = 12;
pub const CHALLENGES_PER_RELATION: usize = 2;
pub const DRAW_COUNT: usize = RELATION_COUNT * CHALLENGES_PER_RELATION;

pub fn RelationElements(comptime arity: usize) type {
    return struct {
        z: QM31,
        alpha: QM31,
        alpha_powers: [arity]QM31,

        const Self = @This();

        pub fn init(z: QM31, alpha: QM31) Self {
            var power = QM31.one();
            var powers: [arity]QM31 = undefined;
            for (&powers) |*slot| {
                slot.* = power;
                power = power.mul(alpha);
            }
            return .{ .z = z, .alpha = alpha, .alpha_powers = powers };
        }

        pub fn dummy() Self {
            return init(
                QM31.fromU32Unchecked(1, 2, 3, 4),
                QM31.fromU32Unchecked(4, 3, 2, 1),
            );
        }

        pub fn combineBase(self: Self, values: [arity]M31) QM31 {
            var result = QM31.zero();
            for (values, self.alpha_powers) |value, power| {
                result = result.add(power.mulM31(value));
            }
            return result.sub(self.z);
        }

        pub fn combineSecure(self: Self, values: [arity]QM31) QM31 {
            return self.combine(values);
        }

        /// Common relation interface used by generic AIR recorders. Native
        /// challenges remain concrete QM31 values; recursive recorders provide
        /// their own relation type with the same method surface.
        pub fn combine(self: Self, values: [arity]QM31) QM31 {
            var result = QM31.zero();
            for (values, self.alpha_powers) |value, power| {
                result = result.add(power.mul(value));
            }
            return result.sub(self.z);
        }
    };
}

/// Relation fields and draw order from pinned Stark-V `schema.rs`.
pub const Relations = struct {
    registers_state: RelationElements(2),
    memory_access: RelationElements(7),
    program_access: RelationElements(5),
    merkle: RelationElements(4),
    poseidon2: RelationElements(16),
    poseidon2_io: RelationElements(32),
    bitwise: RelationElements(4),
    range_check_20: RelationElements(1),
    range_check_8_11: RelationElements(2),
    range_check_8_8_4: RelationElements(3),
    range_check_8_8: RelationElements(2),
    range_check_m31: RelationElements(2),

    /// Draws all 12 pairs in one aligned bulk call. Each pair consumes one
    /// Blake2s output in the Rust oracle, so this is transcript-equivalent to
    /// twelve `draw_secure_felts(2)` calls without twelve allocations.
    pub fn draw(allocator: std.mem.Allocator, channel: anytype) !Relations {
        const values = try channel.drawSecureFelts(
            allocator,
            DRAW_COUNT,
        );
        defer allocator.free(values);
        std.debug.assert(values.len == DRAW_COUNT);
        return fromDraws(values);
    }

    /// Copies the exact transcript draw sequence `(z, alpha)` for all relation
    /// buses into caller-owned storage. This is the recursion leaf sidecar's
    /// single authority for challenge order; it deliberately does not expose
    /// derived alpha powers.
    pub fn writeDraws(self: Relations, destination: []QM31) error{OutputLengthMismatch}!void {
        if (destination.len != DRAW_COUNT) return error.OutputLengthMismatch;
        writePair(destination, 0, self.registers_state);
        writePair(destination, 1, self.memory_access);
        writePair(destination, 2, self.program_access);
        writePair(destination, 3, self.merkle);
        writePair(destination, 4, self.poseidon2);
        writePair(destination, 5, self.poseidon2_io);
        writePair(destination, 6, self.bitwise);
        writePair(destination, 7, self.range_check_20);
        writePair(destination, 8, self.range_check_8_11);
        writePair(destination, 9, self.range_check_8_8_4);
        writePair(destination, 10, self.range_check_8_8);
        writePair(destination, 11, self.range_check_m31);
    }

    /// Reconstructs the canonical relation suite from the exact verifier-owned
    /// draw sequence captured at the native-to-recursive boundary. The fixed
    /// array type makes truncation, extension, and schema-order ambiguity
    /// unrepresentable at this seam.
    pub fn fromDrawSequence(values: *const [DRAW_COUNT]QM31) Relations {
        return fromDraws(values);
    }

    pub fn dummy() Relations {
        return .{
            .registers_state = .dummy(),
            .memory_access = .dummy(),
            .program_access = .dummy(),
            .merkle = .dummy(),
            .poseidon2 = .dummy(),
            .poseidon2_io = .dummy(),
            .bitwise = .dummy(),
            .range_check_20 = .dummy(),
            .range_check_8_11 = .dummy(),
            .range_check_8_8_4 = .dummy(),
            .range_check_8_8 = .dummy(),
            .range_check_m31 = .dummy(),
        };
    }

    fn fromDraws(values: []const QM31) Relations {
        return .{
            .registers_state = pair(2, values, 0),
            .memory_access = pair(7, values, 1),
            .program_access = pair(5, values, 2),
            .merkle = pair(4, values, 3),
            .poseidon2 = pair(16, values, 4),
            .poseidon2_io = pair(32, values, 5),
            .bitwise = pair(4, values, 6),
            .range_check_20 = pair(1, values, 7),
            .range_check_8_11 = pair(2, values, 8),
            .range_check_8_8_4 = pair(3, values, 9),
            .range_check_8_8 = pair(2, values, 10),
            .range_check_m31 = pair(2, values, 11),
        };
    }
};

fn writePair(destination: []QM31, index: usize, relation: anytype) void {
    destination[2 * index] = relation.z;
    destination[2 * index + 1] = relation.alpha;
}

fn pair(comptime arity: usize, values: []const QM31, index: usize) RelationElements(arity) {
    return RelationElements(arity).init(values[2 * index], values[2 * index + 1]);
}

test "relation challenges: combine matches Stark-V alpha-power convention" {
    const relation = RelationElements(3).dummy();
    const values = [3]M31{
        M31.fromU64(11),
        M31.fromU64(22),
        M31.fromU64(33),
    };
    const expected = QM31.fromBase(values[0])
        .add(relation.alpha.mulM31(values[1]))
        .add(relation.alpha.square().mulM31(values[2]))
        .sub(relation.z);
    try std.testing.expect(relation.combineBase(values).eql(expected));
}

test "relation challenges: bulk draw matches twelve oracle pair draws" {
    const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const allocator = std.testing.allocator;
    var actual_channel = Blake2sChannel{};
    var oracle_channel = Blake2sChannel{};

    const actual = try Relations.draw(allocator, &actual_channel);
    var oracle_draws: [RELATION_COUNT * CHALLENGES_PER_RELATION]QM31 = undefined;
    for (0..RELATION_COUNT) |i| {
        const relation_pair = try oracle_channel.drawSecureFelts(allocator, 2);
        defer allocator.free(relation_pair);
        oracle_draws[2 * i] = relation_pair[0];
        oracle_draws[2 * i + 1] = relation_pair[1];
    }
    const expected = Relations.fromDraws(&oracle_draws);

    try std.testing.expect(actual.registers_state.z.eql(expected.registers_state.z));
    try std.testing.expect(actual.memory_access.alpha.eql(expected.memory_access.alpha));
    try std.testing.expect(actual.merkle.z.eql(expected.merkle.z));
    try std.testing.expect(actual.range_check_m31.alpha.eql(expected.range_check_m31.alpha));
    try std.testing.expect(actual_channel.drawSecureFelt().eql(oracle_channel.drawSecureFelt()));
}

test "relation challenges: writeDraws preserves schema order" {
    var values: [DRAW_COUNT]QM31 = undefined;
    for (&values, 0..) |*value, index| {
        value.* = QM31.fromU32Unchecked(@intCast(index + 1), 0, 0, 0);
    }
    const relations = Relations.fromDrawSequence(&values);
    var copied: [DRAW_COUNT]QM31 = undefined;
    try relations.writeDraws(&copied);
    for (values, copied) |expected, actual| {
        try std.testing.expect(actual.eql(expected));
    }
    try std.testing.expectError(
        error.OutputLengthMismatch,
        relations.writeDraws(copied[0 .. copied.len - 1]),
    );
}

test "relation challenges: default-channel limbs match pinned Stark-V" {
    const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    var channel = Blake2sChannel{};
    const relations = try Relations.draw(std.testing.allocator, &channel);

    // Generated by `Relations::draw`'s exact `draw_secure_felts(2)` schedule
    // at Stark-V d478f783055aa0d73a93768a433a3c6c31c91d1c.
    try expectLimbs(relations.registers_state.z, .{
        1508103417, 49928118, 1851109195, 649450964,
    });
    try expectLimbs(relations.registers_state.alpha, .{
        1514800545, 2089281384, 523819246, 1919080973,
    });
    try expectLimbs(relations.memory_access.z, .{
        1769619091, 1335149496, 2007506569, 1426464368,
    });
    try expectLimbs(relations.memory_access.alpha, .{
        853727757, 1673676888, 635879929, 1327640380,
    });
    try expectLimbs(relations.range_check_m31.z, .{
        393284205, 195320790, 1304366664, 1916406947,
    });
    try expectLimbs(relations.range_check_m31.alpha, .{
        64355569, 53204588, 185957963, 406633176,
    });
}

fn expectLimbs(actual: QM31, expected: [4]u32) !void {
    for (actual.toM31Array(), expected) |limb, expected_limb| {
        try std.testing.expectEqual(expected_limb, limb.toU32());
    }
}
