//! One proof-local relation namespace. Draw ONLY after sealed FIXED+MAIN and
//! the trusted statement/program/ordinal have entered the local transcript.
const std = @import("std");
const builtin = @import("builtin");
const fields = @import("stwo_core").fields;
const M = fields.m31.M31;
const O = fields.om31.OM31;
const E = @import("stwo_riscv_frontend").rv64_air.evaluation;
const R = @import("fractions.zig");
pub fn For(comptime C: type) type {
    return struct {
        offsets: [std.enums.values(R.Relation).len]C,
        coefficients: [std.enums.values(R.Relation).len][R.MAX_ARITY]C,
        /// V2 draws exactly its original nine namespaces; the appended V3
        /// namespace is initialized but draws no transcript bytes by default.
        pub fn draw(channel: anytype) @This() {
            return drawMode(channel, false);
        }
        pub fn drawV3(channel: anytype) @This() {
            return drawMode(channel, true);
        }
        pub fn drawForInstances(channel: anytype, instances: []const @import("frame.zig").Instance) @This() {
            for (instances) |instance| if (instance.origin == .core and instance.origin.core == .cpu and instance.terms == 14) return drawV3(channel);
            return draw(channel);
        }
        pub fn drawMode(channel: anytype, v3: bool) @This() {
            const relations = std.enums.values(R.Relation);
            const count: usize = if (v3) relations.len else @intFromEnum(R.Relation.byte_pair);
            channel.mixU32s(&.{ if (v3) @as(u32, 0x4c474b33) else 0x4c474b31, 8, @intCast(count) });
            var out = @This(){ .offsets = @splat(C.zero()), .coefficients = @splat(@splat(C.zero())) };
            for (relations[0..count]) |relation| {
                const index = @intFromEnum(relation);
                channel.mixU32s(&.{ @intCast(index), @intCast(relation.arity()) });
                out.offsets[index] = channel.drawSecureFelt();
                for (0..relation.arity()) |i| out.coefficients[index][i] = if (relation == .range8) C.one() else channel.drawSecureFelt();
            }
            return out;
        }
        /// Native metadata is base-valued. Keep every tuple product a small
        /// M31 by OM31 multiply rather than promoting both operands to OM31.
        pub fn denominatorBase(self: *const @This(), relation: R.Relation, tuple: anytype) C {
            std.debug.assert(tuple.len == relation.arity());
            const index = @intFromEnum(relation);
            if (comptime C == O and builtin.cpu.arch == .x86_64 and std.Target.x86.featureSetHas(builtin.cpu.features, .avx512f)) {
                const values: []const M = if (@typeInfo(@TypeOf(tuple)) == .array) &tuple else tuple;
                return denominatorOctic(self.offsets[index], self.coefficients[index][0..values.len], values);
            }
            var d = self.offsets[index];
            for (tuple, 0..) |value, i| d = d.sub(self.coefficients[index][i].mulM31(value));
            return d;
        }
        pub fn denominatorFor(self: *const @This(), comptime F: type, relation: R.Relation, tuple: anytype) E.SecureFor(F) {
            std.debug.assert(tuple.len == relation.arity());
            const index = @intFromEnum(relation);
            var d = E.splatFor(F, self.offsets[index]);
            for (tuple, 0..) |value, i| d = d.sub(E.mulBaseFor(F, E.splatFor(F, self.coefficients[index][i]), value));
            return d;
        }
    };
}

const Words = @Vector(8, u32);
const Wide = @Vector(8, u64);

inline fn octicWords(value: O) Words {
    var result: Words = undefined;
    inline for (value.toM31Array(), 0..) |coordinate, i| result[i] = coordinate.v;
    return result;
}

inline fn subtractProducts(current: Words, products: Wide) Words {
    const prime: Wide = @splat(fields.m31.Modulus);
    const shifts: @Vector(8, u6) = @splat(31);
    const first = (products & prime) + (products >> shifts);
    const second = (first & prime) + (first >> shifts);
    const reduced: Words = @intCast(@min(second, second -% prime));
    return @min(current -% reduced, (current + @as(Words, @splat(fields.m31.Modulus))) -% reduced);
}

/// Four canonical products fit in u64. Reduce once per group rather than
/// separately for every coordinate of every tuple item.
fn denominatorOctic(offset: O, coefficients: []const O, values: []const M) O {
    var result = octicWords(offset);
    var products: Wide = @splat(0);
    for (coefficients, values, 0..) |coefficient, value, i| {
        const v: Wide = @splat(value.v);
        products += @as(Wide, octicWords(coefficient)) * v;
        if ((i & 3) == 3) {
            result = subtractProducts(result, products);
            products = @splat(0);
        }
    }
    if (values.len % 4 != 0) result = subtractProducts(result, products);
    var coordinates: [8]M = undefined;
    inline for (0..8) |i| coordinates[i] = M.fromCanonical(result[i]);
    return O.fromM31Array(coordinates);
}

test "octic dot groups match scalar reduction across all tuple widths" {
    var random = std.Random.DefaultPrng.init(0x3eb9_9001_c083_4c7c);
    var coefficients: [R.MAX_ARITY]O = undefined;
    var values: [R.MAX_ARITY]M = undefined;
    for (0..32) |round| {
        for (&coefficients, &values) |*coefficient, *value| {
            var coordinates: [8]M = undefined;
            for (&coordinates) |*coordinate| {
                coordinate.* = M.fromCanonical(if (round == 0) fields.m31.Modulus - 1 else random.random().uintLessThan(u32, fields.m31.Modulus));
            }
            coefficient.* = O.fromM31Array(coordinates);
            value.* = M.fromCanonical(if (round == 0) fields.m31.Modulus - 1 else random.random().uintLessThan(u32, fields.m31.Modulus));
        }
        for (0..R.MAX_ARITY + 1) |len| {
            const offset = if (round % 2 == 0) O.zero() else coefficients[0];
            var expected = offset;
            for (coefficients[0..len], values[0..len]) |coefficient, value| expected = expected.sub(coefficient.mulM31(value));
            try std.testing.expectEqualDeep(expected, denominatorOctic(offset, coefficients[0..len], values[0..len]));
        }
    }
}
