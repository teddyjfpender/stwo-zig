//! R7 dot arithmetic stays in 16-lane M31. Only Var compression/prefix and
//! random accumulation use packed OM31; OODS shares the scalar row authority.
const Core = @import("stwo_core");
const Fields = Core.fields.m31;
const Packed = Core.fields.packed_om31;
const O = Core.fields.om31.OM31;
const Row = @import("row.zig");
pub const Base = @import("../domain_lane.zig").Base;
pub const WIDTH = Fields.PACK_WIDTH;
pub const Secure = Packed.PackedOM31;
pub const Prepared = struct {
    powers: [6]Secure,
    z: Secure,
    shift: Secure,
    coefficients: [Row.ROOTS]Secure,
    pub fn init(elements: @import("outer_witness.zig").Elements, shift: O, coefficients: []const O) @This() {
        var out: @This() = undefined;
        for (&out.powers, elements.powers) |*value, scalar| value.* = Packed.splat(scalar);
        out.z = Packed.splat(elements.z);
        out.shift = Packed.splat(shift);
        for (&out.coefficients, 0..) |*value, i| value.* = Packed.splat(coefficients[Row.ROOTS - 1 - i]);
        return out;
    }
    pub fn accumulate(self: *const @This(), main: *const [Row.MAIN]Base, previous_main: *const [8]Base, fixed: *const [Row.FIXED]Base, current: *const [3]Secure, previous: Secure) !Secure {
        var sum = Secure.zero();
        for (Row.arithmeticFor(Base, main, previous_main, fixed), self.coefficients[0..8]) |root, coefficient| sum = sum.add(coefficient.mulBase(root.v));
        const ports = Row.portsFor(Base, main, fixed);
        var prior = Secure.zero();
        for (0..3) |i| {
            var d0 = self.z.neg();
            var d1 = d0;
            for (ports[2 * i].tuple, ports[2 * i + 1].tuple, self.powers) |a, b, power| {
                d0 = d0.add(power.mulBase(a.v));
                d1 = d1.add(power.mulBase(b.v));
            }
            const numerator = d1.mulBase(ports[2 * i].numerator.v).add(d0.mulBase(ports[2 * i + 1].numerator.v));
            const delta = if (i == 2) current[i].sub(previous).add(self.shift).sub(prior) else current[i].sub(prior);
            sum = sum.add(Packed.mul(Packed.mul(delta, Packed.mul(d0, d1)).sub(numerator), self.coefficients[8 + i]));
            prior = current[i];
        }
        return sum;
    }
};

test "OP R7 packed dot domain matches every scalar root across all sixteen lanes" {
    const std = @import("std");
    const M = Core.fields.m31.M31;
    var rng = std.Random.DefaultPrng.init(0x5237444f54);
    const random = rng.random();
    var main: [Row.MAIN]Base = undefined;
    var previous_main: [8]Base = undefined;
    var fixed: [Row.FIXED]Base = undefined;
    for (&main) |*v| for (0..WIDTH) |i| {
        v.v[i] = random.int(u32) % Fields.Modulus;
    };
    for (&previous_main) |*v| for (0..WIDTH) |i| {
        v.v[i] = random.int(u32) % Fields.Modulus;
    };
    for (&fixed) |*v| for (0..WIDTH) |i| {
        v.v[i] = random.int(u32) % Fields.Modulus;
    };
    var scalar_current: [WIDTH][3]O = undefined;
    var scalar_previous: [WIDTH]O = undefined;
    var current: [3]Secure = undefined;
    for (&current, 0..) |*v, index| {
        var coordinates: [8]Fields.PackedM31 = undefined;
        for (&coordinates) |*coordinate| for (0..WIDTH) |i| {
            coordinate[i] = random.int(u32) % Fields.Modulus;
        };
        v.* = Packed.fromCoordinates(coordinates);
        for (0..WIDTH) |i| scalar_current[i][index] = Packed.lane(v.*, i);
    }
    var previous_coordinates: [8]Fields.PackedM31 = undefined;
    for (&previous_coordinates) |*coordinate| for (0..WIDTH) |i| {
        coordinate[i] = random.int(u32) % Fields.Modulus;
    };
    const previous = Packed.fromCoordinates(previous_coordinates);
    for (0..WIDTH) |i| scalar_previous[i] = Packed.lane(previous, i);
    var coefficients: [Row.ROOTS]O = undefined;
    for (&coefficients) |*coefficient| {
        var coordinates: [8]M = undefined;
        for (&coordinates) |*v| v.* = M.fromCanonical(random.int(u32) % Fields.Modulus);
        coefficient.* = O.fromM31Array(coordinates);
    }
    const elements = @import("outer_witness.zig").Elements.init(coefficients[0], coefficients[1]);
    const shift = coefficients[2];
    const prepared = Prepared.init(elements, shift, &coefficients);
    const actual = try prepared.accumulate(&main, &previous_main, &fixed, &current, previous);
    for (0..WIDTH) |i| {
        var scalar_main: [Row.MAIN]O = undefined;
        var scalar_fixed: [Row.FIXED]O = undefined;
        var scalar_prior: [8]O = undefined;
        for (&scalar_main, main) |*v, lanes| v.* = O.fromBase(M.fromCanonical(lanes.v[i]));
        for (&scalar_fixed, fixed) |*v, lanes| v.* = O.fromBase(M.fromCanonical(lanes.v[i]));
        for (&scalar_prior, previous_main) |*v, lanes| v.* = O.fromBase(M.fromCanonical(lanes.v[i]));
        const roots = Row.rootsFor(O, &scalar_main, &scalar_prior, &scalar_fixed, &scalar_current[i], scalar_previous[i], elements.z, elements.powers, shift);
        var expected = O.zero();
        for (roots, 0..) |root, j| expected = expected.add(root.mul(coefficients[Row.ROOTS - 1 - j]));
        try std.testing.expect(expected.eql(Packed.lane(actual, i)));
    }
}
