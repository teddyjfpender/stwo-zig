//! Base-field SIMD domain authority for the dedicated P2 row.
//! OODS continues to use scalar OM31. Domain MAIN/FIXED roots stay M31;
//! only challenge compression, LogUp and random accumulation use packed OM31.
const Core = @import("stwo_core");
const F = Core.fields.m31;
const Packed = Core.fields.packed_om31;
const O = Core.fields.om31.OM31;
const Row = @import("row.zig");
const L = @import("layout.zig");
pub const WIDTH = F.PACK_WIDTH;
pub const Secure = Packed.PackedOM31;
pub const ROOTS = L.CONSTRAINTS + 24;
pub const Base = struct {
    v: F.PackedM31,
    pub inline fn zero() @This() {
        return .{ .v = @splat(0) };
    }
    pub inline fn fromBase(value: F.M31) @This() {
        return .{ .v = @splat(value.v) };
    }
    pub inline fn add(a: @This(), b: @This()) @This() {
        return .{ .v = F.addPacked(a.v, b.v) };
    }
    pub inline fn sub(a: @This(), b: @This()) @This() {
        return .{ .v = F.subPacked(a.v, b.v) };
    }
    pub inline fn mul(a: @This(), b: @This()) @This() {
        return .{ .v = F.mulPacked(a.v, b.v) };
    }
};
pub const Prepared = struct {
    powers: [6]Secure,
    z: Secure,
    shift: Secure,
    coefficients: [ROOTS]Secure,
    pub fn init(elements: @import("witness.zig").Elements, shift: O, coefficients: []const O) @This() {
        var out: @This() = undefined;
        for (&out.powers, elements.powers) |*power, value| power.* = Packed.splat(value);
        out.z = Packed.splat(elements.z);
        out.shift = Packed.splat(shift);
        for (&out.coefficients, 0..) |*coefficient, i| coefficient.* = Packed.splat(coefficients[ROOTS - 1 - i]);
        return out;
    }
    pub inline fn accumulate(self: *const @This(), main: *const [L.MAIN_COLUMNS]Base, fixed: *const [L.FIXED_COLUMNS]Base, current: *const [24]Secure, previous: Secure) !Secure {
        var sum = Secure.zero();
        for (try Row.evaluateFor(Base, main), self.coefficients[0..L.CONSTRAINTS]) |root, coefficient| sum = sum.add(coefficient.mulBase(root.v));
        const ports = Row.portsFor(Base, main, fixed);
        var prior = Secure.zero();
        for (0..24) |i| {
            var d0 = self.z.neg();
            var d1 = self.z.neg();
            for (ports[2 * i].tuple, ports[2 * i + 1].tuple, self.powers) |a, b, power| {
                d0 = d0.add(power.mulBase(a.v));
                d1 = d1.add(power.mulBase(b.v));
            }
            const numerator = d1.mulBase(ports[2 * i].numerator.v).add(d0.mulBase(ports[2 * i + 1].numerator.v));
            const delta = if (i == 23) current[i].sub(previous).add(self.shift).sub(prior) else current[i].sub(prior);
            const root = Packed.mul(delta, Packed.mul(d0, d1)).sub(numerator);
            sum = sum.add(Packed.mul(root, self.coefficients[L.CONSTRAINTS + i]));
            prior = current[i];
        }
        return sum;
    }
};
