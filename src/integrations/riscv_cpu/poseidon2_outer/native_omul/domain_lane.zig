//! Native 16-row M31 arithmetic; only Var challenge compression and random
//! accumulation use packed OM31. OODS uses the same scalar product authority.
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
    pub fn init(elements: @import("witness.zig").Elements, shift: O, coefficients: []const O) @This() {
        var out: @This() = undefined;
        for (&out.powers, elements.powers) |*value, scalar| value.* = Packed.splat(scalar);
        out.z = Packed.splat(elements.z);
        out.shift = Packed.splat(shift);
        for (&out.coefficients, 0..) |*value, i| value.* = Packed.splat(coefficients[Row.ROOTS - 1 - i]);
        return out;
    }
    pub fn accumulate(self: *const @This(), main: *const [Row.MAIN]Base, fixed: *const [Row.FIXED]Base, current: *const [3]Secure, previous: Secure) !Secure {
        var sum = Secure.zero();
        for (Row.evaluateFor(Base, main), self.coefficients[0..Row.ARITHMETIC_ROOTS]) |root, coefficient| sum = sum.add(coefficient.mulBase(root.v));
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
            sum = sum.add(Packed.mul(Packed.mul(delta, Packed.mul(d0, d1)).sub(numerator), self.coefficients[Row.ARITHMETIC_ROOTS + i]));
            prior = current[i];
        }
        return sum;
    }
};
