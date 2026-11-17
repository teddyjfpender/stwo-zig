//! Base-numerator/secure-denominator fraction specialization for GKR.
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const fraction = core.fraction;
pub fn ForField(comptime Secure: type) type {
    return struct {
        const BaseFraction = struct {
            numerator: M31,
            denominator: Secure,
            pub fn add(self: @This(), rhs: @This()) fraction.Fraction(Secure, Secure) {
                return .{ .numerator = rhs.denominator.mulM31(self.numerator).add(self.denominator.mulM31(rhs.numerator)), .denominator = self.denominator.mul(rhs.denominator) };
            }
        };
        pub fn baseFraction(n: M31, d: Secure) BaseFraction {
            return .{ .numerator = n, .denominator = d };
        }
    };
}
