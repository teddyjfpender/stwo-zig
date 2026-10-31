//! Concrete typed affine denominators for the thin CPU. Challenge drawing stays
//! in the one-PCS coordinator, after every participating main commitment.
const E = @import("../evaluation.zig");
const Profile = @import("profile.zig");
const Function = @import("../word16_v1/function_bus.zig");
pub const FunctionChallenges = Function.Challenges;
pub const RegisterChallenges = struct {
    offset: E.Q,
    coefficients: [6]E.Q,
    pub fn denominatorFor(self: @This(), comptime F: type, tuple: [6]F) E.SecureFor(F) {
        return E.denominatorFor(F, self.offset, &self.coefficients, &tuple, true);
    }
};
pub const RomChallenges = struct {
    offset: E.Q,
    coefficients: [16]E.Q,
    control_coefficients: [7]E.Q = @splat(E.Q.zero()),
    pub fn denominatorProfile(self: @This(), comptime F: type, profile: Profile.Profile, tuple: [Profile.MAX_ROM]F) E.SecureFor(F) {
        var result = self.denominatorFor(F, tuple[0..16].*);
        if (profile == .alu_binary_v2) for (self.control_coefficients, tuple[16..]) |coefficient, value| {
            result = result.sub(E.mulBaseFor(F, E.splatFor(F, coefficient), value));
        };
        return result;
    }
    pub fn denominatorFor(self: @This(), comptime F: type, tuple: [16]F) E.SecureFor(F) {
        return E.denominatorFor(F, self.offset, &self.coefficients, &tuple, true);
    }
};
pub const RangeChallenges = @import("../providers/scalar_range.zig").Challenges;
pub const Challenges = struct { register: RegisterChallenges, function: FunctionChallenges, rom: RomChallenges, range16: RangeChallenges, range8: RangeChallenges };
pub const prefix = @import("../providers/scalar_range.zig").prefix;
pub const single = @import("../providers/scalar_range.zig").single;
