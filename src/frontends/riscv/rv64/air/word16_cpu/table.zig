//! Sparse ROM / U16 / U8 physical provider equations. Actual multiplicities
//! commit before challenges; all three closures have independent typed claims.
const E = @import("../evaluation.zig");
const Profile = @import("profile.zig");
const Lookup = @import("lookup.zig");
pub fn romFor(comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, claim: E.Q, challenges: Lookup.RomChallenges, sink: *E.SinkFor(F)) void {
    romProfileFor(F, .binary_v1, fixed, main, current, previous, claim, challenges, sink);
}
pub fn romProfileFor(comptime F: type, profile: Profile.Profile, fixed: []const F, main: []const F, current: []const F, previous: []const F, claim: E.Q, challenges: Lookup.RomChallenges, sink: *E.SinkFor(F)) void {
    const count = Profile.romCount(profile);
    var tuple: [Profile.MAX_ROM]F = @splat(F.zero());
    @memcpy(tuple[0..count], fixed[0..count]);
    Lookup.single(F, challenges.denominatorProfile(F, profile, tuple), main[0].neg(), E.secureFor(F, current, 0), E.secureFor(F, current, 4), E.secureFor(F, previous, 4), fixed[count], fixed[count + 1], claim, sink);
    sink.emit(main[0].mul(F.one().sub(fixed[0])));
}

pub const rangeFor = @import("../providers/scalar_range.zig").rangeFor;
