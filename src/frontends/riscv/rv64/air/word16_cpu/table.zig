//! Sparse ROM / U16 / U8 physical provider equations. Actual multiplicities
//! commit before challenges; all three closures have independent typed claims.
const E = @import("../evaluation.zig");
const Lookup = @import("lookup.zig");
pub fn romFor(comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, claim: E.Q, challenges: Lookup.RomChallenges, sink: *E.SinkFor(F)) void {
    const tuple = fixed[0..16].*;
    Lookup.single(F, challenges.denominatorFor(F, tuple), main[0].neg(), E.secureFor(F, current, 0), E.secureFor(F, current, 4), E.secureFor(F, previous, 4), fixed[16], fixed[17], claim, sink);
    sink.emit(main[0].mul(F.one().sub(fixed[0])));
}
pub fn rangeFor(comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, claim: E.Q, challenges: Lookup.RangeChallenges, sink: *E.SinkFor(F)) void {
    Lookup.single(F, challenges.denominatorFor(F, fixed[0]), main[0].neg(), E.secureFor(F, current, 0), E.secureFor(F, current, 4), E.secureFor(F, previous, 4), fixed[1], fixed[2], claim, sink);
}
