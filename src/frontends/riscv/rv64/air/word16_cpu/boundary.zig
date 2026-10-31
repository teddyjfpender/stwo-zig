//! Public register endpoints through immutable32-row selector polynomials.
//! A request changes public coefficients only, never the fixed tree.
const E = @import("../evaluation.zig");
const P = @import("public.zig");
const Lookup = @import("lookup.zig");
pub const FIXED = 34;
pub const INTERACTION = 8;
pub const CONSTRAINTS = 3;
pub fn tupleFor(comptime F: type, fixed: []const F, public: P.Public, after: bool) [6]F {
    var tuple: [6]F = @splat(F.zero());
    for (0..32) |register| {
        const selector = fixed[register];
        tuple[0] = tuple[0].add(selector.mul(P.literal(F, @intCast(register))));
        const value = P.word(F, if (after) public.final_registers[register] else public.initial_registers[register]);
        for (0..4) |limb| tuple[1 + limb] = tuple[1 + limb].add(selector.mul(value[limb]));
        if (after) tuple[5] = tuple[5].add(selector.mul(P.literal(F, public.register_clocks[register])));
    }
    return tuple;
}
pub fn emitFor(comptime F: type, fixed: []const F, current: []const F, previous: []const F, public: P.Public, claim: E.Q, challenges: Lookup.RegisterChallenges, sink: *E.SinkFor(F)) void {
    const before = challenges.denominatorFor(F, tupleFor(F, fixed, public, false));
    const after = challenges.denominatorFor(F, tupleFor(F, fixed, public, true));
    const inverse = E.secureFor(F, current, 0);
    sink.emit(before.mul(after).mul(inverse).sub(E.SecureFor(F).one()));
    // Opposite the CPU before−after sign: global closure contains this once.
    Lookup.prefix(F, before.sub(after).mul(inverse), E.secureFor(F, current, 4), E.secureFor(F, previous, 4), fixed[32], fixed[33], claim, sink);
}
