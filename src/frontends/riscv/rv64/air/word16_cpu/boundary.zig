//! Public register endpoints through immutable32-row selector polynomials.
//! A request changes public coefficients only, never the fixed tree.
const E = @import("../evaluation.zig");
const P = @import("public.zig");
const Lookup = @import("lookup.zig");
pub const FIXED = 34;
pub const INTERACTION = 8;
pub const CONSTRAINTS = 3;
pub fn PublicFor(comptime C: type) type {
    E.assertConstLane(C);
    return if (C == E.Q) P.Public else struct {
        initial_registers: [32][4]C,
        final_registers: [32][4]C,
        register_clocks: [32]C,
    };
}
/// The only selector/tuple arithmetic. Initial clocks are unconditionally0.
pub fn tupleFromWordsFor(comptime F: type, fixed: []const F, words: *const [32][4]F, clocks: *const [32]F, after: bool) [6]F {
    var tuple: [6]F = @splat(F.zero());
    for (0..32) |register| {
        const selector = fixed[register];
        tuple[0] = tuple[0].add(selector.mul(P.literal(F, @intCast(register))));
        for (0..4) |limb| tuple[1 + limb] = tuple[1 + limb].add(selector.mul(words[register][limb]));
        if (after) tuple[5] = tuple[5].add(selector.mul(clocks[register]));
    }
    return tuple;
}
pub fn tupleFor(comptime F: type, fixed: []const F, public: P.Public, after: bool) [6]F {
    var words: [32][4]F = undefined;
    var clocks: [32]F = undefined;
    for (0..32) |register| {
        words[register] = P.word(F, if (after) public.final_registers[register] else public.initial_registers[register]);
        if (after) clocks[register] = P.literal(F, public.register_clocks[register]);
    }
    return tupleFromWordsFor(F, fixed, &words, &clocks, after);
}
pub fn tupleWithInputsFor(comptime F: type, fixed: []const F, public: PublicFor(E.ConstFor(F)), after: bool) [6]F {
    if (comptime E.ConstFor(F) == E.Q) return tupleFor(F, fixed, public, after);
    return tupleFromWordsFor(F, fixed, if (after) &public.final_registers else &public.initial_registers, &public.register_clocks, after);
}
pub fn emitFor(comptime F: type, fixed: []const F, current: []const F, previous: []const F, public: P.Public, claim: E.Q, challenges: Lookup.RegisterChallenges, sink: *E.SinkFor(F)) void {
    emitWithInputsFor(F, fixed, current, previous, public, claim, challenges, sink);
}
pub fn emitWithInputsFor(comptime F: type, fixed: []const F, current: []const F, previous: []const F, public: PublicFor(E.ConstFor(F)), claim: E.ConstFor(F), challenges: Lookup.RegisterChallengesFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    const before = challenges.denominatorFor(F, tupleWithInputsFor(F, fixed, public, false));
    const after = challenges.denominatorFor(F, tupleWithInputsFor(F, fixed, public, true));
    const inverse = E.secureFor(F, current, 0);
    sink.emit(before.mul(after).mul(inverse).sub(E.SecureFor(F).one()));
    // Opposite the CPU before−after sign: global closure contains this once.
    Lookup.prefix(F, before.sub(after).mul(inverse), E.secureFor(F, current, 4), E.secureFor(F, previous, 4), fixed[32], fixed[33], claim, sink);
}
