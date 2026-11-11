//! Exact affine before/after denominator sharing. R.tuple remains the tuple
//! authority; only its literal zero/one register fields and common event data
//! are factored. No active-slot or Boolean shortcut is used at OODS points.
const E = @import("evaluation.zig");
const R = @import("relations.zig");
const Q = E.Q;
pub fn evaluate(v: E.View, index: Q, challenges: R.Challenges) [8]Q {
    return evaluateFor(Q, v, index, challenges);
}
pub fn evaluateFor(comptime F: type, v: E.ViewFor(F), index: F, challenges: R.ChallengesFor(E.ConstFor(F))) [8]E.SecureFor(F) {
    const c = &challenges.coefficients;
    const register_base = E.splatFor(F, challenges.offset.add(c[18]).add(c[19]));
    const tick_base = index.mul(E.qFor(F, 4));
    var result: [8]E.SecureFor(F) = undefined;
    inline for (0..4) |slot| {
        const pair = @call(if (@import("builtin").mode == .Debug) .never_inline else .always_inline, pairFor, .{ F, slot, v, tick_base, register_base, challenges });
        result[2 * slot] = pair[0];
        result[2 * slot + 1] = pair[1];
    }
    return result;
}

// Keep each unoptimized slot's packed temporaries in its own bounded frame.
// Optimized callers retain the original mandatory slot expansion.
fn pairFor(comptime F: type, comptime slot: usize, v: E.ViewFor(F), tick_base: F, register_base: E.SecureFor(F), challenges: R.ChallengesFor(E.ConstFor(F))) [2]E.SecureFor(F) {
    const c = &challenges.coefficients;
    const entry = R.tupleFor(F, v, slot, true);
    var before = if (slot < 3)
        register_base.add(E.mulBaseFor(F, E.splatFor(F, c[1]), entry[1]))
    else
        E.splatFor(F, challenges.offset.add(c[0])).add(E.mulBaseFor(F, E.splatFor(F, c[18]), entry[18])).add(E.mulBaseFor(F, E.splatFor(F, c[19]), entry[19]));
    if (slot == 3) {
        for (0..8) |byte| before = before.add(E.mulBaseFor(F, E.splatFor(F, c[1 + byte]), entry[1 + byte]));
    }
    before = before.add(E.mulBaseFor(F, E.splatFor(F, c[9]), entry[9]));
    for (0..8) |byte| before = before.add(E.mulBaseFor(F, E.splatFor(F, c[10 + byte]), entry[10 + byte]));
    const after_clock = tick_base.add(E.qFor(F, slot + 1));
    var after = before.add(E.mulBaseFor(F, E.splatFor(F, c[9]), after_clock.sub(entry[9])));
    if (slot >= 2) {
        const terminal = R.tupleFor(F, v, slot, false);
        for (0..8) |byte| after = after.add(E.mulBaseFor(F, E.splatFor(F, c[10 + byte]), terminal[10 + byte].sub(entry[10 + byte])));
    }
    return .{ before, after };
}
