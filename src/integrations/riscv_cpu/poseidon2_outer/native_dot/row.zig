//! Isolated secure-by-base dot accumulator. No live lane/prover route uses it.
//! Eight coordinates are inclusive sums; scalar ports authenticate a complete
//! QM31 value (s,0,0,0), not merely its first coordinate.
const std = @import("std");
const Core = @import("stwo_core");
const M = Core.fields.m31.M31;
pub const MAIN = 17;
pub const FIXED = 10;
pub const INTER = 24;
pub const INPUT_IDS = 0;
pub const OUTPUT_IDS = 3;
pub const OUTPUT_USES = 5;
pub const ENABLED = 7;
pub const FIRST = 8;
pub const LAST = 9;
pub const ACC = 9;
pub const ROOTS = 11;
pub const MAX_DEGREE = 3;
fn literal(comptime F: type, n: u32) F {
    return if (F == M) M.fromCanonical(n) else F.fromBase(M.fromCanonical(n));
}
pub fn arithmeticFor(comptime F: type, main: *const [MAIN]F, previous: *const [8]F, fixed: *const [FIXED]F) [8]F {
    var roots: [8]F = undefined;
    for (&roots, 0..) |*root, i| root.* = fixed[ENABLED].mul(main[ACC + i].sub(literal(F, 1).sub(fixed[FIRST]).mul(previous[i])).sub(main[i].mul(main[8])));
    return roots;
}
pub fn PortFor(comptime F: type) type {
    return struct { numerator: F, tuple: [6]F };
}
pub fn portsFor(comptime F: type, main: *const [MAIN]F, fixed: *const [FIXED]F) [6]PortFor(F) {
    const tag = literal(F, @import("stwo_circuit_frontend").common.component_list.GATE_RELATION_ID);
    var ports: [6]PortFor(F) = undefined;
    for (0..2) |i| ports[i] = .{ .numerator = fixed[ENABLED], .tuple = .{ tag, fixed[INPUT_IDS + i], main[4 * i], main[4 * i + 1], main[4 * i + 2], main[4 * i + 3] } };
    ports[2] = .{ .numerator = fixed[ENABLED], .tuple = .{ tag, fixed[2], main[8], literal(F, 0), literal(F, 0), literal(F, 0) } };
    for (0..2) |i| ports[3 + i] = .{ .numerator = literal(F, 0).sub(fixed[LAST].mul(fixed[OUTPUT_USES + i])), .tuple = .{ tag, fixed[OUTPUT_IDS + i], main[ACC + 4 * i], main[ACC + 4 * i + 1], main[ACC + 4 * i + 2], main[ACC + 4 * i + 3] } };
    // The odd final port pairs with an identically zero-weight dummy.
    ports[5] = .{ .numerator = literal(F, 0), .tuple = @splat(literal(F, 0)) };
    return ports;
}
pub fn denominator(comptime F: type, port: PortFor(F), z: F, powers: [6]F) F {
    var d = literal(F, 0).sub(z);
    for (port.tuple, powers) |value, power| d = d.add(value.mul(power));
    return d;
}
pub fn rootsFor(comptime F: type, main: *const [MAIN]F, previous_main: *const [8]F, fixed: *const [FIXED]F, current: *const [3]F, previous_prefix: F, z: F, powers: [6]F, shift: F) [ROOTS]F {
    var roots: [ROOTS]F = undefined;
    roots[0..8].* = arithmeticFor(F, main, previous_main, fixed);
    const ports = portsFor(F, main, fixed);
    var prior = literal(F, 0);
    for (0..3) |i| {
        const p = ports[2 * i];
        const q = ports[2 * i + 1];
        const d0 = denominator(F, p, z, powers);
        const d1 = denominator(F, q, z, powers);
        const numerator = p.numerator.mul(d1).add(q.numerator.mul(d0));
        const delta = if (i == 2) current[i].sub(previous_prefix).add(shift).sub(prior) else current[i].sub(prior);
        roots[8 + i] = d0.mul(d1).mul(delta).sub(numerator);
        prior = current[i];
    }
    return roots;
}
pub fn fill(weight: Core.fields.om31.OM31, scalar: M, prior: Core.fields.om31.OM31, first: bool) [MAIN]M {
    var out: [MAIN]M = undefined;
    out[0..8].* = weight.toM31Array();
    out[8] = scalar;
    out[ACC..][0..8].* = (if (first) Core.fields.om31.OM31.zero() else prior).add(weight.mulM31(scalar)).toM31Array();
    return out;
}
