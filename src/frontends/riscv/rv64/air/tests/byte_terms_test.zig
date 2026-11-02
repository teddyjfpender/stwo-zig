const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const Cpu = @import("../range/cpu.zig");
const Q = E.Q;

test "prepared byte symmetric polynomials equal the original recurrence over arbitrary QM31" {
    var prng = std.Random.DefaultPrng.init(0x53594d4d45545259);
    const rng = prng.random();
    for (0..384) |round| {
        const alpha = if (round == 0) Q.zero() else if (round == 1) Q.one() else randomQ(rng);
        const prepared = Cpu.PreparedAlpha.init(alpha);
        var values: [3]Q = undefined;
        for (&values) |*value| value.* = if (round % 3 == 0) E.q(rng.int(u32) % core.fields.m31.Modulus) else randomQ(rng);
        if (round % 7 == 0) values[1] = alpha; // zero denominator remains an identity test
        for (0..4) |count| {
            const original = reference(alpha, values[0..count]);
            const actual = prepared.terms(values[0..count]);
            try std.testing.expect(actual.numerator.eql(original.numerator));
            try std.testing.expect(actual.denominator.eql(original.denominator));
        }
    }
}
/// Retained pre-optimization polynomial recurrence for parity/benchmark use.
pub fn reference(alpha: Q, values: []const Q) Cpu.Terms {
    var denominator = Q.one();
    var numerator = Q.zero();
    for (values) |value| {
        const d = alpha.sub(value);
        numerator = numerator.mul(d).add(denominator);
        denominator = denominator.mul(d);
    }
    return .{ .numerator = numerator, .denominator = denominator };
}
fn randomQ(rng: std.Random) Q {
    const p = core.fields.m31.Modulus;
    return Q.fromU32Unchecked(rng.int(u32) % p, rng.int(u32) % p, rng.int(u32) % p, rng.int(u32) % p);
}

// Full-kernel oracle delegates every other family to the production authority.
pub fn emitWithOriginalByteTerms(component: anytype, geometry: @import("../full/frame.zig").Geometry, physical: []const Q, previous_main: []const Q, current: []const Q, previous: []const Q, logical: *const E.Main, out: *E.Sink) void {
    component.emitExecutionConstraints(geometry, physical, previous_main, current, previous, logical, out);
    const begin = component.byteStart();
    const end = component.andStart();
    evaluateOriginal(component.plan, physical[0..component.plan.main_count], current[begin..end], previous[begin..end], geometry[1], geometry[2], component.challenges.bytes, component.claims.bytes, out);
    component.emitTableLookupConstraints(geometry, physical, current, previous, logical, out);
}
fn evaluateOriginal(plan: *const @import("../encoding.zig").Plan, physical: []const Q, current: []const Q, previous: []const Q, first: Q, last: Q, alpha: Q, claim: Q, out: *E.Sink) void {
    var contribution = Q.zero();
    for (0..Cpu.batches(plan)) |batch| {
        var values: [3]Q = undefined;
        const count = @min(3, plan.range_count - batch * 3);
        for (0..count) |i| values[i] = physical[plan.range_sources[batch * 3 + i]];
        const terms = reference(alpha, values[0..count]);
        const inverse = Cpu.secure(current, batch * 4);
        out.emit(terms.denominator.mul(inverse).sub(Q.one()));
        contribution = contribution.add(terms.numerator.mul(inverse));
    }
    const sum = Cpu.secure(current, Cpu.batches(plan) * 4);
    const prior = Cpu.secure(previous, Cpu.batches(plan) * 4);
    out.emit(sum.sub(Q.one().sub(first).mul(prior)).sub(contribution));
    out.emit(last.mul(sum.sub(claim)));
}
