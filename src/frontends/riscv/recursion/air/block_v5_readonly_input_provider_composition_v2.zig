//! Same original provider equations recorded into recursive arithmetic. Shared
//! challenge pairs are unshifted transcript draws; group is admitted public data.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const r = @import("composition_graph_recorder.zig");
pub const S = r.Scalar;
const Air = @import("../../prover/block_v5_readonly_input_provider_component_v2.zig");
pub fn Element(comptime width: usize) type {
    return struct { z: S, alpha_powers: [width]S };
}
pub const Challenges = struct { classification: Element(5), read: Element(4), word: struct { range16: Element(1) } };
pub fn element(comptime width: usize, z: S, alpha: S) Element(width) {
    var result = Element(width){ .z = z, .alpha_powers = undefined };
    var power = S.one();
    for (&result.alpha_powers) |*value| {
        value.* = power;
        power = power.mul(alpha);
    }
    return result;
}
pub fn forGroup(shared: Challenges, class_alpha: S, read_alpha: S, group_id: S) Challenges {
    var result = shared;
    result.classification.z = shared.classification.z.sub(shared.classification.alpha_powers[4].mul(class_alpha).mul(group_id));
    result.read.z = shared.read.z.sub(shared.read.alpha_powers[3].mul(read_alpha).mul(group_id));
    return result;
}
pub fn recordEquation(builder: *r.Builder, log: u32, fixed: [10]S, main: [18]S, prior: [18]S, current: [44]S, previous: [44]S, claims: [11]S, totals: [8]S, challenges: *const Challenges, randomness: S, seed: S, chunks: [4]S) !void {
    if (log < 1 or log > 15) return error.InvalidReadonlyProviderRecursiveGeometry;
    const point = r.pointFromSeed(seed);
    var cache: r.DenominatorCache = @splat(null);
    const denominator = try r.quotientDenominator(log, log, point, &cache);
    const inverse = S.fromBase(try M.fromCanonical(@as(u32, 1) << @intCast(log)).inv());
    var shifts: [11]S = undefined;
    for (&shifts, claims) |*shift, claim| shift.* = claim.mul(inverse);
    const equations = Air.Algebra(S).equations(fixed, main, prior, current, previous, shifts, challenges, totals);
    var accumulated = S.zero();
    for (equations) |equation| r.accumulate(&accumulated, randomness, equation, denominator);
    try builder.constrainZero((try r.reconstructSplitComposition(&chunks, point, log + 2, 2)).sub(accumulated));
}
/// Constant challenge adapter for independent scalar/symbolic equation oracles.
/// Production adapters bind these cells to real transcript outputs instead.
pub fn constants(challenges: anytype) Challenges {
    var result = Challenges{ .classification = undefined, .read = undefined, .word = .{ .range16 = undefined } };
    result.classification.z = S.fromSecure(challenges.classification.z);
    for (&result.classification.alpha_powers, challenges.classification.alpha_powers) |*v, q| v.* = S.fromSecure(q);
    result.read.z = S.fromSecure(challenges.read.z);
    for (&result.read.alpha_powers, challenges.read.alpha_powers) |*v, q| v.* = S.fromSecure(q);
    result.word.range16.z = S.fromSecure(challenges.word.range16.z);
    result.word.range16.alpha_powers[0] = S.one();
    return result;
}
