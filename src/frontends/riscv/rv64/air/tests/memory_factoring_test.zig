const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const actual = @import("../memory_constraints.zig");
const original = @import("memory_reference.zig");
const Q = E.Q;

test "memory expectation factoring preserves every residual for arbitrary QM31 selectors" {
    var prng = std.Random.DefaultPrng.init(0x4d454d4f52594641);
    const rng = prng.random();
    var fixed: E.Fixed = undefined;
    var main: E.Main = undefined;
    var want: [256]Q = undefined;
    var got: [256]Q = undefined;
    for (0..64) |round| {
        for (&fixed) |*value| value.* = randomQ(rng, round % 2 == 0);
        for (&main) |*value| value.* = randomQ(rng, round % 2 == 0);
        if (round < 3) {
            // Include multiple active, unaligned, and out-of-width selectors;
            // no validity equation is assumed by the factored polynomial.
            for (main[E.L.offset_start..][0..8], 0..) |*value, offset| value.* = if (round == 0) Q.one() else if (offset == (if (round == 1) @as(usize, 3) else 7)) Q.one() else Q.zero();
        }
        const view = E.View{ .f = &fixed, .m = &main };
        var old_sink = E.Sink{ .values = &want };
        var new_sink = E.Sink{ .values = &got };
        original.evaluate(view, &old_sink);
        actual.evaluate(view, &new_sink);
        try std.testing.expectEqual(@as(usize, 154), old_sink.count);
        try std.testing.expectEqual(old_sink.count, new_sink.count);
        for (want[0..old_sink.count], got[0..new_sink.count]) |expected, value| try std.testing.expect(expected.eql(value));
    }
}
fn randomQ(rng: std.Random, base: bool) Q {
    const p = core.fields.m31.Modulus;
    return if (base) E.q(rng.int(u32) % p) else Q.fromU32Unchecked(rng.int(u32) % p, rng.int(u32) % p, rng.int(u32) % p, rng.int(u32) % p);
}
