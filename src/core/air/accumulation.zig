const std = @import("std");
const qm31 = @import("../fields/qm31.zig");
const m31 = @import("../fields/m31.zig");

const QM31 = qm31.QM31;
const M31 = m31.M31;

/// Accumulates evaluations into a random linear combination:
/// `acc <- acc * alpha + evaluation`.
pub const PointEvaluationAccumulator = struct {
    random_coeff: QM31,
    accumulation: QM31,

    pub fn init(random_coeff: QM31) PointEvaluationAccumulator {
        return .{
            .random_coeff = random_coeff,
            .accumulation = QM31.zero(),
        };
    }

    pub fn accumulate(self: *PointEvaluationAccumulator, evaluation: QM31) void {
        self.accumulation = self.accumulation.mul(self.random_coeff).add(evaluation);
    }

    pub inline fn finalize(self: PointEvaluationAccumulator) QM31 {
        return self.accumulation;
    }
};

test "air accumulation: matches direct computation" {
    var prng = std.rand.DefaultPrng.init(0);
    const rng = prng.random();

    const alpha = QM31.fromU32Unchecked(2, 3, 4, 5);
    var acc = PointEvaluationAccumulator.init(alpha);
    var direct = QM31.zero();

    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const e = QM31.fromBase(M31.fromCanonical(rng.int(u32) % m31.Modulus));
        acc.accumulate(e);
        direct = direct.mul(alpha).add(e);
    }

    try std.testing.expect(acc.finalize().eql(direct));
}
