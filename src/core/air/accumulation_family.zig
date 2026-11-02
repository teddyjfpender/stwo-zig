const circle = @import("../circle.zig");
const std = @import("std");
const qm31 = @import("../fields/qm31.zig");
const m31 = @import("../fields/m31.zig");

const M31 = m31.M31;

const qm31_mod = @import("../fields/qm31.zig");

pub fn ForField(comptime Secure: type) type {
    return struct {
        const QM31 = Secure;
        const CirclePointQM31 = circle.CirclePoint(Secure);
        const CM31 = Secure.InnerField;
        const DEGREE = @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;
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
    };
}

test "air accumulation: matches pinned recurrence vector" {
    var prng = std.Random.DefaultPrng.init(0);
    const rng = prng.random();

    const alpha = qm31_mod.QM31.fromU32Unchecked(2, 3, 4, 5);
    var acc = ForField(qm31_mod.QM31).PointEvaluationAccumulator.init(alpha);
    var evaluations: [100]qm31_mod.QM31 = undefined;

    for (&evaluations) |*evaluation| {
        evaluation.* = qm31_mod.QM31.fromBase(M31.fromCanonical(rng.int(u32) % m31.Modulus));
    }
    for (evaluations) |e| {
        acc.accumulate(e);
    }

    // A duplicate recurrence in this test is miscompiled by Zig 0.15.2 ReleaseFast.
    const expected = qm31_mod.QM31.fromU32Unchecked(475_135_206, 878_218_281, 117_218_720, 1_587_643_918);
    try std.testing.expect(acc.finalize().eql(expected));
}
