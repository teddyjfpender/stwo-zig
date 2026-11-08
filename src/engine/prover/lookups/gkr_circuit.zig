//! GKR circuit layers and the polynomial oracle consumed by batch sum-check.

const std = @import("std");
const fraction = @import("stwo_core").fraction;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const gkr_verifier_module = @import("gkr_verifier.zig");
const mle_mod = @import("mle.zig");
const utils = @import("utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const MleBase = mle_mod.Mle(M31);
const MleSecure = mle_mod.Mle(QM31);

pub const GkrProverError = error{
    EmptyBatch,
    InvalidK,
    DivisionByZero,
    ShapeMismatch,
    NotPowerOfTwo,
    PointDimensionMismatch,
    NotOutputLayer,
    NotConstantPoly,
    InvalidLayerStructure,
    InvalidSumcheck,
    OutOfMemory,
};

/// Evaluations of `eq((0, x), y)` over the boolean hypercube.
const gkr_verifier = gkr_verifier_module;
pub const ForField = @import("gkr_circuit_field.zig").ForField;

pub const EqEvals = ForField(QM31).EqEvals;
pub const Layer = ForField(QM31).Layer;
pub const GkrMultivariatePolyOracle = ForField(QM31).GkrMultivariatePolyOracle;
pub const correctSumAsPolyInFirstVariable = ForField(QM31).correctSumAsPolyInFirstVariable;
pub const buildLayers = ForField(QM31).buildLayers;
const eqZerosPrefix = ForField(QM31).eqZerosPrefix;

test "gkr circuit: eq evals generation matches direct eq" {
    const alloc = std.testing.allocator;

    const y = [_]QM31{
        QM31.fromU32Unchecked(5, 0, 0, 0),
        QM31.fromU32Unchecked(7, 0, 0, 0),
        QM31.fromU32Unchecked(11, 0, 0, 0),
    };

    var eq_evals = try EqEvals.generate(alloc, y[0..]);
    defer eq_evals.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1) << 2, eq_evals.evals.evalsSlice().len);

    const zero = QM31.zero();
    const one = QM31.one();
    const points = [_][2]QM31{
        .{ zero, zero },
        .{ zero, one },
        .{ one, zero },
        .{ one, one },
    };

    for (points) |point| {
        const got = try eq_evals.evals.evalAtPoint(alloc, point[0..]);
        const expected = try utils.eq(
            QM31,
            &[_]QM31{ zero, point[0], point[1] },
            y[0..],
        );
        try std.testing.expect(got.eql(expected));
    }
}

test "gkr circuit: corrected sum polynomial interpolation" {
    const alloc = std.testing.allocator;

    const y = [_]QM31{
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
        QM31.fromU32Unchecked(7, 0, 0, 0),
    };
    const k: usize = 2;
    const n = y.len;
    const y_idx = y[n - k];

    const c0 = QM31.fromU32Unchecked(2, 0, 0, 0);
    const c1 = QM31.fromU32Unchecked(5, 0, 0, 0);
    const c2 = QM31.fromU32Unchecked(9, 0, 0, 0);
    const c3 = QM31.fromU32Unchecked(6, 0, 0, 0);

    const evalR = struct {
        fn at(t: QM31, c0_: QM31, c1_: QM31, c2_: QM31, c3_: QM31) QM31 {
            return c0_
                .add(c1_.mul(t))
                .add(c2_.mul(t.square()))
                .add(c3_.mul(t.square().mul(t)));
        }
    }.at;

    const zero = QM31.zero();
    const one = QM31.one();
    const two = QM31.fromBase(M31.fromCanonical(2));

    const prefix_len = n - k + 1;
    const eq_prefix = try eqZerosPrefix(y[0..prefix_len]);
    const a_const = QM31.one().div(eq_prefix) catch return GkrProverError.DivisionByZero;

    const denom = QM31.one().sub(y_idx.add(y_idx));
    const b_const = QM31.one().sub(y_idx).div(denom) catch return GkrProverError.DivisionByZero;

    const r0 = evalR(zero, c0, c1, c2, c3);
    const r1 = evalR(one, c0, c1, c2, c3);
    const r2 = evalR(two, c0, c1, c2, c3);

    const eq_at_0 = QM31.one().sub(y_idx);
    const eq_at_2 = try utils.eq(QM31, &[_]QM31{two}, &[_]QM31{y_idx});

    const f0 = r0.div(eq_at_0.mul(a_const)) catch return GkrProverError.DivisionByZero;
    const f2 = r2.div(eq_at_2.mul(a_const)) catch return GkrProverError.DivisionByZero;
    const claim = r0.add(r1);

    var poly = try correctSumAsPolyInFirstVariable(alloc, f0, f2, claim, y[0..], k);
    defer poly.deinit(alloc);

    try std.testing.expect(poly.evalAtPoint(zero).eql(r0));
    try std.testing.expect(poly.evalAtPoint(one).eql(r1));
    try std.testing.expect(poly.evalAtPoint(two).eql(r2));
    try std.testing.expect(poly.evalAtPoint(b_const).isZero());
}
