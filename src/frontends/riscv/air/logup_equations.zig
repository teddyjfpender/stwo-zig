//! Shared LogUp pair and transition equations, independent of trace generation.
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const LogupError = error{ ZeroDenominator, StepClockCycle, OutOfMemory };

pub fn RowPairFor(comptime S: type) type {
    return struct {
        n1: S,
        d1: S,
        n2: S,
        d2: S,

        pub fn single(n: S, d: S) @This() {
            return .{ .n1 = n, .d1 = d, .n2 = S.zero(), .d2 = S.one() };
        }
    };
}

pub const RowPair = RowPairFor(QM31);

pub fn pairConstraintGeneric(
    comptime S: type,
    s: S,
    s_prev: S,
    is_first: S,
    claimed: S,
    pair: RowPairFor(S),
) S {
    const delta = s.sub(s_prev).add(is_first.mul(claimed));
    return delta.mul(pair.d1).mul(pair.d2)
        .sub(pair.n1.mul(pair.d2)).sub(pair.n2.mul(pair.d1));
}

const circle = @import("stwo_core").circle;
const canonic = @import("stwo_core").poly.circle.canonic;
const CirclePointM31 = circle.CirclePointM31;
const CirclePointQM31 = circle.CirclePointQM31;

/// Lift a base-field circle point into the secure field.
pub fn liftPoint(p: CirclePointM31) CirclePointQM31 {
    return .{ .x = QM31.fromBase(p.x), .y = QM31.fromBase(p.y) };
}

/// The trace-order predecessor mask point: `point - g` for the canonic coset
/// step g of the component's domain. Sampling a committed column at this
/// point reads the previous trace row.
pub fn prevRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.sub(liftPoint(step));
}

pub fn pairConstraint(
    s: QM31,
    s_prev: QM31,
    is_first: QM31,
    claimed: QM31,
    pair: RowPair,
) QM31 {
    return pairConstraintGeneric(QM31, s, s_prev, is_first, claimed, pair);
}
