const std = @import("std");
const circle = @import("circle.zig");
const m31 = @import("fields/m31.zig");
const qm31 = @import("fields/qm31.zig");
const canonic = @import("poly/circle/canonic.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const PointSample = struct {
    point: circle.CirclePointQM31,
    value: QM31,
};

pub const LineCoeffs = struct {
    a: QM31,
    b: QM31,
    c: QM31,
};

/// Evaluates a coset vanishing polynomial at `p`.
pub fn cosetVanishing(comptime F: type, coset: circle.Coset, p_in: circle.CirclePoint(F)) F {
    const p = p_in
        .sub(pointInto(F, coset.initial))
        .add(pointInto(F, coset.step_size.half().toPoint()));
    var x = p.x;
    var i: u32 = 1;
    while (i < coset.log_size) : (i += 1) {
        x = circle.CirclePoint(F).doubleX(x);
    }
    return x;
}

/// Evaluates the formal derivative of a coset vanishing polynomial at `p`.
pub fn cosetVanishingDerivative(comptime F: type, coset: circle.Coset, p: circle.CirclePoint(F)) F {
    const field_four = fromBase(F, M31.fromCanonical(4));
    var exp = F.one();
    var i: u32 = 1;
    while (i < coset.log_size) : (i += 1) {
        exp = exp.mul(field_four);
    }

    var vanishing = F.one();
    i = 1;
    while (i < coset.log_size) : (i += 1) {
        vanishing = vanishing.mul(cosetVanishing(F, canonic.CanonicCoset.new(i).coset(), p));
    }

    return exp.mul(vanishing);
}

pub fn pointExcluder(comptime F: type, excluded: circle.CirclePointM31, p: circle.CirclePoint(F)) F {
    return p.sub(pointInto(F, excluded)).x.sub(fromBase(F, M31.one()));
}

pub fn pairVanishing(
    comptime F: type,
    excluded0: circle.CirclePoint(F),
    excluded1: circle.CirclePoint(F),
    p: circle.CirclePoint(F),
) F {
    return excluded0.y.sub(excluded1.y).mul(p.x)
        .add(excluded1.x.sub(excluded0.x).mul(p.y))
        .add(excluded0.x.mul(excluded1.y).sub(excluded0.y.mul(excluded1.x)));
}

/// Evaluates a point vanishing polynomial.
/// Returns `error.DivisionByZero` at the antipode of `vanish_point`.
pub fn pointVanishing(
    comptime F: type,
    vanish_point: circle.CirclePoint(F),
    p: circle.CirclePoint(F),
) !F {
    const h = p.sub(vanish_point);
    return h.y.div(F.one().add(h.x));
}

pub fn complexConjugateLine(
    point: circle.CirclePointQM31,
    value: QM31,
    p: circle.CirclePointM31,
) !QM31 {
    if (point.y.eql(point.y.complexConjugate())) return error.DegenerateLine;

    const dy = value.complexConjugate().sub(value);
    const y_offset = point.y.neg().add(QM31.fromBase(p.y));
    const denom = point.complexConjugate().y.sub(point.y);
    const frac = try dy.mul(y_offset).div(denom);
    return value.add(frac);
}

pub fn complexConjugateLineCoeffs(sample: *const PointSample, alpha: QM31) !LineCoeffs {
    if (sample.point.y.eql(sample.point.y.complexConjugate())) return error.DegenerateLine;
    const a = sample.value.complexConjugate().sub(sample.value);
    const c = sample.point.complexConjugate().y.sub(sample.point.y);
    const b = sample.value.mul(c).sub(a.mul(sample.point.y));
    return .{
        .a = alpha.mul(a),
        .b = alpha.mul(b),
        .c = alpha.mul(c),
    };
}

fn fromBase(comptime F: type, value: M31) F {
    if (F == M31) return value;
    if (F == QM31) return QM31.fromBase(value);
    @compileError("unsupported field conversion from base");
}

fn pointInto(comptime F: type, p: circle.CirclePointM31) circle.CirclePoint(F) {
    return .{
        .x = fromBase(F, p.x),
        .y = fromBase(F, p.y),
    };
}

test "constraints: coset vanishing" {
    const cosets = [_]circle.Coset{
        circle.Coset.halfOdds(5),
        circle.Coset.odds(5),
        circle.Coset.new(circle.CirclePointIndex.zero(), 5),
        circle.Coset.halfOdds(5).conjugate(),
    };

    for (cosets) |c0| {
        var it = c0.iter();
        while (it.next()) |el| {
            try std.testing.expect(cosetVanishing(M31, c0, el).isZero());
            for (cosets) |c1| {
                if (c0.eql(c1)) continue;
                try std.testing.expect(!cosetVanishing(M31, c1, el).isZero());
            }
        }
    }
}

test "constraints: point excluder" {
    const excluded = circle.Coset.halfOdds(5).at(10);
    const point = circle.CirclePointIndex.generator().mul(4).toPoint();

    const num = pointExcluder(M31, excluded, point).mul(pointExcluder(M31, excluded.conjugate(), point));
    const denom = point.x.sub(excluded.x).pow(2);
    try std.testing.expect(num.eql(denom));
}

test "constraints: pair vanishing" {
    const excluded0 = circle.Coset.halfOdds(5).at(10);
    const excluded1 = circle.Coset.halfOdds(5).at(13);
    const point = circle.CirclePointIndex.generator().mul(4).toPoint();

    try std.testing.expect(!pairVanishing(M31, excluded0, excluded1, point).isZero());
    try std.testing.expect(pairVanishing(M31, excluded0, excluded1, excluded0).isZero());
    try std.testing.expect(pairVanishing(M31, excluded0, excluded1, excluded1).isZero());
}

test "constraints: point vanishing success and failure" {
    const coset = circle.Coset.odds(5);
    const vanish_point = coset.at(2);
    var it = coset.iter();
    while (it.next()) |el| {
        if (el.eql(vanish_point)) {
            try std.testing.expect((try pointVanishing(M31, vanish_point, el)).isZero());
            continue;
        }
        if (el.eql(vanish_point.antipode())) continue;
        try std.testing.expect(!(try pointVanishing(M31, vanish_point, el)).isZero());
    }

    const fail_coset = circle.Coset.halfOdds(6);
    const point = fail_coset.at(4);
    try std.testing.expectError(error.DivisionByZero, pointVanishing(M31, point, point.antipode()));
}
