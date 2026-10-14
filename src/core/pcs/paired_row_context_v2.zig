//! Candidate CAS09 original/own-quotient row transform for an admitted H1 source.
//! The caller must supply transcript-derived OOD point, mixed claims and batch
//! challenge; the owned Gate candidate keeps those inputs private.
const std = @import("std");
const circle = @import("../circle.zig");
const constraints = @import("../constraints.zig");
const m31 = @import("../fields/m31.zig");
const cm31 = @import("../fields/cm31.zig");
const qm31 = @import("../fields/qm31.zig");

const M31 = m31.M31;
const CM31 = cm31.CM31;
const QM31 = qm31.QM31;
pub const Error = error{ DegenerateLine, InvalidSourceRowWidth } || std.mem.Allocator.Error || CM31.Error;

/// The same two-point quotient arithmetic as CAS09's RowContext. Store one
/// coefficient and one batch power per key-owned source column, then reuse
/// them across authenticated query rows.
pub const RowContextV2 = struct {
    allocator: std.mem.Allocator,
    coefficients: []constraints.LineCoeffs,
    powers: []QM31,
    point: circle.CirclePointQM31,

    pub fn init(
        allocator: std.mem.Allocator,
        point: circle.CirclePointQM31,
        claims: []const QM31,
        batch: QM31,
    ) Error!RowContextV2 {
        const coefficients = try allocator.alloc(constraints.LineCoeffs, claims.len);
        errdefer allocator.free(coefficients);
        const powers = try allocator.alloc(QM31, claims.len);
        errdefer allocator.free(powers);
        var power = QM31.one();
        for (claims, coefficients, powers) |claim, *coefficient, *slot| {
            coefficient.* = constraints.complexConjugateLineCoeffs(point, claim, QM31.one()) catch
                return error.DegenerateLine;
            slot.* = power;
            power = power.mul(batch);
        }
        return .{ .allocator = allocator, .coefficients = coefficients, .powers = powers, .point = point };
    }

    pub fn deinit(self: *RowContextV2) void {
        self.allocator.free(self.coefficients);
        self.allocator.free(self.powers);
        self.* = undefined;
    }

    pub fn openedValues(self: RowContextV2, values: []const M31, p: circle.CirclePointM31) Error![2]QM31 {
        if (values.len != self.coefficients.len) return error.InvalidSourceRowWidth;
        const denominator = self.point.x.c0.sub(CM31.fromBase(p.x)).mul(self.point.y.c1)
            .sub(self.point.y.c0.sub(CM31.fromBase(p.y)).mul(self.point.x.c1));
        const inverse = try denominator.inv();
        var out = [2]QM31{ QM31.zero(), QM31.zero() };
        for (values, self.coefficients, self.powers) |value, coefficient, power| {
            const quotient = coefficient.c.mulM31(value)
                .sub(coefficient.a.mulM31(p.y)).sub(coefficient.b).mulCM31(inverse);
            out[0] = out[0].add(power.mul(QM31.fromBase(value)));
            out[1] = out[1].add(power.mul(quotient));
        }
        return out;
    }
};
