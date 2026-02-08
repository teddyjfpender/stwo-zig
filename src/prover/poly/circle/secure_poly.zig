const std = @import("std");
const circle = @import("../../../core/circle.zig");
const m31 = @import("../../../core/fields/m31.zig");
const qm31 = @import("../../../core/fields/qm31.zig");
const domain_mod = @import("../../../core/poly/circle/domain.zig");
const poly = @import("poly.zig");
const eval_mod = @import("evaluation.zig");
const secure_column = @import("../../secure_column.zig");
const twiddles_mod = @import("../twiddles.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const CircleDomain = domain_mod.CircleDomain;
const CircleCoefficients = poly.CircleCoefficients;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;

pub const SecurePolyError = error{
    ShapeMismatch,
};

pub const SecureCirclePoly = struct {
    polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients,

    pub fn init(
        polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients,
    ) (SecurePolyError || poly.PolyError)!SecureCirclePoly {
        const log_size = polys[0].logSize();
        for (polys[1..]) |coord| {
            if (coord.logSize() != log_size) return SecurePolyError.ShapeMismatch;
        }
        return .{ .polys = polys };
    }

    pub fn deinit(self: *SecureCirclePoly, allocator: std.mem.Allocator) void {
        for (&self.polys) |*coord| {
            coord.deinit(allocator);
        }
        self.* = undefined;
    }

    pub fn evalColumnsAtPoint(
        self: SecureCirclePoly,
        point: CirclePointQM31,
    ) [qm31.SECURE_EXTENSION_DEGREE]QM31 {
        return .{
            self.polys[0].evalAtPoint(point),
            self.polys[1].evalAtPoint(point),
            self.polys[2].evalAtPoint(point),
            self.polys[3].evalAtPoint(point),
        };
    }

    pub fn evalAtPoint(self: SecureCirclePoly, point: CirclePointQM31) QM31 {
        return QM31.fromPartialEvals(self.evalColumnsAtPoint(point));
    }

    pub fn logSize(self: SecureCirclePoly) u32 {
        return self.polys[0].logSize();
    }

    pub fn intoCoordinatePolys(self: SecureCirclePoly) [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients {
        return self.polys;
    }

    pub const SplitPair = struct {
        left: SecureCirclePoly,
        right: SecureCirclePoly,

        pub fn deinit(self: *SplitPair, allocator: std.mem.Allocator) void {
            self.left.deinit(allocator);
            self.right.deinit(allocator);
            self.* = undefined;
        }
    };

    pub fn splitAtMid(
        self: SecureCirclePoly,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || SecurePolyError || poly.PolyError)!SplitPair {
        var left_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
        var right_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
        var initialized: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < initialized) : (i += 1) {
                left_polys[i].deinit(allocator);
                right_polys[i].deinit(allocator);
            }
        }

        for (self.polys, 0..) |coord, i| {
            const split = try coord.splitAtMid(allocator);
            left_polys[i] = split.left;
            right_polys[i] = split.right;
            initialized += 1;
        }

        return .{
            .left = try SecureCirclePoly.init(left_polys),
            .right = try SecureCirclePoly.init(right_polys),
        };
    }
};

pub fn interpolateFromEvaluation(
    allocator: std.mem.Allocator,
    domain: CircleDomain,
    values: *const SecureColumnByCoords,
) !SecureCirclePoly {
    var twiddle_tree_owned = try twiddles_mod.precomputeM31(allocator, domain.half_coset);
    defer twiddles_mod.deinitM31(allocator, &twiddle_tree_owned);
    return interpolateFromEvaluationWithTwiddles(
        allocator,
        domain,
        values,
        .{
            .root_coset = twiddle_tree_owned.root_coset,
            .twiddles = twiddle_tree_owned.twiddles,
            .itwiddles = twiddle_tree_owned.itwiddles,
        },
    );
}

pub fn interpolateFromEvaluationWithTwiddles(
    allocator: std.mem.Allocator,
    domain: CircleDomain,
    values: *const SecureColumnByCoords,
    twiddle_tree: twiddles_mod.TwiddleTree([]const M31),
) !SecureCirclePoly {
    if (domain.size() != values.len()) return SecurePolyError.ShapeMismatch;

    var coordinate_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
    var initialized: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < initialized) : (i += 1) coordinate_polys[i].deinit(allocator);
    }

    for (0..qm31.SECURE_EXTENSION_DEGREE) |i| {
        const evaluation = try eval_mod.CircleEvaluation.init(domain, values.columns[i]);
        coordinate_polys[i] = try poly.interpolateFromEvaluationWithTwiddles(
            allocator,
            evaluation,
            twiddle_tree,
        );
        initialized += 1;
    }

    return SecureCirclePoly.init(coordinate_polys);
}

test "prover poly circle secure poly: split-at-mid identity" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 6;
    const n = @as(usize, 1) << @intCast(log_size);

    var coordinate_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
    var initialized: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < initialized) : (i += 1) coordinate_polys[i].deinit(alloc);
    }

    for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
        const coeffs = try alloc.alloc(M31, n);
        for (coeffs, 0..) |*coeff, i| {
            const canonical: u32 = @intCast((i * 13 + coord * 11 + 7) % m31.Modulus);
            coeff.* = M31.fromCanonical(canonical);
        }
        coordinate_polys[coord] = try CircleCoefficients.initOwned(coeffs);
        initialized += 1;
    }

    var secure_poly = try SecureCirclePoly.init(coordinate_polys);
    initialized = 0;
    defer secure_poly.deinit(alloc);

    var split = try secure_poly.splitAtMid(alloc);
    defer split.deinit(alloc);

    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(123456789);
    const lhs = split.left.evalAtPoint(point).add(
        point.repeatedDouble(log_size - 2).x.mul(split.right.evalAtPoint(point)),
    );
    const rhs = secure_poly.evalAtPoint(point);
    try std.testing.expect(lhs.eql(rhs));
}

test "prover poly circle secure poly: rejects mixed coordinate log sizes" {
    const coeffs0 = [_]M31{ M31.one(), M31.zero(), M31.zero(), M31.zero() };
    const coeffs1 = [_]M31{ M31.one(), M31.zero() };

    const p0 = try CircleCoefficients.initBorrowed(coeffs0[0..]);
    const p1 = try CircleCoefficients.initBorrowed(coeffs1[0..]);
    try std.testing.expectError(
        SecurePolyError.ShapeMismatch,
        SecureCirclePoly.init(.{ p0, p0, p0, p1 }),
    );
}

test "prover poly circle secure poly: interpolate from evaluation roundtrip" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 4;
    const domain = @import("../../../core/poly/circle/canonic.zig").CanonicCoset.new(log_size).circleDomain();
    const n = domain.size();

    var coordinate_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
    var initialized_polys: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < initialized_polys) : (i += 1) coordinate_polys[i].deinit(alloc);
    }

    for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
        const coeffs = try alloc.alloc(M31, n);
        for (coeffs, 0..) |*coeff, i| {
            const canonical: u32 = @intCast((i * 7 + coord * 5 + 1) % m31.Modulus);
            coeff.* = M31.fromCanonical(canonical);
        }
        coordinate_polys[coord] = try CircleCoefficients.initOwned(coeffs);
        initialized_polys += 1;
    }

    var secure_poly = try SecureCirclePoly.init(coordinate_polys);
    initialized_polys = 0;
    defer secure_poly.deinit(alloc);

    var eval_columns: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
    var initialized_eval_cols: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < initialized_eval_cols) : (i += 1) alloc.free(eval_columns[i]);
    }

    for (secure_poly.polys, 0..) |coord_poly, i| {
        const eval = try coord_poly.evaluate(alloc, domain);
        eval_columns[i] = @constCast(eval.values);
        initialized_eval_cols += 1;
    }

    var secure_eval = try SecureColumnByCoords.initOwned(eval_columns);
    defer secure_eval.deinit(alloc);

    var interpolated = try interpolateFromEvaluation(alloc, domain, &secure_eval);
    defer interpolated.deinit(alloc);

    for (0..qm31.SECURE_EXTENSION_DEGREE) |i| {
        try std.testing.expectEqualSlices(
            M31,
            secure_poly.polys[i].coefficients(),
            interpolated.polys[i].coefficients(),
        );
    }
}

test "prover poly circle secure poly: interpolate with twiddles matches interpolate" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 5;
    const domain = @import("../../../core/poly/circle/canonic.zig").CanonicCoset.new(log_size).circleDomain();
    const n = domain.size();

    var eval_columns: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
    for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
        const values = try alloc.alloc(M31, n);
        for (values, 0..) |*value, i| {
            const canonical: u32 = @intCast((i * 13 + coord * 17 + 3) % m31.Modulus);
            value.* = M31.fromCanonical(canonical);
        }
        eval_columns[coord] = values;
    }

    var secure_eval = try SecureColumnByCoords.initOwned(eval_columns);
    defer secure_eval.deinit(alloc);

    var interpolated = try interpolateFromEvaluation(alloc, domain, &secure_eval);
    defer interpolated.deinit(alloc);

    var twiddle_tree = try twiddles_mod.precomputeM31(alloc, domain.half_coset);
    defer twiddles_mod.deinitM31(alloc, &twiddle_tree);
    var interpolated_with_twiddles = try interpolateFromEvaluationWithTwiddles(
        alloc,
        domain,
        &secure_eval,
        .{
            .root_coset = twiddle_tree.root_coset,
            .twiddles = twiddle_tree.twiddles,
            .itwiddles = twiddle_tree.itwiddles,
        },
    );
    defer interpolated_with_twiddles.deinit(alloc);

    for (0..qm31.SECURE_EXTENSION_DEGREE) |i| {
        try std.testing.expectEqualSlices(
            M31,
            interpolated.polys[i].coefficients(),
            interpolated_with_twiddles.polys[i].coefficients(),
        );
    }
}
