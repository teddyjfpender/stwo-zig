const std = @import("std");
const circle = @import("../../../core/circle.zig");
const m31 = @import("../../../core/fields/m31.zig");
const qm31 = @import("../../../core/fields/qm31.zig");
const domain_mod = @import("../../../core/poly/circle/domain.zig");
const eval_mod = @import("evaluation.zig");
const utils = @import("../../../core/utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const CircleDomain = domain_mod.CircleDomain;

pub const PolyError = error{
    InvalidLength,
    InvalidLogSize,
    NonBaseEvaluation,
    SingularSystem,
};

/// Polynomial coefficients in the circle-FFT basis.
///
/// Invariants:
/// - `coeffs.len` is a non-zero power of two.
pub const CircleCoefficients = struct {
    coeffs: []const M31,
    log_size: u32,
    owns_coeffs: bool,

    pub fn initBorrowed(coeffs: []const M31) PolyError!CircleCoefficients {
        if (coeffs.len == 0 or !std.math.isPowerOfTwo(coeffs.len)) {
            return PolyError.InvalidLength;
        }
        return .{
            .coeffs = coeffs,
            .log_size = @intCast(std.math.log2_int(usize, coeffs.len)),
            .owns_coeffs = false,
        };
    }

    pub fn initOwned(coeffs: []M31) PolyError!CircleCoefficients {
        var out = try initBorrowed(coeffs);
        out.owns_coeffs = true;
        return out;
    }

    pub fn deinit(self: *CircleCoefficients, allocator: std.mem.Allocator) void {
        if (self.owns_coeffs) allocator.free(@constCast(self.coeffs));
        self.* = undefined;
    }

    pub fn logSize(self: CircleCoefficients) u32 {
        return self.log_size;
    }

    pub fn coefficients(self: CircleCoefficients) []const M31 {
        return self.coeffs;
    }

    /// Evaluates the polynomial at one secure-field point.
    pub fn evalAtPoint(self: CircleCoefficients, point: CirclePointQM31) QM31 {
        if (self.log_size == 0) return QM31.fromBase(self.coeffs[0]);

        const max_log_size = circle.M31_CIRCLE_LOG_ORDER;
        std.debug.assert(self.log_size <= max_log_size);
        var mappings: [circle.M31_CIRCLE_LOG_ORDER]QM31 = undefined;

        mappings[self.log_size - 1] = point.y;
        if (self.log_size > 1) {
            var x = point.x;
            var i: usize = self.log_size - 1;
            while (i > 0) {
                i -= 1;
                mappings[i] = x;
                x = circle.CirclePoint(QM31).doubleX(x);
            }
        }

        var acc = QM31.zero();
        for (self.coeffs, 0..) |coeff, idx| {
            var twiddle = QM31.one();
            var bit_idx: usize = 0;
            var bit_words = idx;
            while (bit_idx < self.log_size and bit_words != 0) : (bit_idx += 1) {
                if ((bit_words & 1) == 1) {
                    twiddle = twiddle.mul(mappings[bit_idx]);
                }
                bit_words >>= 1;
            }
            acc = acc.add(QM31.fromBase(coeff).mul(twiddle));
        }

        return acc;
    }

    pub fn extend(
        self: CircleCoefficients,
        allocator: std.mem.Allocator,
        log_size: u32,
    ) (std.mem.Allocator.Error || PolyError)!CircleCoefficients {
        if (log_size < self.log_size) return PolyError.InvalidLogSize;
        const new_len = checkedPow2(log_size) catch return PolyError.InvalidLogSize;
        const out = try allocator.alloc(M31, new_len);
        @memset(out, M31.zero());
        @memcpy(out[0..self.coeffs.len], self.coeffs);
        return CircleCoefficients.initOwned(out);
    }

    pub fn evaluate(
        self: CircleCoefficients,
        allocator: std.mem.Allocator,
        domain: CircleDomain,
    ) (std.mem.Allocator.Error || PolyError || eval_mod.EvaluationError)!eval_mod.CircleEvaluation {
        if (domain.logSize() < self.log_size) return PolyError.InvalidLogSize;
        const values = try allocator.alloc(M31, domain.size());
        errdefer allocator.free(values);

        for (values, 0..) |*value, i| {
            const point = pointM31IntoQM31(
                domain.at(utils.bitReverseIndex(i, domain.logSize())),
            );
            const secure_eval = self.evalAtPoint(point);
            value.* = secure_eval.tryIntoM31() catch return PolyError.NonBaseEvaluation;
        }

        return eval_mod.CircleEvaluation.init(domain, values);
    }

    pub const SplitPair = struct {
        left: CircleCoefficients,
        right: CircleCoefficients,

        pub fn deinit(self: *SplitPair, allocator: std.mem.Allocator) void {
            self.left.deinit(allocator);
            self.right.deinit(allocator);
            self.* = undefined;
        }
    };

    /// Splits the coefficient vector in the middle.
    ///
    /// Returns `(left, right)` such that:
    /// `p(z) = left(z) + pi^{L-2}(z.x) * right(z)`, where `L = log2(coeffs.len)`.
    pub fn splitAtMid(
        self: CircleCoefficients,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || PolyError)!SplitPair {
        if (self.log_size == 0) return PolyError.InvalidLogSize;
        const mid = self.coeffs.len / 2;
        const left = try allocator.dupe(M31, self.coeffs[0..mid]);
        errdefer allocator.free(left);
        const right = try allocator.dupe(M31, self.coeffs[mid..]);
        errdefer allocator.free(right);

        return .{
            .left = try CircleCoefficients.initOwned(left),
            .right = try CircleCoefficients.initOwned(right),
        };
    }
};

/// Interpolates circle coefficients from bit-reversed domain evaluations.
///
/// This is a deterministic reference implementation (Gaussian elimination).
pub fn interpolateFromEvaluation(
    allocator: std.mem.Allocator,
    evaluation: eval_mod.CircleEvaluation,
) (std.mem.Allocator.Error || PolyError)!CircleCoefficients {
    const n = evaluation.values.len;
    if (n == 0 or !std.math.isPowerOfTwo(n)) return PolyError.InvalidLength;
    if (evaluation.domain.size() != n) return PolyError.InvalidLength;

    const log_size = evaluation.domain.logSize();
    const row_width = n + 1;
    const aug = try allocator.alloc(M31, n * row_width);
    defer allocator.free(aug);

    for (0..n) |row| {
        const row_slice = aug[row * row_width .. (row + 1) * row_width];
        const point = evaluation.domain.at(utils.bitReverseIndex(row, log_size));
        const mappings = buildMappingsM31(point, log_size);
        for (0..n) |col| {
            row_slice[col] = twiddleAtM31(mappings[0..log_size], col);
        }
        row_slice[n] = evaluation.values[row];
    }

    // Gauss-Jordan elimination over M31.
    for (0..n) |col| {
        var pivot_row = col;
        while (pivot_row < n and aug[pivot_row * row_width + col].isZero()) : (pivot_row += 1) {}
        if (pivot_row == n) return PolyError.SingularSystem;

        if (pivot_row != col) {
            for (0..row_width) |j| {
                const a_idx = col * row_width + j;
                const b_idx = pivot_row * row_width + j;
                const tmp = aug[a_idx];
                aug[a_idx] = aug[b_idx];
                aug[b_idx] = tmp;
            }
        }

        const pivot = aug[col * row_width + col];
        const pivot_inv = pivot.inv() catch return PolyError.SingularSystem;
        for (col..row_width) |j| {
            const idx = col * row_width + j;
            aug[idx] = aug[idx].mul(pivot_inv);
        }

        for (0..n) |row| {
            if (row == col) continue;
            const factor = aug[row * row_width + col];
            if (factor.isZero()) continue;
            for (col..row_width) |j| {
                const idx = row * row_width + j;
                const pivot_idx = col * row_width + j;
                aug[idx] = aug[idx].sub(factor.mul(aug[pivot_idx]));
            }
        }
    }

    const coeffs = try allocator.alloc(M31, n);
    for (0..n) |i| {
        coeffs[i] = aug[i * row_width + n];
    }
    return CircleCoefficients.initOwned(coeffs);
}

fn checkedPow2(log_size: u32) PolyError!usize {
    if (log_size >= @bitSizeOf(usize)) return PolyError.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn pointM31IntoQM31(point: circle.CirclePointM31) CirclePointQM31 {
    return .{
        .x = QM31.fromBase(point.x),
        .y = QM31.fromBase(point.y),
    };
}

fn buildMappingsM31(point: circle.CirclePointM31, log_size: u32) [circle.M31_CIRCLE_LOG_ORDER]M31 {
    var mappings: [circle.M31_CIRCLE_LOG_ORDER]M31 = undefined;
    if (log_size == 0) return mappings;
    mappings[log_size - 1] = point.y;
    if (log_size > 1) {
        var x = point.x;
        var i: usize = log_size - 1;
        while (i > 0) {
            i -= 1;
            mappings[i] = x;
            x = circle.CirclePoint(M31).doubleX(x);
        }
    }
    return mappings;
}

fn twiddleAtM31(mappings: []const M31, mut_index: usize) M31 {
    var index = mut_index;
    var product = M31.one();
    for (mappings) |mapping| {
        if ((index & 1) == 1) {
            product = product.mul(mapping);
        }
        index >>= 1;
        if (index == 0) break;
    }
    return product;
}

test "prover poly circle poly: eval at point for constant polynomial" {
    const coeffs = [_]M31{M31.fromCanonical(23)};
    const poly = try CircleCoefficients.initBorrowed(coeffs[0..]);
    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(11);
    try std.testing.expect(poly.evalAtPoint(point).eql(QM31.fromBase(M31.fromCanonical(23))));
}

test "prover poly circle poly: split-at-mid identity" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 5;

    const coeffs = try alloc.alloc(M31, @as(usize, 1) << @intCast(log_size));
    defer alloc.free(coeffs);
    for (coeffs, 0..) |*coeff, i| {
        const canonical: u32 = @intCast((i * 17 + 5) % m31.Modulus);
        coeff.* = M31.fromCanonical(canonical);
    }

    const poly = try CircleCoefficients.initBorrowed(coeffs);
    var split = try poly.splitAtMid(alloc);
    defer split.deinit(alloc);

    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(21903);
    const lhs = split.left.evalAtPoint(point).add(
        point.repeatedDouble(log_size - 2).x.mul(split.right.evalAtPoint(point)),
    );
    const rhs = poly.evalAtPoint(point);
    try std.testing.expect(lhs.eql(rhs));
}

test "prover poly circle poly: evaluate on domain returns base values" {
    const alloc = std.testing.allocator;
    const coeffs = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(0),
        M31.fromCanonical(0),
        M31.fromCanonical(0),
    };
    const poly = try CircleCoefficients.initBorrowed(coeffs[0..]);
    const domain = @import("../../../core/poly/circle/canonic.zig").CanonicCoset.new(3).circleDomain();

    const evaluation = try poly.evaluate(alloc, domain);
    defer alloc.free(@constCast(evaluation.values));

    for (evaluation.values) |value| {
        try std.testing.expect(value.eql(M31.fromCanonical(1)));
    }
}

test "prover poly circle poly: interpolation roundtrip" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 4;
    const n = @as(usize, 1) << @intCast(log_size);

    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    for (coeffs, 0..) |*coeff, i| {
        const canonical: u32 = @intCast((i * 19 + 3) % m31.Modulus);
        coeff.* = M31.fromCanonical(canonical);
    }

    const poly = try CircleCoefficients.initBorrowed(coeffs);
    const domain = @import("../../../core/poly/circle/canonic.zig").CanonicCoset.new(log_size).circleDomain();
    const evaluation = try poly.evaluate(alloc, domain);
    defer alloc.free(@constCast(evaluation.values));

    var interpolated = try interpolateFromEvaluation(alloc, evaluation);
    defer interpolated.deinit(alloc);
    try std.testing.expectEqualSlices(M31, poly.coefficients(), interpolated.coefficients());
}
