const std = @import("std");
const circle = @import("../../../core/circle.zig");
const fft = @import("../../../core/fft.zig");
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
        @memset(values, M31.zero());
        @memcpy(values[0..self.coeffs.len], self.coeffs);

        const log_size = domain.logSize();
        if (log_size == 1) {
            var v0 = values[0];
            var v1 = values[1];
            fft.butterfly(M31, &v0, &v1, domain.half_coset.initial.y);
            values[0] = v0;
            values[1] = v1;
            return eval_mod.CircleEvaluation.init(domain, values);
        }
        if (log_size == 2) {
            var v0 = values[0];
            var v1 = values[1];
            var v2 = values[2];
            var v3 = values[3];
            const x = domain.half_coset.initial.x;
            const y = domain.half_coset.initial.y;
            fft.butterfly(M31, &v0, &v2, x);
            fft.butterfly(M31, &v1, &v3, x);
            fft.butterfly(M31, &v0, &v1, y);
            fft.butterfly(M31, &v2, &v3, y.neg());
            values[0] = v0;
            values[1] = v1;
            values[2] = v2;
            values[3] = v3;
            return eval_mod.CircleEvaluation.init(domain, values);
        }

        const log_line_size = log_size - 1;
        const twiddles = try slowPrecomputeTwiddles(allocator, domain.half_coset);
        defer allocator.free(twiddles);

        var layer_idx: usize = log_line_size;
        while (layer_idx > 0) {
            layer_idx -= 1;
            const layer: u32 = @intCast(layer_idx);
            const layer_twiddles = lineTwiddlesLayer(twiddles, log_line_size, layer);
            for (layer_twiddles, 0..) |twid, h| {
                fftLayerLoop(values, layer + 1, h, twid, false);
            }
        }

        const first_line_twiddles = lineTwiddlesLayer(twiddles, log_line_size, 0);
        for (0..values.len / 2) |h| {
            fftLayerLoop(
                values,
                0,
                h,
                circleTwiddleFromFirstLine(first_line_twiddles, h),
                false,
            );
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
    const coeffs = try allocator.dupe(M31, evaluation.values);
    errdefer allocator.free(coeffs);

    const log_size = evaluation.domain.logSize();
    if (log_size == 1) {
        const y = evaluation.domain.half_coset.initial.y;
        const n_f = M31.fromCanonical(2);
        const yn_inv = y.mul(n_f).inv() catch return PolyError.SingularSystem;
        const y_inv = yn_inv.mul(n_f);
        const n_inv = yn_inv.mul(y);

        var v0 = coeffs[0];
        var v1 = coeffs[1];
        fft.ibutterfly(M31, &v0, &v1, y_inv);
        coeffs[0] = v0.mul(n_inv);
        coeffs[1] = v1.mul(n_inv);
        return CircleCoefficients.initOwned(coeffs);
    }
    if (log_size == 2) {
        const x = evaluation.domain.half_coset.initial.x;
        const y = evaluation.domain.half_coset.initial.y;
        const n_f = M31.fromCanonical(4);
        const xyn_inv = x.mul(y).mul(n_f).inv() catch return PolyError.SingularSystem;
        const x_inv = xyn_inv.mul(y).mul(n_f);
        const y_inv = xyn_inv.mul(x).mul(n_f);
        const n_inv = xyn_inv.mul(x).mul(y);

        var v0 = coeffs[0];
        var v1 = coeffs[1];
        var v2 = coeffs[2];
        var v3 = coeffs[3];
        fft.ibutterfly(M31, &v0, &v1, y_inv);
        fft.ibutterfly(M31, &v2, &v3, y_inv.neg());
        fft.ibutterfly(M31, &v0, &v2, x_inv);
        fft.ibutterfly(M31, &v1, &v3, x_inv);
        coeffs[0] = v0.mul(n_inv);
        coeffs[1] = v1.mul(n_inv);
        coeffs[2] = v2.mul(n_inv);
        coeffs[3] = v3.mul(n_inv);
        return CircleCoefficients.initOwned(coeffs);
    }

    const log_line_size = log_size - 1;
    const twiddles = try slowPrecomputeTwiddles(allocator, evaluation.domain.half_coset);
    defer allocator.free(twiddles);
    const itwiddles = try inverseTwiddles(allocator, twiddles);
    defer allocator.free(itwiddles);

    const first_line_itwiddles = lineTwiddlesLayer(itwiddles, log_line_size, 0);
    for (0..coeffs.len / 2) |h| {
        fftLayerLoop(
            coeffs,
            0,
            h,
            circleTwiddleFromFirstLine(first_line_itwiddles, h),
            true,
        );
    }

    var layer: u32 = 0;
    while (layer < log_line_size) : (layer += 1) {
        const layer_twiddles = lineTwiddlesLayer(itwiddles, log_line_size, layer);
        for (layer_twiddles, 0..) |twid, h| {
            fftLayerLoop(coeffs, layer + 1, h, twid, true);
        }
    }

    const n_inv = M31.fromCanonical(@intCast(n)).inv() catch return PolyError.SingularSystem;
    for (coeffs) |*coeff| {
        coeff.* = coeff.*.mul(n_inv);
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

fn slowPrecomputeTwiddles(
    allocator: std.mem.Allocator,
    root_coset: circle.Coset,
) ![]M31 {
    var coset = root_coset;
    const out = try allocator.alloc(M31, root_coset.size());

    var at: usize = 0;
    var i: u32 = 0;
    while (i < root_coset.logSize()) : (i += 1) {
        const layer_len = coset.size() / 2;
        var it = coset.iter();
        var j: usize = 0;
        while (j < layer_len) : (j += 1) {
            out[at + j] = it.next().?.x;
        }
        utils.bitReverse(M31, out[at .. at + layer_len]);
        at += layer_len;
        coset = coset.double();
    }

    std.debug.assert(at + 1 == out.len);
    out[at] = M31.one();
    return out;
}

fn inverseTwiddles(
    allocator: std.mem.Allocator,
    twiddles: []const M31,
) ![]M31 {
    const out = try allocator.alloc(M31, twiddles.len);
    for (twiddles, 0..) |twid, i| {
        out[i] = twid.inv() catch return PolyError.SingularSystem;
    }
    return out;
}

fn lineTwiddlesLayer(
    twiddle_buffer: []const M31,
    log_line_size: u32,
    layer: u32,
) []const M31 {
    std.debug.assert(layer < log_line_size);
    const len: usize = @as(usize, 1) << @intCast(log_line_size - 1 - layer);
    const end = twiddle_buffer.len - len;
    const start = end - len;
    return twiddle_buffer[start..end];
}

fn circleTwiddleFromFirstLine(
    first_line_twiddles: []const M31,
    h: usize,
) M31 {
    const pair_idx = h / 4;
    const pair_off = h % 4;
    const x = first_line_twiddles[pair_idx * 2];
    const y = first_line_twiddles[pair_idx * 2 + 1];
    return switch (pair_off) {
        0 => y,
        1 => y.neg(),
        2 => x.neg(),
        3 => x,
        else => unreachable,
    };
}

fn fftLayerLoop(
    values: []M31,
    i: u32,
    h: usize,
    twid: M31,
    comptime inverse: bool,
) void {
    const half_block: usize = @as(usize, 1) << @intCast(i);
    var l: usize = 0;
    while (l < half_block) : (l += 1) {
        const idx0 = (h << @intCast(i + 1)) + l;
        const idx1 = idx0 + half_block;
        var v0 = values[idx0];
        var v1 = values[idx1];
        if (inverse) {
            fft.ibutterfly(M31, &v0, &v1, twid);
        } else {
            fft.butterfly(M31, &v0, &v1, twid);
        }
        values[idx0] = v0;
        values[idx1] = v1;
    }
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
