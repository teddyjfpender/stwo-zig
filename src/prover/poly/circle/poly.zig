const std = @import("std");
const circle = @import("../../../core/circle.zig");
const fft = @import("../../../core/fft.zig");
const m31 = @import("../../../core/fields/m31.zig");
const qm31 = @import("../../../core/fields/qm31.zig");
const domain_mod = @import("../../../core/poly/circle/domain.zig");
const line_mod = @import("../../../core/poly/line.zig");
const poly_utils = @import("../../../core/poly/utils.zig");
const eval_mod = @import("evaluation.zig");
const twiddles_mod = @import("../twiddles.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const CircleDomain = domain_mod.CircleDomain;
const M31TwiddleTree = twiddles_mod.TwiddleTree([]const M31);

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
        var factors: [circle.M31_CIRCLE_LOG_ORDER]QM31 = undefined;
        factors[0] = point.y;
        if (self.log_size > 1) {
            var x = point.x;
            factors[1] = x;
            var bit: u32 = 2;
            while (bit < self.log_size) : (bit += 1) {
                x = circle.CirclePoint(QM31).doubleX(x);
                factors[bit] = x;
            }
        }

        return evalAtPointIterative(
            self.coeffs,
            factors[0..self.log_size],
            self.log_size,
        );
    }

    pub fn evalAtPointsFolded(
        self: CircleCoefficients,
        points: []const CirclePointQM31,
        fold_count: u32,
        out: []QM31,
    ) void {
        std.debug.assert(points.len == out.len);
        for (points, 0..) |point, i| {
            const folded_point = if (fold_count == 0) point else repeatedDoubleOnCircleQM31(point, fold_count);
            var factors: [circle.M31_CIRCLE_LOG_ORDER]QM31 = undefined;
            factors[0] = folded_point.y;
            if (self.log_size > 1) {
                var x = folded_point.x;
                factors[1] = x;
                var bit: u32 = 2;
                while (bit < self.log_size) : (bit += 1) {
                    x = circle.CirclePoint(QM31).doubleX(x);
                    factors[bit] = x;
                }
            }
            out[i] = evalAtPointIterative(self.coeffs, factors[0..self.log_size], self.log_size);
        }
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
        var twiddle_tree_owned = twiddles_mod.precomputeM31(allocator, domain.half_coset) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.SingularTwiddle => return PolyError.SingularSystem,
        };
        defer twiddles_mod.deinitM31(allocator, &twiddle_tree_owned);
        return self.evaluateWithTwiddles(
            allocator,
            domain,
            .{
                .root_coset = twiddle_tree_owned.root_coset,
                .twiddles = twiddle_tree_owned.twiddles,
                .itwiddles = twiddle_tree_owned.itwiddles,
            },
        );
    }

    pub fn evaluateWithTwiddles(
        self: CircleCoefficients,
        allocator: std.mem.Allocator,
        domain: CircleDomain,
        twiddle_tree: M31TwiddleTree,
    ) (std.mem.Allocator.Error || PolyError || eval_mod.EvaluationError)!eval_mod.CircleEvaluation {
        if (domain.logSize() < self.log_size) return PolyError.InvalidLogSize;
        if (!domain.half_coset.isDoublingOf(twiddle_tree.root_coset)) return PolyError.InvalidLogSize;
        const values = try allocator.alloc(M31, domain.size());
        errdefer allocator.free(values);
        @memcpy(values[0..self.coeffs.len], self.coeffs);
        if (self.coeffs.len < values.len) @memset(values[self.coeffs.len..], M31.zero());

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

        const line_log_size = domain.half_coset.logSize();
        const twiddle_len = twiddle_tree.twiddles.len;
        var layer_idx: u32 = line_log_size;
        while (layer_idx > 0) {
            layer_idx -= 1;
            const depth = line_log_size - 1 - layer_idx;
            const len = @as(usize, 1) << @intCast(depth);
            const start = twiddle_len - (len * 2);
            const layer_twiddles = twiddle_tree.twiddles[start .. twiddle_len - len];
            for (layer_twiddles, 0..) |twid, h| {
                fftLayerLoopForwardM31(values, @intCast(layer_idx + 1), h, twid);
            }
        }

        const first_line_len = @as(usize, 1) << @intCast(line_log_size - 1);
        const first_line_twiddles = twiddle_tree.twiddles[twiddle_len - (first_line_len * 2) .. twiddle_len - first_line_len];
        var pair_idx: usize = 0;
        var first_h: usize = 0;
        const first_half = values.len / 2;
        while (first_h < first_half) : ({
            first_h += 4;
            pair_idx += 1;
        }) {
            const x = first_line_twiddles[pair_idx * 2];
            const y = first_line_twiddles[pair_idx * 2 + 1];
            fftPairForwardM31(values, first_h, y);
            fftPairForwardM31(values, first_h + 1, y.neg());
            fftPairForwardM31(values, first_h + 2, x.neg());
            fftPairForwardM31(values, first_h + 3, x);
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
    var twiddle_tree_owned = twiddles_mod.precomputeM31(allocator, evaluation.domain.half_coset) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.SingularTwiddle => return PolyError.SingularSystem,
    };
    defer twiddles_mod.deinitM31(allocator, &twiddle_tree_owned);
    return interpolateFromEvaluationWithTwiddles(
        allocator,
        evaluation,
        .{
            .root_coset = twiddle_tree_owned.root_coset,
            .twiddles = twiddle_tree_owned.twiddles,
            .itwiddles = twiddle_tree_owned.itwiddles,
        },
    );
}

pub fn interpolateFromEvaluationWithTwiddles(
    allocator: std.mem.Allocator,
    evaluation: eval_mod.CircleEvaluation,
    twiddle_tree: M31TwiddleTree,
) (std.mem.Allocator.Error || PolyError)!CircleCoefficients {
    const n = evaluation.values.len;
    if (n == 0 or !std.math.isPowerOfTwo(n)) return PolyError.InvalidLength;
    if (evaluation.domain.size() != n) return PolyError.InvalidLength;
    if (!evaluation.domain.half_coset.isDoublingOf(twiddle_tree.root_coset)) return PolyError.InvalidLogSize;
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

    const line_log_size = evaluation.domain.half_coset.logSize();
    const itwiddle_len = twiddle_tree.itwiddles.len;
    const first_line_len = @as(usize, 1) << @intCast(line_log_size - 1);
    const first_line_itwiddles = twiddle_tree.itwiddles[itwiddle_len - (first_line_len * 2) .. itwiddle_len - first_line_len];
    var pair_idx: usize = 0;
    var first_h: usize = 0;
    const first_half = coeffs.len / 2;
    while (first_h < first_half) : ({
        first_h += 4;
        pair_idx += 1;
    }) {
        const x = first_line_itwiddles[pair_idx * 2];
        const y = first_line_itwiddles[pair_idx * 2 + 1];
        fftPairInverseM31(coeffs, first_h, y);
        fftPairInverseM31(coeffs, first_h + 1, y.neg());
        fftPairInverseM31(coeffs, first_h + 2, x.neg());
        fftPairInverseM31(coeffs, first_h + 3, x);
    }

    var layer_idx: u32 = 0;
    while (layer_idx < line_log_size) : (layer_idx += 1) {
        const depth = line_log_size - 1 - layer_idx;
        const len = @as(usize, 1) << @intCast(depth);
        const start = itwiddle_len - (len * 2);
        const layer_twiddles = twiddle_tree.itwiddles[start .. itwiddle_len - len];
        for (layer_twiddles, 0..) |twid, h| {
            fftLayerLoopInverseM31(coeffs, @intCast(layer_idx + 1), h, twid);
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

fn evalAtPointRecursive(
    coeffs: []const M31,
    factors: []const QM31,
    bits_left: u32,
) QM31 {
    std.debug.assert(coeffs.len == (@as(usize, 1) << @intCast(bits_left)));
    if (bits_left == 0) return QM31.fromBase(coeffs[0]);

    const mid = coeffs.len / 2;
    const left = evalAtPointRecursive(coeffs[0..mid], factors, bits_left - 1);
    const right = evalAtPointRecursive(coeffs[mid..], factors, bits_left - 1);
    return left.add(right.mul(factors[bits_left - 1]));
}

inline fn evalAtPointIterative(
    coeffs: []const M31,
    factors: []const QM31,
    log_size: u32,
) QM31 {
    std.debug.assert(coeffs.len == (@as(usize, 1) << @intCast(log_size)));
    std.debug.assert(factors.len == log_size);

    if (log_size == 0) return QM31.fromBase(coeffs[0]);

    var pending: [circle.M31_CIRCLE_LOG_ORDER + 1]QM31 = undefined;

    for (coeffs, 0..) |coeff, coeff_idx| {
        var value = QM31.fromBase(coeff);
        var level: usize = @as(usize, @intCast(@ctz(~coeff_idx)));
        if (level > @as(usize, @intCast(log_size))) level = @as(usize, @intCast(log_size));
        var merge_level: usize = 0;
        while (merge_level < level) : (merge_level += 1) {
            value = pending[merge_level].add(value.mul(factors[merge_level]));
        }
        pending[level] = value;
    }

    return pending[log_size];
}

fn evalAtPointReference(self: CircleCoefficients, point: CirclePointQM31) QM31 {
    if (self.log_size == 0) return QM31.fromBase(self.coeffs[0]);

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
                const mapping_idx = self.log_size - 1 - bit_idx;
                twiddle = twiddle.mul(mappings[mapping_idx]);
            }
            bit_words >>= 1;
        }
        acc = acc.add(QM31.fromBase(coeff).mul(twiddle));
    }
    return acc;
}

fn pointM31IntoQM31(point: circle.CirclePointM31) CirclePointQM31 {
    return .{
        .x = QM31.fromBase(point.x),
        .y = QM31.fromBase(point.y),
    };
}

inline fn repeatedDoubleOnCircleQM31(point: CirclePointQM31, n: u32) CirclePointQM31 {
    var x = point.x;
    var y = point.y;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const xx = x.square();
        const xy = x.mul(y);
        x = xx.add(xx).sub(QM31.one());
        y = xy.add(xy);
    }
    return .{ .x = x, .y = y };
}

inline fn fftLayerLoopForwardM31(
    values: []M31,
    i: u32,
    h: usize,
    twid: M31,
) void {
    const half_block: usize = @as(usize, 1) << @intCast(i);
    const block_start = h << @intCast(i + 1);
    var idx0 = block_start;
    var idx1 = block_start + half_block;
    var l: usize = 0;
    while (l < half_block) : (l += 1) {
        const v0 = values[idx0];
        const v1 = values[idx1];
        const mul = v1.mul(twid);
        values[idx0] = v0.add(mul);
        values[idx1] = v0.sub(mul);
        idx0 += 1;
        idx1 += 1;
    }
}

inline fn fftPairForwardM31(values: []M31, h: usize, twid: M31) void {
    const idx0 = h << 1;
    const idx1 = idx0 + 1;
    const v0 = values[idx0];
    const v1 = values[idx1];
    const mul = v1.mul(twid);
    values[idx0] = v0.add(mul);
    values[idx1] = v0.sub(mul);
}

inline fn fftLayerLoopInverseM31(
    values: []M31,
    i: u32,
    h: usize,
    itwid: M31,
) void {
    const half_block: usize = @as(usize, 1) << @intCast(i);
    const block_start = h << @intCast(i + 1);
    var idx0 = block_start;
    var idx1 = block_start + half_block;
    var l: usize = 0;
    while (l < half_block) : (l += 1) {
        const v0 = values[idx0];
        const v1 = values[idx1];
        values[idx0] = v0.add(v1);
        values[idx1] = v0.sub(v1).mul(itwid);
        idx0 += 1;
        idx1 += 1;
    }
}

inline fn fftPairInverseM31(values: []M31, h: usize, itwid: M31) void {
    const idx0 = h << 1;
    const idx1 = idx0 + 1;
    const v0 = values[idx0];
    const v1 = values[idx1];
    values[idx0] = v0.add(v1);
    values[idx1] = v0.sub(v1).mul(itwid);
}

test "prover poly circle poly: eval at point for constant polynomial" {
    const coeffs = [_]M31{M31.fromCanonical(23)};
    const poly = try CircleCoefficients.initBorrowed(coeffs[0..]);
    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(11);
    try std.testing.expect(poly.evalAtPoint(point).eql(QM31.fromBase(M31.fromCanonical(23))));
}

test "prover poly circle poly: eval at point fast path matches reference" {
    const alloc = std.testing.allocator;
    const log_sizes = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };

    var prng = std.Random.DefaultPrng.init(0x97d8_114a_3f61_55cc);
    const random = prng.random();

    for (log_sizes) |log_size| {
        const n = @as(usize, 1) << @intCast(log_size);
        const coeffs = try alloc.alloc(M31, n);
        defer alloc.free(coeffs);
        for (coeffs) |*coeff| {
            coeff.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, m31.Modulus));
        }

        const poly = try CircleCoefficients.initBorrowed(coeffs);
        var sample_idx: usize = 0;
        while (sample_idx < 24) : (sample_idx += 1) {
            const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(@as(u64, random.int(u32)) + 11);
            const fast = poly.evalAtPoint(point);
            const reference = evalAtPointReference(poly, point);
            try std.testing.expect(fast.eql(reference));
        }
    }
}

test "prover poly circle poly: eval at point iterative matches recursive oracle" {
    const alloc = std.testing.allocator;
    const log_sizes = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };

    var prng = std.Random.DefaultPrng.init(0x8a3f_77de_13cc_59e1);
    const random = prng.random();

    for (log_sizes) |log_size| {
        const n = @as(usize, 1) << @intCast(log_size);
        const coeffs = try alloc.alloc(M31, n);
        defer alloc.free(coeffs);
        for (coeffs) |*coeff| {
            coeff.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, m31.Modulus));
        }

        var sample_idx: usize = 0;
        while (sample_idx < 24) : (sample_idx += 1) {
            const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(@as(u64, random.int(u32)) + 29);

            var factors: [circle.M31_CIRCLE_LOG_ORDER]QM31 = undefined;
            factors[0] = point.y;
            if (log_size > 1) {
                var x = point.x;
                factors[1] = x;
                var bit: u32 = 2;
                while (bit < log_size) : (bit += 1) {
                    x = circle.CirclePoint(QM31).doubleX(x);
                    factors[bit] = x;
                }
            }

            const iterative = evalAtPointIterative(coeffs, factors[0..log_size], log_size);
            const recursive = evalAtPointRecursive(coeffs, factors[0..log_size], log_size);
            try std.testing.expect(iterative.eql(recursive));
        }
    }
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

test "prover poly circle poly: evaluate with twiddles matches evaluate" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 5;
    const domain_log_size: u32 = 7;
    const n = @as(usize, 1) << @intCast(log_size);

    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    for (coeffs, 0..) |*coeff, i| {
        const canonical: u32 = @intCast((i * 23 + 11) % m31.Modulus);
        coeff.* = M31.fromCanonical(canonical);
    }

    const poly = try CircleCoefficients.initBorrowed(coeffs);
    const domain = @import("../../../core/poly/circle/canonic.zig").CanonicCoset.new(domain_log_size).circleDomain();

    const eval_direct = try poly.evaluate(alloc, domain);
    defer alloc.free(@constCast(eval_direct.values));

    var twiddle_tree = try twiddles_mod.precomputeM31(alloc, domain.half_coset);
    defer twiddles_mod.deinitM31(alloc, &twiddle_tree);
    const eval_with_twiddles = try poly.evaluateWithTwiddles(
        alloc,
        domain,
        .{
            .root_coset = twiddle_tree.root_coset,
            .twiddles = twiddle_tree.twiddles,
            .itwiddles = twiddle_tree.itwiddles,
        },
    );
    defer alloc.free(@constCast(eval_with_twiddles.values));

    try std.testing.expectEqualSlices(M31, eval_direct.values, eval_with_twiddles.values);
}

test "prover poly circle poly: interpolate with twiddles matches interpolate" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 6;
    const n = @as(usize, 1) << @intCast(log_size);

    const values = try alloc.alloc(M31, n);
    defer alloc.free(values);
    for (values, 0..) |*value, i| {
        const canonical: u32 = @intCast((i * 7 + 29) % m31.Modulus);
        value.* = M31.fromCanonical(canonical);
    }

    const domain = @import("../../../core/poly/circle/canonic.zig").CanonicCoset.new(log_size).circleDomain();
    const evaluation = try eval_mod.CircleEvaluation.init(domain, values);

    var interpolated_direct = try interpolateFromEvaluation(alloc, evaluation);
    defer interpolated_direct.deinit(alloc);

    var twiddle_tree = try twiddles_mod.precomputeM31(alloc, domain.half_coset);
    defer twiddles_mod.deinitM31(alloc, &twiddle_tree);
    var interpolated_with_twiddles = try interpolateFromEvaluationWithTwiddles(
        alloc,
        evaluation,
        .{
            .root_coset = twiddle_tree.root_coset,
            .twiddles = twiddle_tree.twiddles,
            .itwiddles = twiddle_tree.itwiddles,
        },
    );
    defer interpolated_with_twiddles.deinit(alloc);

    try std.testing.expectEqualSlices(
        M31,
        interpolated_direct.coefficients(),
        interpolated_with_twiddles.coefficients(),
    );
}
