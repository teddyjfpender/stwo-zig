const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const canonic = @import("stwo_core").poly.circle.canonic;
const eval_mod = @import("stwo_prover_engine").poly.circle.evaluation;
const fft_kernels = @import("stwo_prover_engine").poly.circle.fft_kernels;
const circle_poly = @import("stwo_prover_engine").poly.circle.poly;
const twiddles_mod = @import("stwo_prover_engine").poly.twiddles;

const M31 = m31.M31;
const CircleCoefficients = circle_poly.CircleCoefficients;

test "prover poly circle poly: owned interpolation matches cloned interpolation" {
    const alloc = std.testing.allocator;
    const domain = canonic.CanonicCoset.new(5).circleDomain();
    const values = try alloc.alloc(M31, domain.size());
    defer alloc.free(values);
    for (values, 0..) |*value, i| {
        value.* = M31.fromCanonical(@intCast((i * 13 + 7) % m31.Modulus));
    }

    const twiddle_tree = try twiddles_mod.precomputeM31(alloc, domain.half_coset);
    defer {
        var owned = twiddle_tree;
        twiddles_mod.deinitM31(alloc, &owned);
    }

    const evaluation = try eval_mod.CircleEvaluation.init(domain, values);
    var cloned = try circle_poly.interpolateFromEvaluationWithTwiddles(
        alloc,
        evaluation,
        .{
            .root_coset = twiddle_tree.root_coset,
            .twiddles = twiddle_tree.twiddles,
            .itwiddles = twiddle_tree.itwiddles,
        },
    );
    defer cloned.deinit(alloc);

    const owned_values = try alloc.dupe(M31, values);
    var in_place = try circle_poly.interpolateOwnedValuesWithTwiddles(
        domain,
        owned_values,
        .{
            .root_coset = twiddle_tree.root_coset,
            .twiddles = twiddle_tree.twiddles,
            .itwiddles = twiddle_tree.itwiddles,
        },
    );
    defer in_place.deinit(alloc);

    try std.testing.expectEqual(cloned.logSize(), in_place.logSize());
    try std.testing.expectEqualSlices(M31, cloned.coefficients(), in_place.coefficients());
}

test "prover poly circle poly: batched owned interpolation matches scalar helper" {
    const alloc = std.testing.allocator;
    const domain = canonic.CanonicCoset.new(5).circleDomain();
    const twiddle_tree = try twiddles_mod.precomputeM31(alloc, domain.half_coset);
    defer {
        var owned = twiddle_tree;
        twiddles_mod.deinitM31(alloc, &owned);
    }

    var prng = std.Random.DefaultPrng.init(0x6d41_9b83_7e52_4c11);
    const random = prng.random();

    for ([_]usize{ 1, 2, 3, 4, 5, 6, 7, 8 }) |column_count| {
        const batch_values = try alloc.alloc([]M31, column_count);
        defer alloc.free(batch_values);
        const scalar_values = try alloc.alloc([]M31, column_count);
        defer alloc.free(scalar_values);

        for (0..column_count) |idx| {
            batch_values[idx] = try alloc.alloc(M31, domain.size());
            scalar_values[idx] = try alloc.alloc(M31, domain.size());
            for (batch_values[idx], scalar_values[idx]) |*batch, *scalar| {
                const value = M31.fromCanonical(random.intRangeLessThan(u32, 0, m31.Modulus));
                batch.* = value;
                scalar.* = value;
            }
        }

        defer {
            for (batch_values) |values| alloc.free(values);
            for (scalar_values) |values| if (values.len != 0) alloc.free(values);
        }

        try circle_poly.interpolateOwnedValuesBatchWithTwiddles(
            domain,
            batch_values,
            .{
                .root_coset = twiddle_tree.root_coset,
                .twiddles = twiddle_tree.twiddles,
                .itwiddles = twiddle_tree.itwiddles,
            },
        );
        for (scalar_values, 0..) |values, idx| {
            var scalar = try circle_poly.interpolateOwnedValuesWithTwiddles(
                domain,
                values,
                .{
                    .root_coset = twiddle_tree.root_coset,
                    .twiddles = twiddle_tree.twiddles,
                    .itwiddles = twiddle_tree.itwiddles,
                },
            );
            defer scalar.deinit(alloc);
            scalar_values[idx] = &[_]M31{};
            try std.testing.expectEqualSlices(M31, scalar.coefficients(), batch_values[idx]);
        }
    }
}

test "prover poly circle poly: batched evaluation matches scalar helper" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 5;
    const extended_log_size: u32 = 7;
    const domain = canonic.CanonicCoset.new(extended_log_size).circleDomain();
    const twiddle_tree = try twiddles_mod.precomputeM31(alloc, domain.half_coset);
    defer {
        var owned = twiddle_tree;
        twiddles_mod.deinitM31(alloc, &owned);
    }

    var prng = std.Random.DefaultPrng.init(0x4f17_5c32_e992_120d);
    const random = prng.random();

    for ([_]usize{ 1, 2, 3, 4, 5, 6, 7, 8 }) |poly_count| {
        const polys = try alloc.alloc(CircleCoefficients, poly_count);
        defer alloc.free(polys);
        var initialized: usize = 0;
        defer {
            for (polys[0..initialized]) |*poly| poly.deinit(alloc);
        }

        for (0..poly_count) |idx| {
            const coeffs = try alloc.alloc(M31, @as(usize, 1) << @intCast(log_size));
            for (coeffs) |*coeff| {
                coeff.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, m31.Modulus));
            }
            polys[idx] = try CircleCoefficients.initOwned(coeffs);
            initialized += 1;
        }

        const batch_values = try circle_poly.evaluateManyWithTwiddles(
            alloc,
            polys,
            domain,
            .{
                .root_coset = twiddle_tree.root_coset,
                .twiddles = twiddle_tree.twiddles,
                .itwiddles = twiddle_tree.itwiddles,
            },
        );
        defer {
            for (batch_values) |values| alloc.free(values);
            alloc.free(batch_values);
        }

        for (polys, 0..) |poly, idx| {
            const scalar = try poly.evaluateWithTwiddles(
                alloc,
                domain,
                .{
                    .root_coset = twiddle_tree.root_coset,
                    .twiddles = twiddle_tree.twiddles,
                    .itwiddles = twiddle_tree.itwiddles,
                },
            );
            defer alloc.free(@constCast(scalar.values));
            try std.testing.expectEqualSlices(M31, scalar.values, batch_values[idx]);
        }
    }
}

test "prover poly circle: four- and five-layer tails match independent stages" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x9b05_688c_2b3e_6c1f);
    const random = prng.random();

    for ([_]u32{ 4, 5 }) |layer_count| {
        const block_len = @as(usize, 1) << @intCast(layer_count);
        const value_count = block_len * 3;
        const input = try allocator.alloc(M31, value_count);
        defer allocator.free(input);
        const expected = try allocator.alloc(M31, value_count);
        defer allocator.free(expected);
        const actual = try allocator.alloc(M31, value_count);
        defer allocator.free(actual);
        const t4s = try allocator.alloc(M31, value_count / 32);
        defer allocator.free(t4s);
        const t3s = try allocator.alloc(M31, value_count / 16);
        defer allocator.free(t3s);
        const t2s = try allocator.alloc(M31, value_count / 8);
        defer allocator.free(t2s);
        const t01s = try allocator.alloc(M31, value_count / 4);
        defer allocator.free(t01s);

        for (input) |*value| value.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, m31.Modulus));
        for (t4s) |*value| value.* = M31.fromCanonical(random.intRangeLessThan(u32, 1, m31.Modulus));
        for (t3s) |*value| value.* = M31.fromCanonical(random.intRangeLessThan(u32, 1, m31.Modulus));
        for (t2s) |*value| value.* = M31.fromCanonical(random.intRangeLessThan(u32, 1, m31.Modulus));
        for (t01s) |*value| value.* = M31.fromCanonical(random.intRangeLessThan(u32, 1, m31.Modulus));

        @memcpy(expected, input);
        @memcpy(actual, input);
        if (layer_count == 5) {
            for (t4s, 0..) |twiddle, block| fft_kernels.fftLayerLoopForwardM31(expected, 4, block, twiddle);
        }
        for (t3s, 0..) |twiddle, block| fft_kernels.fftLayerLoopForwardM31(expected, 3, block, twiddle);
        for (t2s, 0..) |twiddle, block| fft_kernels.fftLayerLoopForwardM31(expected, 2, block, twiddle);
        for (t01s, 0..) |twiddle, block| fft_kernels.fftLayerLoopForwardM31(expected, 1, block, twiddle);
        for (0..value_count / 8) |block| {
            const x = t01s[block * 2];
            const y = t01s[block * 2 + 1];
            const pair_twiddles = [_]M31{ y, y.neg(), x.neg(), x };
            for (pair_twiddles, 0..) |twiddle, pair| {
                fft_kernels.fftPairForwardM31(expected, block * 4 + pair, twiddle);
            }
        }
        if (layer_count == 4) {
            fft_kernels.fftBottomFourLayersForwardM31(actual, t3s, t2s, t01s);
        } else {
            fft_kernels.fftBottomFiveLayersForwardM31(actual, t4s, t3s, t2s, t01s);
        }
        try std.testing.expectEqualSlices(M31, expected, actual);

        @memcpy(expected, input);
        @memcpy(actual, input);
        for (0..value_count / 8) |block| {
            const x = t01s[block * 2];
            const y = t01s[block * 2 + 1];
            const pair_twiddles = [_]M31{ y, y.neg(), x.neg(), x };
            for (pair_twiddles, 0..) |twiddle, pair| {
                fft_kernels.fftPairInverseM31(expected, block * 4 + pair, twiddle);
            }
        }
        for (t01s, 0..) |twiddle, block| fft_kernels.fftLayerLoopInverseM31(expected, 1, block, twiddle);
        for (t2s, 0..) |twiddle, block| fft_kernels.fftLayerLoopInverseM31(expected, 2, block, twiddle);
        for (t3s, 0..) |twiddle, block| fft_kernels.fftLayerLoopInverseM31(expected, 3, block, twiddle);
        if (layer_count == 5) {
            for (t4s, 0..) |twiddle, block| fft_kernels.fftLayerLoopInverseM31(expected, 4, block, twiddle);
        }
        if (layer_count == 4) {
            fft_kernels.fftBottomFourLayersInverseM31(actual, t3s, t2s, t01s);
        } else {
            fft_kernels.fftBottomFiveLayersInverseM31(actual, t4s, t3s, t2s, t01s);
        }
        try std.testing.expectEqualSlices(M31, expected, actual);
    }
}
