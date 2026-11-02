const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const G = engine.lookups.gkr_prover.ForField(O);
const Mle = engine.lookups.mle.MleFor;
const a = std.testing.allocator;
extern "c" fn rv64_test_mul(*const [8]u32, *const [8]u32, *[8]u32) void;
extern "c" fn rv64_test_combine(*const [8]u32, *const [8]u32, *const [8]u32, *const [8]u32, *[16]u32) void;
extern "c" fn rv64_test_sum([*]const [8]u32, [*]const [8]u32, [*]const [8]u32, *const [8]u32, u32, u32, *[16]u32) void;
fn words(v: O) [8]u32 {
    var out: [8]u32 = undefined;
    for (v.toM31Array(), &out) |c, *d| d.* = c.v;
    return out;
}
fn value(seed: u32) O {
    var out: [8]M = undefined;
    var x = seed;
    for (&out) |*c| {
        x = x *% 1664525 +% 1013904223;
        c.* = M.fromCanonical(x % core.fields.m31.Modulus);
    }
    return O.fromM31Array(out);
}
fn expect(expected: O, got: []const u32) !void {
    try std.testing.expectEqualSlices(u32, &words(expected), got);
}
test "RV64 CUDA host arithmetic matches native OM31 in every basis coordinate and random full-width operands" {
    for (0..8) |i| for (0..8) |j| {
        var x = [_]M{M.zero()} ** 8;
        var y = x;
        x[i] = M.one();
        y[j] = M.one();
        const u = O.fromM31Array(x);
        const v = O.fromM31Array(y);
        var out: [8]u32 = undefined;
        rv64_test_mul(&words(u), &words(v), &out);
        try expect(u.mul(v), &out);
    };
    for (0..1024) |i| {
        const x = value(@intCast(i));
        const y = value(@intCast(i + 8191));
        var out: [8]u32 = undefined;
        rv64_test_mul(&words(x), &words(y), &out);
        try expect(x.mul(y), &out);
        var combined: [16]u32 = undefined;
        const z = value(@intCast(i + 17));
        const w = value(@intCast(i + 31));
        rv64_test_combine(&words(x), &words(y), &words(z), &words(w), &combined);
        try expect(x.mul(w).add(z.mul(y)), combined[0..8]);
        try expect(y.mul(w), combined[8..16]);
    }
}
test "RV64 CUDA sumcheck arithmetic agrees with the native GKR polynomial for base and secure numerators" {
    inline for (.{ 4, 8, 16, 256, 1024 }) |count| {
        var denominators: [count]O = undefined;
        var numerators: [count]O = undefined;
        var base_n: [count]M = undefined;
        var dn: [count][8]u32 = undefined;
        var nn: [count][8]u32 = undefined;
        for (0..count) |i| {
            denominators[i] = value(@intCast(100 + i));
            base_n[i] = M.fromCanonical(@intCast(i * 11));
            dn[i] = words(denominators[i]);
        }
        var y: [std.math.log2_int(usize, count) - 1]O = undefined;
        for (&y, 0..) |*c, i| c.* = value(@intCast(2000 + i));
        var eq = try G.EqEvals.generate(a, &y);
        defer eq.deinit(a);
        var eq_words: [count / 4][8]u32 = undefined;
        for (&eq_words, 0..) |*w, i| w.* = words(eq.at(i));
        const lambda = value(9000);
        inline for (.{ true, false }) |base_mode| {
            for (0..count) |i| {
                numerators[i] = if (base_mode) O.fromBase(base_n[i]) else value(@intCast(7000 + i));
                nn[i] = words(numerators[i]);
            }
            const layer: G.Layer = if (base_mode) .{ .LogUpMultiplicities = .{ .numerators = try Mle(O, M).initBorrowed(&base_n), .denominators = try Mle(O, O).initBorrowed(&denominators) } } else .{ .LogUpGeneric = .{ .numerators = try Mle(O, O).initBorrowed(&numerators), .denominators = try Mle(O, O).initBorrowed(&denominators) } };
            const oracle = G.GkrMultivariatePolyOracle{ .eq_evals = eq.borrowed(), .input_layer = layer, .eq_fixed_var_correction = O.one(), .lambda = lambda };
            const claim = value(91);
            var native_poly = try oracle.sumAsPolyInFirstVariable(a, claim);
            defer native_poly.deinit(a);
            var raw: [16]u32 = undefined;
            rv64_test_sum(&nn, &dn, &eq_words, &words(lambda), count, @intFromBool(base_mode), &raw);
            var raw_o: [2]O = undefined;
            for (&raw_o, 0..) |*out, k| {
                var fields: [8]M = undefined;
                for (&fields, 0..) |*f, c| f.* = M.fromCanonical(raw[k * 8 + c]);
                out.* = O.fromM31Array(fields);
            }
            var from_cuda_math = try G.correctSumAsPolyInFirstVariable(a, raw_o[0], raw_o[1], claim, &y, y.len);
            defer from_cuda_math.deinit(a);
            for (0..5) |i| {
                const x = value(@intCast(10000 + i));
                try std.testing.expect(native_poly.evalAtPoint(x).eql(from_cuda_math.evalAtPoint(x)));
            }
        }
    }
}
