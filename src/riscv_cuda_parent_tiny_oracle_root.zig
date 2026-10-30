const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
test "export original tiny parent transform oracle" {
    const a = std.testing.allocator;
    const path = std.posix.getenv("STWO_TINY_ORACLE") orelse return error.MissingOracleOutput;
    var f = try std.fs.cwd().createFile(path, .{});
    defer f.close();
    var prng = std.Random.DefaultPrng.init(0x522345);
    const rng = prng.random();
    for (1..3) |ll| {
        const log: u32 = @intCast(ll);
        const n = @as(usize, 1) << @intCast(log);
        const domain = core.poly.circle.CanonicCoset.new(log).circleDomain();
        var tw = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
        defer engine.poly.twiddles.deinitM31(a, &tw);
        const head = [_]u32{ log, 1024 };
        try f.writeAll(std.mem.sliceAsBytes(&head));
        try f.writeAll(std.mem.sliceAsBytes(tw.twiddles));
        try f.writeAll(std.mem.sliceAsBytes(tw.itwiddles));
        for (0..1024) |case| {
            var input: [4]core.fields.m31.M31 = undefined;
            for (input[0..n]) |*v| v.* = core.fields.m31.M31.fromCanonical(if (case == 0) 0 else if (case == 1) core.fields.m31.Modulus - 1 else rng.uintLessThan(u32, core.fields.m31.Modulus));
            const evaluation = try engine.poly.circle.CircleEvaluation.init(domain, input[0..n]);
            var coeff = try engine.poly.circle.poly.interpolateFromEvaluation(a, evaluation);
            defer coeff.deinit(a);
            const half = try engine.poly.circle.CircleCoefficients.initBorrowed(input[0 .. n / 2]);
            const extended = try half.evaluate(a, domain);
            defer a.free(extended.values);
            try f.writeAll(std.mem.sliceAsBytes(input[0..n]));
            try f.writeAll(std.mem.sliceAsBytes(coeff.coeffs));
            try f.writeAll(std.mem.sliceAsBytes(extended.values));
        }
    }
}
