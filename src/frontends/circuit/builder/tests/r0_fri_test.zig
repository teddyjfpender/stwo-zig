//! Rung R0, `fri` section of `vectors/circuit/r0/primitives.json` (oracle
//! `primitives` subcommand over https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230), inlined: the circuit verifier
//! folds FRI layers with the same arithmetic as `stwo_core.fri`, so the core
//! folds must reproduce the oracle's per-fold `values_sha256` digests.

const std = @import("std");
const stwo_core = @import("stwo_core");
const circuit_summary = @import("../../testing/circuit_summary.zig");

const fri = stwo_core.fri;
const line = stwo_core.poly.line;
const canonic = stwo_core.poly.circle.canonic;
const QM31 = stwo_core.fields.qm31.QM31;
const FoldLineWorkspace = fri.FoldLineWorkspace;
const foldLineSingleStep = fri.foldLineSingleStep;
const foldCircleIntoLine = fri.foldCircleIntoLine;

fn expectValuesDigest(expected_hex: *const [64]u8, values: []const QM31) !void {
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, &expected, &circuit_summary.valuesSha256(values));
}

// The R0 `fri` vector of `vectors/circuit/r0/primitives.json` (oracle `primitives`, section
// `fri`), inlined: a 2^8 circle evaluation folded with fold_step 4 to a last layer of degree
// bound 0, replaying the prover's layer schedule with fixed alphas (circle-to-line fold, then
// `fold_step - 1` line folds with the squared alpha; then `fold_step` line folds per layer).
test "R0: FRI fold_step 4 folds match the oracle digests" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 8;
    const p: u64 = stwo_core.fields.m31.Modulus;
    var input: [1 << log_size]QM31 = undefined;
    for (&input, 0..) |*value, i| {
        const x: u64 = i;
        value.* = QM31.fromU32Unchecked(
            @intCast((x + 1) % p),
            @intCast((2 * x + 3) % p),
            @intCast((3 * x + 5) % p),
            @intCast((7 * x + 11) % p),
        );
    }
    try expectValuesDigest("676b7f2de3eb1878a8aee09df51706bfe3eb7dcb3c3588f3994c1e07e41dd747", &input);

    const layer_alphas = [_]QM31{
        QM31.fromU32Unchecked(5, 7, 11, 13),
        QM31.fromU32Unchecked(17, 19, 23, 29),
    };
    // Per single fold: the output digest, in schedule order.
    const expected = [_]*const [64]u8{
        "012d32936102268b54bb331e44297762696434e0f64e8794086ec51d373d44ec",
        "2b8c1166945cb6b198e1f327ba230bc882f1570545d6b5de4464bf6418bff673",
        "6fe210bdddeb5fcb7e4357f9750d36f7dd3efe03202bc5aa178385b93ed36b06",
        "f151fefeb2b3dc0198b6e3aec72e44345a3ec9f6f4cb48a17d827b780448e17f",
        "f1a2fb03345029790266384124d46d0ac91bd8b0600f6e56841b79916613f279",
        "c0760805bf628f35c0c3e6032c651b7417bfbb95ceb9148c60c9ddec4d38c425",
        "100b6eec7158de19da00be74f6c0d1d560889579ab330526ed207de8dd4c98d6",
        "d5c4299b10a98d577d3b24240c7d7854732120dbafa02f844dee8566a6ed02e4",
    };

    // First layer: circle -> line with alpha_0 (into a zero accumulator).
    const source_domain = canonic.CanonicCoset.new(log_size).circleDomain();
    const line_eval = try alloc.alloc(QM31, input.len / 2);
    @memset(line_eval, QM31.zero());
    try foldCircleIntoLine(line_eval, &input, source_domain, layer_alphas[0]);
    try expectScalarCircleFold(&input, line_eval, source_domain, layer_alphas[0]);
    try expectValuesDigest(expected[0], line_eval);

    var workspace = try FoldLineWorkspace.init(alloc, line_eval.len / 2);
    defer workspace.deinit(alloc);
    var values = line_eval;
    defer alloc.free(values);
    var domain = try line.LineDomain.init(source_domain.half_coset);
    var step: usize = 1;
    // Then `fold_step - 1` line folds with alpha_0^2, alpha_0^4, alpha_0^8, and one layer of
    // `fold_step` folds with alpha_1, alpha_1^2, alpha_1^4, alpha_1^8.
    const schedule = [_]struct { alpha: QM31, n_folds: u32 }{
        .{ .alpha = layer_alphas[0].square(), .n_folds = 3 },
        .{ .alpha = layer_alphas[1], .n_folds = 4 },
    };
    for (schedule) |layer| {
        const layer_input = try alloc.dupe(QM31, values);
        defer alloc.free(layer_input);
        const layer_domain = domain;
        var alpha = layer.alpha;
        var fold: u32 = 0;
        while (fold < layer.n_folds) : (fold += 1) {
            const folded = try foldLineSingleStep(alloc, values, domain, alpha, &workspace);
            alloc.free(values);
            values = folded.values;
            domain = folded.domain;
            try expectValuesDigest(expected[step], values);
            step += 1;
            alpha = alpha.square();
        }
        // The multi-fold entry point squares the alpha between folds identically.
        const direct = try fri.foldLineNWithWorkspace(
            alloc,
            layer_input,
            layer_domain,
            layer.alpha,
            &workspace,
            layer.n_folds,
        );
        defer alloc.free(direct.values);
        try std.testing.expectEqualSlices(QM31, values, direct.values);
    }
    try std.testing.expectEqual(expected.len, step);
    try std.testing.expectEqual(@as(usize, 1), values.len);
    try std.testing.expect(values[0].eql(QM31.fromU32Unchecked(1266552422, 1856893702, 1654478679, 295175920)));
}

// The reference avoids field helpers, vector arithmetic and batch inversion.
// Authenticate it against the oracle before using it to diagnose optimized code.
fn expectScalarCircleFold(input: []const QM31, actual: []const QM31, domain: stwo_core.poly.circle.domain.CircleDomain, alpha: QM31) !void {
    const a = [_]u64{ alpha.c0.a.v, alpha.c0.b.v, alpha.c1.a.v, alpha.c1.b.v };
    const reference = try std.testing.allocator.alloc(QM31, actual.len);
    defer std.testing.allocator.free(reference);
    for (reference, 0..) |*value, i| {
        const point = domain.at(stwo_core.utils.bitReverseIndex(i << 1, domain.logSize()));
        try std.testing.expect(point.y.v != 0);
        var exponent: u64 = modulus - 2;
        var base: u64 = point.y.v;
        var inverse: u64 = 1;
        while (exponent != 0) : (exponent >>= 1) {
            if (exponent & 1 != 0) inverse = inverse * base % modulus;
            base = base * base % modulus;
        }
        const left = &input[2 * i];
        const right = &input[2 * i + 1];
        const x = [_]u64{ left.c0.a.v, left.c0.b.v, left.c1.a.v, left.c1.b.v };
        const y = [_]u64{ right.c0.a.v, right.c0.b.v, right.c1.a.v, right.c1.b.v };
        var sum: [4]u64 = undefined;
        var difference: [4]u64 = undefined;
        for (0..4) |j| {
            sum[j] = (x[j] + y[j]) % modulus;
            difference[j] = (x[j] + modulus - y[j]) % modulus * inverse % modulus;
        }
        const product = scalarProduct(a, difference);
        var expected: [4]u32 = undefined;
        for (0..4) |j| expected[j] = @intCast((sum[j] + product[j]) % modulus);
        value.* = QM31.fromU32Unchecked(expected[0], expected[1], expected[2], expected[3]);
    }
    try expectValuesDigest("012d32936102268b54bb331e44297762696434e0f64e8794086ec51d373d44ec", reference);
    for (reference, actual, 0..) |*expected_value, *value, i| {
        const expected = [_]u32{ expected_value.c0.a.v, expected_value.c0.b.v, expected_value.c1.a.v, expected_value.c1.b.v };
        const stored = [_]u32{ value.c0.a.v, value.c0.b.v, value.c1.a.v, value.c1.b.v };
        if (!std.mem.eql(u32, &expected, &stored)) std.debug.print("FRI integer differential index={d}\n", .{i});
        try std.testing.expectEqualSlices(u32, &expected, &stored);
        try std.testing.expectEqualSlices(u32, &stored, &@import("stwo_circuit_frontend").builder.ivalue.limbs(value.*));
    }
}

const modulus: u64 = 2147483647;
fn scalarProduct(a: [4]u64, b: [4]u64) [4]u64 {
    // (a0+a1*i) + (a2+a3*i)*u, with i^2=-1 and u^2=2+i.
    const ac = scalarComplex(a[0..2].*, b[0..2].*);
    const bd = scalarComplex(a[2..4].*, b[2..4].*);
    const cross = scalarComplex(.{ (a[0] + a[2]) % modulus, (a[1] + a[3]) % modulus }, .{ (b[0] + b[2]) % modulus, (b[1] + b[3]) % modulus });
    return .{
        (ac[0] + 2 * bd[0] + modulus - bd[1]) % modulus,
        (ac[1] + 2 * bd[1] + bd[0]) % modulus,
        (cross[0] + 2 * modulus - ac[0] - bd[0]) % modulus,
        (cross[1] + 2 * modulus - ac[1] - bd[1]) % modulus,
    };
}

fn scalarComplex(a: [2]u64, b: [2]u64) [2]u64 {
    return .{ (a[0] * b[0] % modulus + modulus - a[1] * b[1] % modulus) % modulus, (a[0] * b[1] % modulus + a[1] * b[0] % modulus) % modulus };
}
