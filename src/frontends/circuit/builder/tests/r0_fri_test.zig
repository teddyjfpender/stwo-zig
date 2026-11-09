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

// The scalar path deliberately avoids QM31 vector arithmetic and batch inversion.
// It distinguishes a wrong fold from a wrong digest/projection without repinning.
fn expectScalarCircleFold(input: []const QM31, actual: []const QM31, domain: stwo_core.poly.circle.domain.CircleDomain, alpha: QM31) !void {
    const M31 = stwo_core.fields.m31.M31;
    const a = [_]M31{ alpha.c0.a, alpha.c0.b, alpha.c1.a, alpha.c1.b };
    const reference = try std.testing.allocator.alloc(QM31, actual.len);
    defer std.testing.allocator.free(reference);
    for (actual, 0..) |*value, i| {
        const point = domain.at(stwo_core.utils.bitReverseIndex(i << 1, domain.logSize()));
        const inverse_y = try point.y.inv();
        const left = &input[2 * i];
        const right = &input[2 * i + 1];
        const x = [_]M31{ left.c0.a, left.c0.b, left.c1.a, left.c1.b };
        const y = [_]M31{ right.c0.a, right.c0.b, right.c1.a, right.c1.b };
        var sum: [4]M31 = undefined;
        var difference: [4]M31 = undefined;
        for (0..4) |j| {
            sum[j] = x[j].add(y[j]);
            difference[j] = x[j].sub(y[j]).mul(inverse_y);
        }
        const product = scalarProduct(a, difference);
        var expected: [4]u32 = undefined;
        for (0..4) |j| expected[j] = sum[j].add(product[j]).v;
        reference[i] = QM31.fromU32Unchecked(expected[0], expected[1], expected[2], expected[3]);
        const stored = [_]u32{ value.c0.a.v, value.c0.b.v, value.c1.a.v, value.c1.b.v };
        if (!std.mem.eql(u32, &expected, &stored))
            std.debug.print("FRI scalar differential index={d} y={d} inverse={d}\n", .{ i, point.y.v, inverse_y.v });
        try std.testing.expectEqualSlices(u32, &expected, &stored);
        // Also guard the by-value canonical projection used by digest consumers.
        try std.testing.expectEqualSlices(u32, &stored, &@import("stwo_circuit_frontend").builder.ivalue.limbs(value.*));
    }
    try expectValuesDigest("012d32936102268b54bb331e44297762696434e0f64e8794086ec51d373d44ec", reference);
}

fn scalarProduct(a: [4]stwo_core.fields.m31.M31, b: [4]stwo_core.fields.m31.M31) [4]stwo_core.fields.m31.M31 {
    // (a0+a1*i) + (a2+a3*i)*u, with i^2=-1 and u^2=2+i.
    const ac = scalarComplex(a[0..2].*, b[0..2].*);
    const bd = scalarComplex(a[2..4].*, b[2..4].*);
    const cross = scalarComplex(.{ a[0].add(a[2]), a[1].add(a[3]) }, .{ b[0].add(b[2]), b[1].add(b[3]) });
    return .{
        ac[0].add(bd[0].add(bd[0]).sub(bd[1])),
        ac[1].add(bd[1].add(bd[1]).add(bd[0])),
        cross[0].sub(ac[0]).sub(bd[0]),
        cross[1].sub(ac[1]).sub(bd[1]),
    };
}

fn scalarComplex(a: [2]stwo_core.fields.m31.M31, b: [2]stwo_core.fields.m31.M31) [2]stwo_core.fields.m31.M31 {
    return .{ a[0].mul(b[0]).sub(a[1].mul(b[1])), a[0].mul(b[1]).add(a[1].mul(b[0])) };
}
