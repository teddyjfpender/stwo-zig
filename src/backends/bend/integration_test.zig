const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const bend = @import("stwo_bend_backend");
const M31 = core.fields.m31.M31;
const B = bend.BendBackend(.{ .executable = @import("config").executable });
const tw = prover.poly.twiddles;
fn view(tree: tw.TwiddleTree([]M31)) tw.TwiddleTree([]const M31) {
    return .init(tree.root_coset, tree.twiddles, tree.itwiddles);
}
test "bend native: roundtrip and combined LDE match Zig across small and fused sizes" {
    const a = std.testing.allocator;
    for ([_]u32{ 1, 2, 3, 5, 10 }) |log| {
        const d = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
        const ed = core.poly.circle.canonic.CanonicCoset.new(log + 1).circleDomain();
        var tree = try tw.precomputeM31(a, d.half_coset);
        defer tw.deinitM31(a, &tree);
        var etree = try tw.precomputeM31(a, ed.half_coset);
        defer tw.deinitM31(a, &etree);
        const original = try a.alloc(M31, d.size());
        defer a.free(original);
        for (original, 0..) |*x, i| x.* = M31.fromCanonical(@intCast(i * 19));
        const base = try a.dupe(M31, original);
        defer a.free(base);
        const extended = try a.alloc(M31, ed.size());
        defer a.free(extended);
        _ = try B.evaluateCircleBuffers(a, &.{base}, d, view(tree));
        _ = try B.interpolateCircleBuffers(a, &.{base}, d, view(tree));
        try std.testing.expectEqualSlices(M31, original, base);
        const receipt = try B.interpolateAndEvaluateCircleBuffers(a, &.{original}, &.{base}, &.{extended}, extended, 0, extended.len, d, view(tree), ed, view(etree));
        try receipt.validate();
        const expected = try a.alloc(M31, ed.size());
        defer a.free(expected);
        @memcpy(expected[0..base.len], original);
        var b = [_][]M31{expected[0..base.len]};
        try prover.poly.circle.poly.interpolateBuffersWithTwiddles(&b, d, view(tree));
        @memset(expected[base.len..], M31.zero());
        var e = [_][]M31{expected};
        try prover.poly.circle.poly.evaluateBuffersWithTwiddles(&e, ed, view(etree));
        try std.testing.expectEqualSlices(M31, expected, extended);
        try std.testing.expectError(error.InvalidColumns, B.evaluateCircleBuffers(a, &.{base[1..]}, d, view(tree)));
    }
}
test "bend native: missing runtime errors without fallback" {
    const Missing = bend.BendBackend(.{ .executable = "/does-not-exist/stwo-bend" });
    const a = std.testing.allocator;
    const d = core.poly.circle.canonic.CanonicCoset.new(1).circleDomain();
    var tree = try tw.precomputeM31(a, d.half_coset);
    defer tw.deinitM31(a, &tree);
    var values = [_]M31{ M31.one(), M31.zero() };
    try std.testing.expectError(error.FileNotFound, Missing.evaluateCircleBuffers(a, &.{&values}, d, view(tree)));
    try std.testing.expectEqual(@as(u32, 1), values[0].v);
}

test "bend persistent session: repeated transforms and consuming multi-fold FRI match core" {
    const P = bend.BendBackend(.{ .executable = @import("config").executable, .persistent = true });
    defer bend.runtime.shutdown();
    const a = std.testing.allocator;
    const Q = core.fields.qm31.QM31;
    const d = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    var tree = try tw.precomputeM31(a, d.half_coset);
    defer tw.deinitM31(a, &tree);
    var vals: [32]M31 = undefined;
    for (&vals, 0..) |*x, i| x.* = M31.fromCanonical(@intCast(i * 65537));
    const original = vals;
    for (0..3) |_| {
        _ = try P.evaluateCircleBuffers(a, &.{&vals}, d, view(tree));
        _ = try P.interpolateCircleBuffers(a, &.{&vals}, d, view(tree));
        try std.testing.expectEqualSlices(M31, &original, &vals);
    }
    const line = try core.poly.line.LineDomain.init(core.circle.Coset.halfOdds(5));
    var workspace = try core.fri.FoldLineWorkspace.init(a, 16);
    defer workspace.deinit(a);
    const alpha = Q.fromU32Unchecked(17, 2147483646, 65535, 12345);
    const values = try a.alloc(Q, 32);
    // foldLineN consumes values on success; testing allocator catches leaks.
    for (values, 0..) |*x, i| x.* = Q.fromU32Unchecked(@intCast(i * 123), 65536, 32767, 1);
    const expected = try @call(.never_inline, core.fri.foldLineNWithWorkspace, .{ a, values, line, alpha, &workspace, @as(u32, 3) });
    defer a.free(expected.values);
    const actual = try P.foldLineN(a, values, line, alpha, &workspace, 3);
    defer a.free(actual.values);
    try std.testing.expectEqualSlices(Q, expected.values, actual.values);
    var dst = [_]Q{Q.one()} ** 16;
    var want = dst;
    const planes: [4][]const M31 = .{ &vals, &vals, &vals, &vals };
    var circle_workspace = try core.fri.FoldCircleWorkspace.init(a, 16);
    defer circle_workspace.deinit(a);
    try @call(.never_inline, core.fri.foldCircleColumnsIntoLineWithWorkspace, .{ a, &want, planes, d, alpha, &circle_workspace });
    try P.foldCircleIntoLine(a, &dst, planes, d, alpha, &circle_workspace);
    try std.testing.expectEqualSlices(Q, &want, &dst);
    const calls = bend.runtime.snapshot().calls;
    try std.testing.expect(calls[0] >= 3 and calls[1] >= 3 and calls[4] >= 4);
}
