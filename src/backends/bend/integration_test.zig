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
