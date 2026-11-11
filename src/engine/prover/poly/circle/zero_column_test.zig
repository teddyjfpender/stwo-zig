const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const P = @import("poly.zig");
const T = @import("transforms.zig");
const Tw = @import("../twiddles.zig");
const E = @import("evaluation.zig").CircleEvaluation;
const a = std.testing.allocator;

fn lifecycle(allocator: std.mem.Allocator) !void {
    const domain = core.poly.circle.canonic.CanonicCoset.new(11).circleDomain();
    var tree = try Tw.precomputeM31(allocator, domain.half_coset);
    defer Tw.deinitM31(allocator, &tree);
    const borrowed = Tw.TwiddleTree([]const M).init(tree.root_coset, tree.twiddles, tree.itwiddles);
    var zeros: [512]M = @splat(M.zero());
    var nonzero: [1024]M = @splat(M.zero());
    nonzero[1023] = M.one();
    const polys = [_]P.CircleCoefficients{
        try P.CircleCoefficients.initBorrowed(&zeros),
        try P.CircleCoefficients.initBorrowed(&nonzero),
        try P.CircleCoefficients.initBorrowed(zeros[0..256]),
    };
    const actual = try P.evaluateManyWithTwiddles(allocator, &polys, domain, borrowed);
    defer allocator.free(actual);
    defer for (actual) |values| allocator.free(values);
    for (polys, actual) |poly, values| {
        const dense = try allocator.alloc(M, domain.size());
        defer allocator.free(dense);
        @memcpy(dense[0..poly.coeffs.len], poly.coeffs);
        @memset(dense[poly.coeffs.len..], M.zero());
        try T.evaluateBuffersWithTwiddles(&.{dense}, domain, borrowed);
        try std.testing.expectEqualDeep(dense, values);
        const single = try poly.evaluateWithTwiddles(allocator, domain, borrowed);
        defer allocator.free(single.values);
        try std.testing.expectEqualDeep(dense, single.values);
    }
    const owned = try allocator.dupe(M, &zeros);
    // This API consumes its input only on success.
    var recovered = P.interpolateOwnedValuesWithTwiddles(core.poly.circle.canonic.CanonicCoset.new(9).circleDomain(), owned, borrowed) catch |err| {
        allocator.free(owned);
        return err;
    };
    defer recovered.deinit(allocator);
    try std.testing.expect(recovered.coeffs.ptr == owned.ptr);
    const dense_coeffs = try allocator.dupe(M, &zeros);
    defer allocator.free(dense_coeffs);
    try T.interpolateIntoBufferWithTwiddles(dense_coeffs, core.poly.circle.canonic.CanonicCoset.new(9).circleDomain(), borrowed);
    try std.testing.expectEqualDeep(dense_coeffs, recovered.coeffs);
    var copied = try P.interpolateFromEvaluationWithTwiddles(allocator, try E.init(core.poly.circle.canonic.CanonicCoset.new(9).circleDomain(), &zeros), borrowed);
    defer copied.deinit(allocator);
    try std.testing.expect(copied.coeffs.ptr != zeros[0..].ptr);
    try std.testing.expectEqualDeep(dense_coeffs, copied.coeffs);
    var wrong = borrowed;
    wrong.root_coset = domain.half_coset.double();
    try std.testing.expectError(error.InvalidLogSize, P.evaluateManyWithTwiddles(allocator, polys[0..1], domain, wrong));
}
test "prover poly circle poly: exact zero shortcut matches dense transforms and preserves ownership under allocation failure" {
    try std.testing.checkAllAllocationFailures(a, lifecycle, .{});
}
