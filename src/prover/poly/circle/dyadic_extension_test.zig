const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const T = @import("transforms.zig");
const Poly = @import("poly.zig").CircleCoefficients;
const Tw = @import("../twiddles.zig");
const Pool = @import("../../work_pool.zig");
const a = std.testing.allocator;
fn parity(coefficient_log: u32, extra: u32, pool: ?*Pool.WorkPool) !void {
    const log = coefficient_log + extra;
    const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
    var tree = try Tw.precomputeM31(a, domain.half_coset);
    defer Tw.deinitM31(a, &tree);
    const borrowed = Tw.TwiddleTree([]const M).init(tree.root_coset, tree.twiddles, tree.itwiddles);
    const n = @as(usize, 1) << @intCast(coefficient_log);
    const reference = try a.alloc(M, domain.size());
    defer a.free(reference);
    const actual = try a.alloc(M, domain.size());
    defer a.free(actual);
    for (0..n) |i| reference[i] = M.fromCanonical(@intCast((i * 7919 + 65537) % core.fields.m31.Modulus));
    @memcpy(actual[0..n], reference[0..n]);
    @memset(reference[n..], M.zero());
    @memset(actual[n..], M.fromCanonical(12345)); // Upper slots are deliberately not zero.
    // Independent pointwise polynomial evaluator covers small edge geometries.
    if (coefficient_log <= 4) {
        const poly = try Poly.initBorrowed(reference[0..n]);
        const oracle = try a.alloc(M, domain.size());
        defer a.free(oracle);
        for (oracle, 0..) |*v, p| {
            const point = domain.at(core.utils.bitReverseIndex(p, log));
            const secure = poly.evalAtPoint(.{ .x = Q.fromBase(point.x), .y = Q.fromBase(point.y) });
            v.* = try secure.tryIntoM31();
        }
        try T.evaluateBuffersWithTwiddles(&.{reference}, domain, borrowed);
        try std.testing.expectEqualDeep(oracle, reference);
    } else try T.evaluateBuffersWithTwiddles(&.{reference}, domain, borrowed);
    try T.evaluateDyadicExtensionBuffersWithTwiddlesWithPool(&.{actual}, coefficient_log, domain, borrowed, pool);
    try std.testing.expectEqualDeep(reference, actual);
}
test "prover poly circle poly: dyadic2x4x8x zero layers match dense FFT and independent point evaluations" {
    for ([_]u32{ 0, 1, 2, 3, 4, 7, 10, 14 }) |log| for ([_]u32{ 1, 2, 3 }) |extra| try parity(log, extra, null);
    var pool: Pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3 });
    defer pool.deinit();
    try parity(12, 3, &pool);
}
test "prover poly circle poly: dyadic extension rejects alias shape and domain errors before writes" {
    var data = [_]M{M.one()} ** 32;
    const domain = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    var tree = try Tw.precomputeM31(a, domain.half_coset);
    defer Tw.deinitM31(a, &tree);
    const borrowed = Tw.TwiddleTree([]const M).init(tree.root_coset, tree.twiddles, tree.itwiddles);
    try std.testing.expectError(error.InvalidLength, T.evaluateDyadicExtensionBuffersWithTwiddlesWithPool(&.{ &data, &data }, 3, domain, borrowed, null));
    try std.testing.expectError(error.InvalidLength, T.evaluateDyadicExtensionBuffersWithTwiddlesWithPool(&.{data[0..16]}, 3, domain, borrowed, null));
    try std.testing.expectError(error.InvalidLogSize, T.evaluateDyadicExtensionBuffersWithTwiddlesWithPool(&.{&data}, 6, domain, borrowed, null));
    var partial = [_]M{M.one()} ** 48;
    try std.testing.expectError(error.InvalidLength, T.evaluateDyadicExtensionBuffersWithTwiddlesWithPool(&.{ partial[0..32], partial[16..48] }, 3, domain, borrowed, null));
    var wrong_tree = borrowed;
    wrong_tree.root_coset = domain.half_coset.double();
    try std.testing.expectError(error.InvalidLogSize, T.evaluateDyadicExtensionBuffersWithTwiddlesWithPool(&.{&data}, 3, domain, wrong_tree, null));
    for (data) |v| try std.testing.expect(v.eql(M.one()));
    for (partial) |v| try std.testing.expect(v.eql(M.one()));
}
fn columnLifecycle(allocator: std.mem.Allocator) !void {
    const CT = @import("../../pcs/columns/circle_transforms.zig");
    const Source = @import("../twiddle_source.zig").TwiddleSource;
    var source = Source.initOwned(allocator);
    defer source.deinit(allocator);
    const values = [_]M{M.one()} ** 32;
    const coefficient = try Poly.initBorrowed(&values);
    const output = try CT.extendCoefficientColumnsByGroupForBackend(struct {}, allocator, &.{coefficient}, 2, &source, null, .column_extension_fft);
    defer allocator.free(output);
    defer for (output) |c| allocator.free(c.values);
    // Borrowed original coefficient ownership never transfers to the LDE.
    for (values) |v| try std.testing.expect(v.eql(M.one()));
}
test "prover poly circle poly: dyadic PCS extension preserves owners on every allocation failure" {
    try std.testing.checkAllAllocationFailures(a, columnLifecycle, .{});
}
