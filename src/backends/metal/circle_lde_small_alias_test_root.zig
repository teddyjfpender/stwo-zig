//! Device-free regression for terminal Ethereum's adopted small-column arena.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const Backend = @import("commit_backend.zig").MetalCommitBackend;
const M31 = core.fields.m31.M31;
const canonic = core.poly.circle.canonic.CanonicCoset;

test "metal small LDE adopted source alias preserves coefficients and evaluations" {
    const allocator = std.testing.allocator;
    for (1..3) |log| {
        const domain = canonic.new(@intCast(log)).circleDomain();
        const extended_domain = canonic.new(@intCast(log + 1)).circleDomain();
        var base_tree = try prover.poly.twiddles.precomputeM31(allocator, domain.half_coset);
        defer prover.poly.twiddles.deinitM31(allocator, &base_tree);
        var extended_tree = try prover.poly.twiddles.precomputeM31(allocator, extended_domain.half_coset);
        defer prover.poly.twiddles.deinitM31(allocator, &extended_tree);
        var source: [4]M31 = undefined;
        var adopted: [4]M31 = undefined;
        var reference_base: [4]M31 = undefined;
        var reference_extended: [8]M31 = undefined;
        var actual_extended: [8]M31 = undefined;
        for (source[0..domain.size()], 0..) |*value, row| value.* = M31.fromCanonical(@intCast(17 + row * row * 31));
        @memcpy(adopted[0..domain.size()], source[0..domain.size()]);
        const reference = try Backend.interpolateAndEvaluateCircleBuffers(allocator, &.{source[0..domain.size()]}, &.{reference_base[0..domain.size()]}, &.{reference_extended[0..extended_domain.size()]}, reference_extended[0..extended_domain.size()], 0, extended_domain.size(), domain, asConst(base_tree), extended_domain, asConst(extended_tree));
        const actual = try Backend.interpolateAndEvaluateCircleBuffers(allocator, &.{adopted[0..domain.size()]}, &.{adopted[0..domain.size()]}, &.{actual_extended[0..extended_domain.size()]}, actual_extended[0..extended_domain.size()], 0, extended_domain.size(), domain, asConst(base_tree), extended_domain, asConst(extended_tree));
        try std.testing.expectEqualDeep(reference, actual);
        try std.testing.expectEqualSlices(M31, reference_base[0..domain.size()], adopted[0..domain.size()]);
        try std.testing.expectEqualSlices(M31, reference_extended[0..extended_domain.size()], actual_extended[0..extended_domain.size()]);
    }
}

test "metal small LDE rejects partial source overlap and invalid shapes before writes" {
    const allocator = std.testing.allocator;
    const domain = canonic.new(2).circleDomain();
    const extended_domain = canonic.new(3).circleDomain();
    var base_tree = try prover.poly.twiddles.precomputeM31(allocator, domain.half_coset);
    defer prover.poly.twiddles.deinitM31(allocator, &base_tree);
    var extended_tree = try prover.poly.twiddles.precomputeM31(allocator, extended_domain.half_coset);
    defer prover.poly.twiddles.deinitM31(allocator, &extended_tree);
    var source = [_]M31{M31.fromCanonical(19)} ** 5;
    const before = source;
    var extended = [_]M31{M31.fromCanonical(29)} ** 8;
    try std.testing.expectError(error.InvalidColumns, Backend.interpolateAndEvaluateCircleBuffers(allocator, &.{source[0..4]}, &.{source[1..5]}, &.{&extended}, &extended, 0, 8, domain, asConst(base_tree), extended_domain, asConst(extended_tree)));
    try std.testing.expectEqualSlices(M31, &before, &source);
    try std.testing.expectError(error.InvalidColumns, Backend.interpolateAndEvaluateCircleBuffers(allocator, &.{source[0..3]}, &.{source[0..4]}, &.{&extended}, &extended, 0, 8, domain, asConst(base_tree), extended_domain, asConst(extended_tree)));
    try std.testing.expectEqualSlices(M31, &before, &source);
}

fn asConst(tree: prover.poly.twiddles.TwiddleTree([]M31)) prover.poly.twiddles.TwiddleTree([]const M31) {
    return .init(tree.root_coset, tree.twiddles, tree.itwiddles);
}
