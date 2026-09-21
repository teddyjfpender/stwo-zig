//! Independent retained-coefficient/committed-LDE parity and admission tests.
const std = @import("std");
const core_constraints = @import("stwo_core").constraints;
const core_utils = @import("stwo_core").utils;
const M31 = @import("stwo_core").fields.m31.M31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const owner = @import("prepared_evaluation_owner.zig");
const ExtensionCounts = owner.ExtensionCounts;
const ExtensionSource = owner.ExtensionSource;
const RetainedLdeOwner = owner.RetainedLdeOwner;
const extensionSource = owner.extensionSource;
const retainedLdeResidentBytes = owner.retainedLdeResidentBytes;
const residentBytes = owner.residentBytes;

/// Lightweight parity exercise reused by the filtered candidate-leaf proof
/// gate.  It compares the exact quotient-domain composition inputs produced
/// from retained coefficients (`.always`) and from only the committed LDE
/// (`.never`).
pub fn exerciseRetainedLdeParityForTest(allocator: std.mem.Allocator) !void {
    const trace_log_size: u32 = 3;
    const committed_log_size: u32 = 4;
    const evaluation_log_size: u32 = 5;
    const committed_size: usize = @as(usize, 1) << @intCast(committed_log_size);
    const evaluation_size: usize = @as(usize, 1) << @intCast(evaluation_log_size);

    var coefficient_values: [8]M31 = undefined;
    for (&coefficient_values, 0..) |*value, index| {
        value.* = M31.fromU64(@intCast(11 + index * 37));
    }
    const coefficients = try prover_poly.CircleCoefficients.initBorrowed(
        &coefficient_values,
    );
    const committed_values = try allocator.alloc(M31, committed_size);
    defer allocator.free(committed_values);
    @memcpy(committed_values[0..coefficient_values.len], &coefficient_values);
    @memset(committed_values[coefficient_values.len..], M31.zero());
    const committed_domain = canonic.CanonicCoset.new(
        committed_log_size,
    ).circleDomain();
    var committed_twiddles = try prover_twiddles.precomputeM31(
        allocator,
        committed_domain.half_coset,
    );
    defer prover_twiddles.deinitM31(allocator, &committed_twiddles);
    var committed_buffers = [_][]M31{committed_values};
    try prover_poly.evaluateBuffersWithTwiddles(
        &committed_buffers,
        committed_domain,
        prover_twiddles.TwiddleTree([]const M31).init(
            committed_twiddles.root_coset,
            committed_twiddles.twiddles,
            committed_twiddles.itwiddles,
        ),
    );

    const retained_poly = prover_component.Poly{
        .log_size = committed_log_size,
        .values = committed_values,
        .coefficients = coefficients,
    };
    const discarded_poly = prover_component.Poly{
        .log_size = committed_log_size,
        .values = committed_values,
    };
    var retained_counts = ExtensionCounts{};
    try retained_counts.add(try extensionSource(
        retained_poly,
        trace_log_size,
        evaluation_log_size,
    ));
    var discarded_counts = ExtensionCounts{};
    try discarded_counts.add(try extensionSource(
        discarded_poly,
        trace_log_size,
        evaluation_log_size,
    ));
    try std.testing.expectEqual(@as(usize, 1), retained_counts.owned);
    try std.testing.expectEqual(@as(usize, 1), retained_counts.retained_coefficients);
    try std.testing.expectEqual(@as(usize, 1), discarded_counts.owned);
    try std.testing.expectEqual(@as(usize, 1), discarded_counts.committed_lde);

    const evaluation_domain = canonic.CanonicCoset.new(
        evaluation_log_size,
    ).circleDomain();
    var retained_owner = try RetainedLdeOwner.init(allocator, retained_counts);
    defer retained_owner.deinit();
    const retained_evaluation = try retained_owner.value(
        retained_poly,
        trace_log_size,
        evaluation_log_size,
        evaluation_size,
    );
    try retained_owner.finish(evaluation_domain);

    var discarded_owner = try RetainedLdeOwner.init(allocator, discarded_counts);
    defer discarded_owner.deinit();
    const discarded_evaluation = try discarded_owner.value(
        discarded_poly,
        trace_log_size,
        evaluation_log_size,
        evaluation_size,
    );
    try discarded_owner.finish(evaluation_domain);

    const extension_bits: u5 = @intCast(
        evaluation_log_size - trace_log_size,
    );
    var denominator_inverses: [4]M31 = undefined;
    const trace_coset = canonic.CanonicCoset.new(trace_log_size).coset();
    for (&denominator_inverses, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            trace_coset,
            evaluation_domain.at(core_utils.bitReverseIndex(
                index,
                extension_bits,
            )),
        ).inv();
    }

    var retained_fold = M31.zero();
    var discarded_fold = M31.zero();
    for (retained_evaluation, discarded_evaluation, 0..) |
        retained,
        discarded,
        row,
    | {
        try std.testing.expect(retained.eql(discarded));
        const denominator = denominator_inverses[
            row >> @intCast(trace_log_size)
        ];
        const random_power = M31.fromU64(@intCast(3 + row * 19));
        retained_fold = retained_fold.add(
            retained.mul(denominator).mul(random_power),
        );
        discarded_fold = discarded_fold.add(
            discarded.mul(denominator).mul(random_power),
        );
    }
    try std.testing.expect(retained_fold.eql(discarded_fold));

    const retained_resident = try retainedLdeResidentBytes(
        retained_counts,
        evaluation_size,
    );
    const discarded_resident = try retainedLdeResidentBytes(
        discarded_counts,
        evaluation_size,
    );
    try std.testing.expectEqual(
        try residentBytes(1, evaluation_size) + @sizeOf([]M31),
        retained_resident,
    );
    try std.testing.expectEqual(
        try residentBytes(1, evaluation_size) + 2 * @sizeOf([]M31),
        discarded_resident,
    );
}

test "prepared evaluation owner: always and never quotient composition inputs match" {
    try exerciseRetainedLdeParityForTest(std.testing.allocator);
}

test "prepared evaluation owner: retained LDE fallback is bounded and fail closed" {
    const allocator = std.testing.allocator;
    var equal_domain_values = [_]M31{M31.zero()} ** 32;
    const equal_domain = prover_component.Poly{
        .log_size = 5,
        .values = &equal_domain_values,
    };
    try std.testing.expectEqual(
        ExtensionSource.borrowed,
        try extensionSource(equal_domain, 3, 5),
    );
    var no_extensions = try RetainedLdeOwner.init(allocator, .{});
    defer no_extensions.deinit();
    const borrowed = try no_extensions.value(equal_domain, 3, 5, 32);
    try std.testing.expect(borrowed.ptr == equal_domain_values[0..].ptr);
    try no_extensions.finish(canonic.CanonicCoset.new(5).circleDomain());

    var too_narrow_values = [_]M31{M31.zero()} ** 4;
    const too_narrow = prover_component.Poly{
        .log_size = 2,
        .values = &too_narrow_values,
    };
    try std.testing.expectError(
        error.InvalidProofShape,
        extensionSource(too_narrow, 3, 5),
    );
    try std.testing.expectError(
        error.InvalidProofShape,
        RetainedLdeOwner.init(allocator, .{ .owned = 1 }),
    );
}
