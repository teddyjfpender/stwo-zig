const std = @import("std");
const subject =
    @import("recursive_common_canonical_empty_wrapper_gap_v1.zig");

test "canonical-empty diagnostic shape cannot enter common proof route" {
    const gap = try subject.GapAuthorityV1.inspect();
    try std.testing.expectEqual(@as(u32, 252), gap.diagnostic.preprocessed_columns);
    try std.testing.expectEqual(@as(u32, 570), gap.universal_reference.preprocessed_columns);
    try std.testing.expectEqual(@as(u32, 1044), gap.universal_reference.main_columns);
    try std.testing.expectEqual(@as(u32, 560), gap.universal_reference.interaction_columns);
    try std.testing.expectError(
        error.CanonicalEmptyCommonGeometryUnavailable,
        gap.requireProofRoute(),
    );
}

test "canonical-empty gap rejects resealed-looking availability mutations" {
    var gap = try subject.GapAuthorityV1.inspect();
    gap.proof_route_available = true;
    try std.testing.expectError(
        error.CanonicalEmptyGapAuthorityMismatch,
        gap.validate(),
    );

    gap = try subject.GapAuthorityV1.inspect();
    gap.universal_native_trace_materializer_available = true;
    try std.testing.expectError(
        error.CanonicalEmptyGapAuthorityMismatch,
        gap.validate(),
    );

    gap = try subject.GapAuthorityV1.inspect();
    gap.universal_reference.preprocessed_columns -= 1;
    try std.testing.expectError(
        error.CanonicalEmptyGapAuthorityMismatch,
        gap.validate(),
    );
}
