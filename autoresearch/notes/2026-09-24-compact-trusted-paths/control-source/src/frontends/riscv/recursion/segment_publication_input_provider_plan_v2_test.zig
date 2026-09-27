const std = @import("std");

const source_v2 = @import("segment_leaf_authority_v2.zig");
const subject = @import("segment_publication_input_provider_plan_v2.zig");
const fixture_support = @import("segment_public_outer_test_support.zig");

test "SegmentV2 publication provider plan is exact and remains fail closed" {
    var fixture = try fixture_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var prepared: subject.PreparedProviderPlanV2 = undefined;
    try subject.prepareInto(&prepared, &fixture.publication);
    try prepared.validateAgainst(&fixture.publication);
    try std.testing.expect(!prepared.productionReady());

    var emits: [subject.WORD_COUNT]subject.ProviderEventV2 = undefined;
    var consumes: [subject.WORD_COUNT]source_v2.VerifierInputEventV2 = undefined;
    try subject.writeEmitsInto(&prepared, &fixture.publication, &emits);
    try source_v2.writeVerifiedNativeVerifierInputEventsInto(
        &fixture.publication,
        &consumes,
    );
    try subject.requireExactConsumerParity(&emits, &consumes);

    emits[17].tuple[4] = emits[17].tuple[4].add(@import("stwo_core").fields.m31.M31.one());
    try std.testing.expectError(
        error.ProviderPlanMismatch,
        subject.requireExactConsumerParity(&emits, &consumes),
    );
    try std.testing.expect(!subject.REQUIRED_INTEGRATION.productionReady());
    try std.testing.expect(!subject.TYPED_AIR_PROVIDER_AVAILABLE);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
}
