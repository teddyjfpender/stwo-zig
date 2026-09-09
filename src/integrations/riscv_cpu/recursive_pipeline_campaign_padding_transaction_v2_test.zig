const std = @import("std");

const subject = @import("recursive_pipeline_campaign_padding_transaction_v2.zig");
const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const fixture_mod =
    @import("recursive_common_wrapper_padding_remint_v2_test.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");

test "pre-final target and three cold remints mint one campaign authority" {
    var fixture = try fixture_mod.Fixture.init();
    const shape = try shape_mod.CampaignShapeAuthorityV2.init(
        sha(11),
        sha(12),
        13,
    );
    const active = fixture.activeSources();
    const target = try target_mod.CampaignPaddingTargetV2.derive(
        &shape,
        active,
    );
    fixture.remintForTarget(&target.target);
    const final_sources = fixture.finalSources();
    const finalized = try subject.FinalizedCampaignV2.init(
        &target,
        active,
        final_sources,
    );
    try finalized.validate(&target, active, final_sources);
    const authority = try finalized.authority(&target);
    try authority.validateAgainstCampaign(shape.campaign_namespace_sha256);
    try target.validateAgainstFinal(&authority);
    inline for (final_sources, 0..) |source, index| {
        const role: target_mod.Role = @enumFromInt(index);
        try std.testing.expectEqualDeep(
            source.geometry_value,
            (try authority.geometryForRole(role)).*,
        );
    }
    try std.testing.expect(!@hasDecl(subject.FinalizedCampaignV2, "encode"));
    try std.testing.expect(!@hasDecl(subject.FinalizedCampaignV2, "decode"));
}

test "final transaction rejects target source and final geometry mutation" {
    var fixture = try fixture_mod.Fixture.init();
    const shape = try shape_mod.CampaignShapeAuthorityV2.init(
        sha(21),
        sha(22),
        37,
    );
    const target = try target_mod.CampaignPaddingTargetV2.derive(
        &shape,
        fixture.activeSources(),
    );
    fixture.remintForTarget(&target.target);
    var finalized = try subject.FinalizedCampaignV2.init(
        &target,
        fixture.activeSources(),
        fixture.finalSources(),
    );

    var wrong_target = target;
    wrong_target.identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.CampaignPaddingTargetMismatch,
        finalized.validateSelf(&wrong_target),
    );
    fixture.final_common.valid = false;
    try std.testing.expectError(
        error.RejectedFixtureColdGeometry,
        finalized.validate(
            &target,
            fixture.activeSources(),
            fixture.finalSources(),
        ),
    );
    fixture.final_common.valid = true;
    fixture.final_empty.target_bound = false;
    try std.testing.expectError(
        error.RejectedFixturePaddingTarget,
        finalized.validate(
            &target,
            fixture.activeSources(),
            fixture.finalSources(),
        ),
    );
    fixture.final_empty.target_bound = true;
    finalized.identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.CampaignPaddingTransactionMismatch,
        finalized.validateSelf(&target),
    );
}

fn sha(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index| byte.* = seed +% @as(u8, @intCast(index));
    return result;
}
