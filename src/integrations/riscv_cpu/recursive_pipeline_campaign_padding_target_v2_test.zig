const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const subject = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const remint_mod = @import("recursive_common_wrapper_padding_remint_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const fixture_mod =
    @import("recursive_common_wrapper_padding_remint_v2_test.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");

const PROVIDER_ROW: usize = @intFromEnum(
    frontend.recursion.air.universal_roster.Component.poseidon2,
);

test "pre-final campaign target binds live active geometries and runtime shape" {
    var fixture = try fixture_mod.Fixture.init();
    const shape13 = try shape_mod.CampaignShapeAuthorityV2.init(
        sha(11),
        sha(12),
        13,
    );
    const value13 = try subject.CampaignPaddingTargetV2.derive(
        &shape13,
        fixture.activeSources(),
    );
    try value13.validateAgainstActive(fixture.activeSources());
    try std.testing.expectEqual(@as(u32, 16), value13.shape.padded_leaf_count);
    try std.testing.expectEqual(@as(u8, 4), value13.shape.root_height);
    try std.testing.expectEqual(
        @as(u8, 8),
        (try value13.activeLogsForRole(
            .ethereum_incremental_leaf_wrapper_v4,
        ))[PROVIDER_ROW],
    );
    try std.testing.expectEqual(
        @as(u8, 7),
        (try value13.activeLogsForRole(.canonical_empty_field_v2))[PROVIDER_ROW],
    );
    try std.testing.expectEqual(
        @as(u8, 8),
        (try value13.paddedLogs())[PROVIDER_ROW],
    );

    const shape37 = try shape_mod.CampaignShapeAuthorityV2.init(
        sha(21),
        sha(22),
        37,
    );
    const value37 = try subject.CampaignPaddingTargetV2.derive(
        &shape37,
        fixture.activeSources(),
    );
    try std.testing.expectEqual(@as(u32, 64), value37.shape.padded_leaf_count);
    try std.testing.expectEqual(@as(u8, 6), value37.shape.root_height);
    try std.testing.expect(!std.mem.eql(
        u8,
        &value13.identity_sha256,
        &value37.identity_sha256,
    ));
}

test "pre-final target rejects mutation and post-final reopen preserves target" {
    var fixture = try fixture_mod.Fixture.init();
    const shape = try shape_mod.CampaignShapeAuthorityV2.init(
        sha(31),
        sha(32),
        13,
    );
    const active = fixture.activeSources();
    const value = try subject.CampaignPaddingTargetV2.derive(&shape, active);

    var identity_mutation = value;
    identity_mutation.identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.CampaignPaddingTargetMismatch,
        identity_mutation.validateSelf(),
    );
    fixture.active_empty.valid = false;
    try std.testing.expectError(
        error.RejectedFixtureColdGeometry,
        value.validateAgainstActive(fixture.activeSources()),
    );
    fixture.active_empty.valid = true;

    fixture.remintForTarget(&value.target);
    const final = try remint_mod.FinalRemintAuthorityV2.mint(
        &value.target,
        fixture.activeSources(),
        fixture.finalSources(),
    );
    const admitted = try final_mod.CampaignFinalRemintAuthorityV2.init(
        &shape,
        &final,
    );
    const reopened = try subject.CampaignPaddingTargetV2.fromFinal(&admitted);
    try reopened.validateAgainstFinal(&admitted);
    try std.testing.expectEqualDeep(value, reopened);

    var wrong_final = admitted;
    wrong_final.binding_identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.CampaignFinalRemintMismatch,
        reopened.validateAgainstFinal(&wrong_final),
    );
}

test "pre-final campaign target has no freshness codec or geometry output" {
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(!@hasDecl(subject.CampaignPaddingTargetV2, "encode"));
    try std.testing.expect(!@hasDecl(subject.CampaignPaddingTargetV2, "decode"));
    try std.testing.expect(!@hasDecl(subject.CampaignPaddingTargetV2, "geometry"));
    try std.testing.expect(!@hasDecl(subject.CampaignPaddingTargetV2, "registry"));
}

fn sha(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index| byte.* = seed +% @as(u8, @intCast(index));
    return result;
}
