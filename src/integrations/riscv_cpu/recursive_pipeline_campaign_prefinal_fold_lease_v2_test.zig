const std = @import("std");

const subject = @import("recursive_pipeline_campaign_prefinal_fold_lease_v2.zig");
const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const fixture_mod =
    @import("recursive_common_wrapper_padding_remint_v2_test.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");

fn Lease(comptime role: subject.Role) type {
    return struct {
        pub const ROLE = role;

        padding_target: *const subject.Authority,
        geometry: *const subject.Geometry,

        pub fn validateForPaddingTarget(
            self: *const @This(),
            target: *const subject.Authority,
        ) !void {
            if (self.padding_target != target or self.geometry.role != role)
                return error.FixturePreFinalLeaseMismatch;
            try target.validateRemintedGeometry(role, self.geometry);
        }

        pub fn preFinalFoldProjection(
            self: *const @This(),
            target: *const subject.Authority,
        ) !subject.ProjectionV2 {
            try self.validateForPaddingTarget(target);
            return error.FixtureProjectionIntentionallyUnavailable;
        }
    };
}

const RealLease = Lease(.ethereum_incremental_leaf_wrapper_v4);
const EmptyLease = Lease(.canonical_empty_field_v2);
const CommonLease = Lease(.common_fold_field_v2);
const Tagged = subject.TypedCampaignPreFinalFoldLeaseV2(
    RealLease,
    EmptyLease,
    CommonLease,
);

test "typed pre-final union preserves nominal roles and fails without cold projection" {
    var fixture = try fixture_mod.Fixture.init();
    const shape = try shape_mod.CampaignShapeAuthorityV2.init(
        sha(1),
        sha(2),
        13,
    );
    const target = try target_mod.CampaignPaddingTargetV2.derive(
        &shape,
        fixture.activeSources(),
    );
    fixture.remintForTarget(&target.target);
    const real = RealLease{
        .padding_target = &target,
        .geometry = &fixture.final_real.geometry_value,
    };
    const empty = EmptyLease{
        .padding_target = &target,
        .geometry = &fixture.final_empty.geometry_value,
    };
    const common = CommonLease{
        .padding_target = &target,
        .geometry = &fixture.final_common.geometry_value,
    };
    const values = [_]Tagged{
        .{ .padding_target = &target, .payload = .{
            .ethereum_incremental_leaf_wrapper_v4 = &real,
        } },
        .{ .padding_target = &target, .payload = .{
            .canonical_empty_field_v2 = &empty,
        } },
        .{ .padding_target = &target, .payload = .{
            .common_fold_field_v2 = &common,
        } },
    };
    for (values, std.enums.values(subject.Role)) |value, role| {
        try std.testing.expectEqual(role, value.role());
        try std.testing.expectError(
            error.FixtureProjectionIntentionallyUnavailable,
            value.preFinalFoldProjection(&target),
        );
    }
}

test "pre-final union rejects target pointer and role geometry mutation" {
    var fixture = try fixture_mod.Fixture.init();
    const shape = try shape_mod.CampaignShapeAuthorityV2.init(
        sha(11),
        sha(12),
        37,
    );
    const target = try target_mod.CampaignPaddingTargetV2.derive(
        &shape,
        fixture.activeSources(),
    );
    fixture.remintForTarget(&target.target);
    const empty = EmptyLease{
        .padding_target = &target,
        .geometry = &fixture.final_empty.geometry_value,
    };
    const tagged = Tagged{
        .padding_target = &target,
        .payload = .{ .canonical_empty_field_v2 = &empty },
    };

    var copied_target = target;
    try std.testing.expectError(
        error.CampaignPreFinalFoldLeaseAuthorityMismatch,
        tagged.validateAgainstPaddingTarget(&copied_target),
    );
    var wrong_empty = empty;
    wrong_empty.geometry = &fixture.final_real.geometry_value;
    try std.testing.expectError(
        error.FixturePreFinalLeaseMismatch,
        Tagged.fromEmpty(&target, &wrong_empty),
    );
    try std.testing.expect(!@hasDecl(Tagged, "encode"));
    try std.testing.expect(!@hasDecl(Tagged, "decode"));
}

fn sha(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index| byte.* = seed +% @as(u8, @intCast(index));
    return result;
}
