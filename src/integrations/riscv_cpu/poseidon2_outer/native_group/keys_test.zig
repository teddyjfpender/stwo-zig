const std = @import("std");
const Owner = @import("keys.zig").Owner;
const Profile = @import("../op_profile.zig").Profile;
test "R7 canonical typed group key constructors reject numerical sources and reference policy before allocation" {
    const a = std.testing.allocator;
    const profile = Profile.op_target_b4_q72_p0_fold4_v1;
    const root = @import("../pure_p2_native.zig").hashWords(&.{1});
    var base = try @import("source.zig").Stream.init(a, false, 0, 1, profile, root);
    defer base.deinit();
    try std.testing.expectError(error.NativeGroupSourceTraceRequired, Owner.fromStream(std.testing.failing_allocator, &base));
    try std.testing.expectError(error.InvalidOpPurePoseidonProfile, Owner.fromStreamWithProfile(std.testing.failing_allocator, &base, .reference_b2_q24_p0));
    var dot = try @import("../native_dot/group_source.zig").Stream.init(a, false, 0, 1, profile, root);
    defer dot.deinit();
    try std.testing.expectError(error.NativeGroupSourceTraceRequired, Owner.fromNativeDotStream(std.testing.failing_allocator, &dot));
    try std.testing.expectError(error.InvalidOpPurePoseidonProfile, Owner.fromNativeDotStreamWithProfile(std.testing.failing_allocator, &dot, .reference_b2_q24_p0));
    var key: @import("../native_dot/outer_authority.zig").Key = undefined;
    key.core.base.profile = profile;
    key.core.base.n_outputs = 8;
    try std.testing.expectError(error.FoldSourceOutputArity, Owner.canonicalFold(std.testing.failing_allocator, .{ .{ .r7 = &key }, .{ .r7 = &key } }, profile));
}
