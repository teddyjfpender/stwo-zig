const std = @import("std");
const schedule = @import("action_schedule.zig");

test "empty action schedule is canonical for a non-empty segment" {
    try schedule.validate(40, 80, &.{});
    const first = try schedule.digest(40, 80, &.{});
    const second = try schedule.digest(40, 80, &.{});
    const expected = [_]u8{
        0xc7, 0x89, 0xaa, 0x2f, 0x99, 0x3e, 0x49, 0xd5,
        0x1f, 0xe7, 0x41, 0x03, 0x06, 0x81, 0x99, 0xd4,
        0x56, 0x4e, 0x0c, 0x6c, 0x7a, 0x96, 0xb1, 0x46,
        0xba, 0x40, 0x32, 0xa5, 0xe6, 0x9e, 0x62, 0xf8,
    };
    try std.testing.expectEqualSlices(u8, &expected, &first);
    try std.testing.expectEqualSlices(u8, &first, &second);
}

test "action schedule rejects invalid ranges ordering and bounds" {
    try std.testing.expectError(
        error.InvalidSegmentRange,
        schedule.validate(80, 40, &.{}),
    );
    try std.testing.expectError(
        error.InvalidSegmentRange,
        schedule.validate(40, 40, &.{}),
    );
    try std.testing.expectError(
        error.NonIncreasingActionTime,
        schedule.validate(40, 80, &.{
            .{ .mcycle = 60, .pressed = 0x01 },
            .{ .mcycle = 50, .pressed = 0x02 },
        }),
    );
    try std.testing.expectError(
        error.NonIncreasingActionTime,
        schedule.validate(40, 80, &.{
            .{ .mcycle = 60, .pressed = 0x01 },
            .{ .mcycle = 60, .pressed = 0x02 },
        }),
    );
    try std.testing.expectError(
        error.ActionOutOfSegment,
        schedule.validate(40, 80, &.{
            .{ .mcycle = 39, .pressed = 0x01 },
        }),
    );
    try std.testing.expectError(
        error.ActionOutOfSegment,
        schedule.validate(40, 80, &.{
            .{ .mcycle = 80, .pressed = 0x01 },
        }),
    );
}

test "digest binds segment count time and pressed mask" {
    const actions = [_]schedule.Action{
        .{ .mcycle = 40, .pressed = 0x01 },
        .{ .mcycle = 61, .pressed = 0x82 },
    };
    const baseline = try schedule.digest(40, 80, &actions);

    const moved_segment_start = try schedule.digest(39, 80, &actions);
    try expectDifferent(baseline, moved_segment_start);
    const moved_segment_end = try schedule.digest(40, 81, &actions);
    try expectDifferent(baseline, moved_segment_end);
    const shorter = try schedule.digest(40, 80, actions[0..1]);
    try expectDifferent(baseline, shorter);

    var time_mutation = actions;
    time_mutation[1].mcycle ^= 1;
    const moved_time = try schedule.digest(40, 80, &time_mutation);
    try expectDifferent(baseline, moved_time);

    var mask_mutation = actions;
    mask_mutation[1].pressed ^= 1;
    const moved_mask = try schedule.digest(40, 80, &mask_mutation);
    try expectDifferent(baseline, moved_mask);
}

fn expectDifferent(left: schedule.Digest, right: schedule.Digest) !void {
    try std.testing.expect(!std.mem.eql(u8, &left, &right));
}
