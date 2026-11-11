const std = @import("std");
const protocol = @import("capture_protocol.zig");
const schedule = @import("capture_schedule.zig");

test "C-013 schedule closes every cell arm and phase exactly" {
    var counts = [_][2][2]usize{.{ .{ 0, 0 }, .{ 0, 0 } }} **
        schedule.cell_count;
    var iterator = schedule.Iterator{};
    var observed: usize = 0;
    while (iterator.next()) |attempt| {
        try std.testing.expectEqual(observed, attempt.ordinal);
        const phase: usize = switch (attempt.phase) {
            .warmup => 0,
            .measured => 1,
            else => return error.InvalidSchedulePhase,
        };
        counts[attempt.cell_index][phase][@intFromEnum(attempt.arm)] += 1;
        observed += 1;
    }
    try std.testing.expectEqual(schedule.attempt_count, observed);
    for (counts) |cell| {
        try std.testing.expectEqualSlices(usize, &.{ 10, 10 }, &cell[0]);
        try std.testing.expectEqualSlices(usize, &.{ 30, 30 }, &cell[1]);
    }
}

test "C-013 schedule is shape-major call-minor and round-alternating" {
    const first = try schedule.attemptAt(0);
    try std.testing.expectEqual(protocol.Shape.core_only, first.shape);
    try std.testing.expectEqual(@as(usize, 0), first.calls);
    try std.testing.expectEqual(protocol.Arm.software, first.arm);
    const warmup_reverse = try schedule.attemptAt(2);
    try std.testing.expectEqual(protocol.Arm.precompile, warmup_reverse.arm);

    const first_measured = try schedule.attemptAt(20);
    try std.testing.expectEqual(@as(?usize, 0), first_measured.round);
    try std.testing.expectEqual(protocol.Arm.software, first_measured.arm);
    const second_round = try schedule.attemptAt(40);
    try std.testing.expectEqual(@as(?usize, 1), second_round.round);
    try std.testing.expectEqual(protocol.Arm.precompile, second_round.arm);
    const next_cell = try schedule.attemptAt(schedule.attempts_per_cell);
    try std.testing.expectEqual(protocol.Shape.core_only, next_cell.shape);
    try std.testing.expectEqual(@as(usize, 1), next_cell.calls);
    const next_shape = try schedule.attemptAt(
        schedule.call_counts.len * schedule.attempts_per_cell,
    );
    try std.testing.expectEqual(
        protocol.Shape.balanced_core_and_poseidon2,
        next_shape.shape,
    );
    try schedule.validateAttempt(
        20,
        .core_only,
        0,
        .measured,
        .software,
    );
    try std.testing.expectError(
        error.CaptureScheduleAttemptMismatch,
        schedule.validateAttempt(20, .core_only, 0, .measured, .precompile),
    );
}

test "C-013 A/A schedule uses one authority under two balanced labels" {
    var counts = [_]usize{ 0, 0 };
    for (0..schedule.calibration_attempt_count) |ordinal| {
        const attempt = try schedule.calibrationAttemptAt(ordinal);
        counts[@intFromEnum(attempt.arm)] += 1;
        try std.testing.expectEqual(protocol.Phase.calibration, attempt.phase);
    }
    try std.testing.expectEqualSlices(usize, &.{ 40, 40 }, &counts);
    try std.testing.expectEqual(
        schedule.CalibrationArm.a,
        (try schedule.calibrationAttemptAt(20)).arm,
    );
    try std.testing.expectEqual(
        schedule.CalibrationArm.a_control,
        (try schedule.calibrationAttemptAt(40)).arm,
    );
    try std.testing.expectEqual(
        schedule.calibration_attempt_count + schedule.attempt_count,
        schedule.global_attempt_count,
    );
    try std.testing.expect(
        (try schedule.globalAttemptAt(0)) == .calibration,
    );
    try std.testing.expect(
        (try schedule.globalAttemptAt(schedule.calibration_attempt_count)) == .m6,
    );
}

test "C-013 schedule identity is stable and complete" {
    const identity = schedule.digest();
    const hex = std.fmt.bytesToHex(identity, .lower);
    try std.testing.expectEqualStrings(
        protocol.capture_schedule_sha256,
        &hex,
    );
}
