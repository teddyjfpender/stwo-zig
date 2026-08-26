//! Focused adversarial checks for the compact profile clock authority.

const std = @import("std");

pub fn rejectGapOrderAndCountForgery(comptime Trace: type) !void {
    var subject = Trace.init(std.testing.allocator);
    defer subject.deinit();

    try std.testing.expect(subject.expectsNextCoreRetirement(1));
    try std.testing.expect(!subject.expectsNextCoreRetirement(2));
    try std.testing.expectError(
        error.InstructionClockMismatch,
        subject.prepareRecordedExternalRetirement(2, 0, 0, 0),
    );
    try std.testing.expectError(
        error.ProfileClockCountMismatch,
        subject.prepareRecordedExternalRetirement(1, 0, 1, 0),
    );

    const first = try subject.prepareRecordedExternalRetirement(1, 0, 0, 0);
    try std.testing.expect(subject.externalRetirementTokenIsCurrent(first, 0, 0));
    try std.testing.expect(!subject.externalRetirementTokenIsCurrent(first, 1, 0));
    try std.testing.expect(Trace.externalRetirementCommitIsValid(
        first,
        1,
        1,
        1,
        1,
    ));
    try std.testing.expect(!Trace.externalRetirementCommitIsValid(
        first,
        2,
        1,
        1,
        1,
    ));
    try std.testing.expect(!Trace.externalRetirementCommitIsValid(
        first,
        1,
        1,
        2,
        1,
    ));
    subject.commitRecordedExternalRetirement(first);
    try std.testing.expect(!subject.externalRetirementTokenIsCurrent(first, 0, 0));

    try std.testing.expectEqual(@as(usize, 1), subject.recordedExternalSteps());
    try std.testing.expect(subject.expectsNextCoreRetirement(2));
    try std.testing.expectError(
        error.InstructionClockMismatch,
        subject.prepareRecordedExternalRetirement(1, 0, 1, 1),
    );
    try std.testing.expectError(
        error.InstructionClockMismatch,
        subject.prepareRecordedExternalRetirement(3, 0, 1, 1),
    );
    try std.testing.expectError(
        error.ProfileClockCountMismatch,
        subject.prepareRecordedExternalRetirement(2, 1, 1, 1),
    );
}

pub fn carryExactContinuationOrigin(comptime Trace: type) !void {
    var cumulative = Trace.init(std.testing.allocator);
    defer cumulative.deinit();
    const first = try cumulative.prepareRecordedExternalRetirement(1, 0, 0, 0);
    cumulative.commitRecordedExternalRetirement(first);

    const resumed = try cumulative.prepareRecordedExternalRetirement(2, 1, 0, 0);
    cumulative.commitRecordedExternalRetirement(resumed);
    try std.testing.expect(cumulative.expectsNextCoreRetirement(3));

    var extracted = Trace.init(std.testing.allocator);
    defer extracted.deinit();
    try extracted.bindExtractedClockRange(1, 2, 1);
    try extracted.validateClockRange(1, 2, 1);
    try std.testing.expect(extracted.expectsNextCoreRetirement(3));
    try std.testing.expectError(
        error.ProfileClockAuthorityMismatch,
        extracted.bindExtractedClockRange(1, 3, 1),
    );
    try std.testing.expectError(
        error.ProfileClockAuthorityMismatch,
        extracted.validateClockRange(0, 2, 1),
    );
}
