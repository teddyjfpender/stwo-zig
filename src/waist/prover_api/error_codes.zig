//! Exact column-admission diagnostics, not an outer anyerror classifier.
const Entry = @import("stwo_core").error_codes.Entry;
const ColumnError = @import("column.zig").QuotientOpsError;
pub const ColumnFailure = struct { cause: ColumnError, entry: Entry };
pub const table = [_]Entry{
    .{ .tag = "ShapeMismatch", .code = 0x3001, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidColumnLogSize", .code = 0x3002, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidColumnLength", .code = 0x3003, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "TaskGraphRecorderIdentityExhausted", .code = 0x3101, .class = .resource_exhausted, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskGraphReservationActive", .code = 0x3102, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskGraphReservationGenerationExhausted", .code = 0x3103, .class = .resource_exhausted, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskGraphReservationStale", .code = 0x3104, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskGraphReservationStorageMismatch", .code = 0x3105, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskGraphReservationWrongRecorder", .code = 0x3106, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileComponentWorkCountImpossible", .code = 0x3107, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileContributionCountOverflow", .code = 0x3108, .class = .resource_exhausted, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfilePlannedTaskCountMismatch", .code = 0x3109, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileTaskCountOverflow", .code = 0x310a, .class = .resource_exhausted, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileUnexpectedStealCount", .code = 0x310b, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileUnsupportedScheduler", .code = 0x310c, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileComponentKindDrift", .code = 0x310d, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileComponentWorkCountMismatch", .code = 0x310e, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileComponentWorkOverflow", .code = 0x310f, .class = .resource_exhausted, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileContributionCompletionExceedsPlan", .code = 0x3110, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileContributionCompletionStateMismatch", .code = 0x3111, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileContributionRangeCoverageMismatch", .code = 0x3112, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileContributionRangeNotContiguous", .code = 0x3113, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileContributionRangeOutOfBounds", .code = 0x3114, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileContributionRoleDrift", .code = 0x3115, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileDuplicateComponentContribution", .code = 0x3116, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "TaskProfileExclusiveContributionNotExclusive", .code = 0x3117, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "OutOfMemory", .code = 0x3118, .class = .resource_exhausted, .since = "1.0.0-rc.3" },
};

pub fn fromColumn(err: ColumnError) Entry {
    return switch (err) {
        error.ShapeMismatch => table[0],
        error.InvalidColumnLogSize => table[1],
        error.InvalidColumnLength => table[2],
    };
}

pub fn recordColumnFailure(output: ?*?ColumnFailure, err: ColumnError) ColumnError {
    if (output) |sink| if (sink.* == null) {
        sink.* = .{ .cause = err, .entry = fromColumn(err) };
    };
    return err;
}

/// Only the closed task-recorder operations may project this owned union.
pub fn fromTaskProfile(err: @import("task_profile.zig").Error) Entry {
    return switch (err) {
        error.TaskGraphRecorderIdentityExhausted => table[3],
        error.TaskGraphReservationActive => table[4],
        error.TaskGraphReservationGenerationExhausted => table[5],
        error.TaskGraphReservationStale => table[6],
        error.TaskGraphReservationStorageMismatch => table[7],
        error.TaskGraphReservationWrongRecorder => table[8],
        error.TaskProfileComponentWorkCountImpossible => table[9],
        error.TaskProfileContributionCountOverflow => table[10],
        error.TaskProfilePlannedTaskCountMismatch => table[11],
        error.TaskProfileTaskCountOverflow => table[12],
        error.TaskProfileUnexpectedStealCount => table[13],
        error.TaskProfileUnsupportedScheduler => table[14],
        error.TaskProfileComponentKindDrift => table[15],
        error.TaskProfileComponentWorkCountMismatch => table[16],
        error.TaskProfileComponentWorkOverflow => table[17],
        error.TaskProfileContributionCompletionExceedsPlan => table[18],
        error.TaskProfileContributionCompletionStateMismatch => table[19],
        error.TaskProfileContributionRangeCoverageMismatch => table[20],
        error.TaskProfileContributionRangeNotContiguous => table[21],
        error.TaskProfileContributionRangeOutOfBounds => table[22],
        error.TaskProfileContributionRoleDrift => table[23],
        error.TaskProfileDuplicateComponentContribution => table[24],
        error.TaskProfileExclusiveContributionNotExclusive => table[25],
        error.OutOfMemory => table[26],
    };
}

pub fn lookup(code: u16) ?Entry {
    for (table) |entry| if (entry.code == code) return entry;
    return null;
}

test {
    _ = @import("error_codes_test.zig");
}
