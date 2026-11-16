const std = @import("std");
const codes = @import("error_codes.zig");
const column = @import("column.zig");

test "prover column diagnostics have typed literal meanings and reject foreign codes" {
    try std.testing.expect(@typeInfo(@TypeOf(codes.fromColumn)).@"fn".params[0].type.? == column.QuotientOpsError);
    const errors = [_]column.QuotientOpsError{ error.ShapeMismatch, error.InvalidColumnLogSize, error.InvalidColumnLength };
    for (errors, 0..) |err, i| {
        const entry = codes.fromColumn(err);
        try std.testing.expectEqual(@as(u16, @intCast(0x3001 + i)), entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqual(@import("stwo_core").error_codes.Class.invalid_input, entry.class);
        try std.testing.expectEqualStrings("1.0.0-rc.2", entry.since);
        try std.testing.expectEqualStrings(entry.tag, codes.lookup(entry.code).?.tag);
    }
    for ([_]u16{ 0, 0x1001, 0x2001, 0x3000, 0x3004, 0x4001, 0x5002, 65535 }) |id| try std.testing.expect(codes.lookup(id) == null);
}

test "prover column diagnostics retain exact primary failure and first cause" {
    var diagnostic: ?codes.ColumnFailure = null;
    const invalid = column.ColumnEvaluation{ .log_size = 2, .values = &.{} };
    invalid.validateRetained() catch |err| {
        try std.testing.expectEqual(error.InvalidColumnLength, codes.recordColumnFailure(&diagnostic, err));
    };
    try std.testing.expectEqual(error.InvalidColumnLength, diagnostic.?.cause);
    try std.testing.expectEqual(@as(u16, 0x3003), diagnostic.?.entry.code);
    try std.testing.expectEqual(error.ShapeMismatch, codes.recordColumnFailure(&diagnostic, error.ShapeMismatch));
    try std.testing.expectEqual(@as(u16, 0x3003), diagnostic.?.entry.code);
    try std.testing.expectEqual(error.ShapeMismatch, codes.recordColumnFailure(null, error.ShapeMismatch));
}

test "same-tag arbitrary transaction errors remain unmapped" {
    const engine = @import("engine.zig");
    var diagnostic: ?engine.ProveDiagnostic = null;
    engine.ProveDiagnostic.recordFirst(&diagnostic, .finalize, error.ShapeMismatch);
    try std.testing.expect(diagnostic.?.code == null);
    engine.ProveDiagnostic.recordFirst(&diagnostic, .fri, error.InvalidColumnLength);
    try std.testing.expectEqual(error.ShapeMismatch, diagnostic.?.cause);
    try std.testing.expect(diagnostic.?.code == null);
}

test "task lifecycle codes pin exact owned error contracts and stable meanings" {
    const task = @import("task_profile.zig");
    try std.testing.expect(@typeInfo(@TypeOf(codes.fromTaskProfile)).@"fn".params[0].type.? == task.Error);
    try std.testing.expect(@typeInfo(@typeInfo(@TypeOf(task.Recorder.reserveTaskGraphShape)).@"fn".return_type.?).error_union.error_set == task.ReservationError);
    try std.testing.expect(@typeInfo(@typeInfo(@TypeOf(task.PendingGraph.abort)).@"fn".return_type.?).error_union.error_set == task.PendingError);
    try std.testing.expect(@typeInfo(@typeInfo(@TypeOf(task.Recorder.publishTaskGraphAfterJoin)).@"fn".return_type.?).error_union.error_set == task.PublicationError);
    const errors = [_]task.Error{ error.TaskGraphRecorderIdentityExhausted, error.TaskGraphReservationActive, error.TaskGraphReservationGenerationExhausted, error.TaskGraphReservationStale, error.TaskGraphReservationStorageMismatch, error.TaskGraphReservationWrongRecorder, error.TaskProfileComponentWorkCountImpossible, error.TaskProfileContributionCountOverflow, error.TaskProfilePlannedTaskCountMismatch, error.TaskProfileTaskCountOverflow, error.TaskProfileUnexpectedStealCount, error.TaskProfileUnsupportedScheduler, error.TaskProfileComponentKindDrift, error.TaskProfileComponentWorkCountMismatch, error.TaskProfileComponentWorkOverflow, error.TaskProfileContributionCompletionExceedsPlan, error.TaskProfileContributionCompletionStateMismatch, error.TaskProfileContributionRangeCoverageMismatch, error.TaskProfileContributionRangeNotContiguous, error.TaskProfileContributionRangeOutOfBounds, error.TaskProfileContributionRoleDrift, error.TaskProfileDuplicateComponentContribution, error.TaskProfileExclusiveContributionNotExclusive, error.OutOfMemory };
    for (errors, 0..) |err, index| {
        const entry = codes.fromTaskProfile(err);
        const code: u16 = @intCast(0x3101 + index);
        try std.testing.expectEqual(code, entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqualStrings("1.0.0-rc.3", entry.since);
        const resource = switch (code) {
            0x3101, 0x3103, 0x3108, 0x310a, 0x310f, 0x3118 => true,
            else => false,
        };
        try std.testing.expectEqual(if (resource) @import("stwo_core").error_codes.Class.resource_exhausted else .invalid_input, entry.class);
        try std.testing.expectEqualStrings(entry.tag, codes.lookup(code).?.tag);
    }
    for ([_]u16{ 0x3100, 0x3119, 65535 }) |code| try std.testing.expect(codes.lookup(code) == null);
}

test "work accounting codes pin exact owned error signatures and stable meanings" {
    const work = @import("work_profile.zig");
    try std.testing.expect(@typeInfo(@TypeOf(codes.fromWorkProfile)).@"fn".params[0].type.? == work.Error);
    const errors = [_]work.Error{ error.CounterOverflow, error.InvalidCounterGroup, error.InvalidProducerCoverage, error.InvalidWorkProfile };
    for (errors, 0..) |err, i| {
        const entry = codes.fromWorkProfile(err);
        try std.testing.expectEqual(@as(u16, @intCast(0x3201 + i)), entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqualStrings("1.0.0-rc.4", entry.since);
        try std.testing.expectEqual(if (i == 0) @import("stwo_core").error_codes.Class.resource_exhausted else .invalid_input, entry.class);
        try std.testing.expectEqualStrings(entry.tag, codes.lookup(entry.code).?.tag);
    }
    for ([_]u16{ 0x3200, 0x3205, 65535 }) |code| try std.testing.expect(codes.lookup(code) == null);
}
