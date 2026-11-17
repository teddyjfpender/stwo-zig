//! Codes belong to the arena-plan error origin, not arbitrary error names.
const std = @import("std");
const backend = @import("mod.zig");
const core = @import("stwo_core");

test "backend arena diagnostics pin typed append-only meanings and foreign refusal" {
    const C = backend.error_codes;
    const function = @typeInfo(@TypeOf(C.fromArena)).@"fn";
    try std.testing.expect(function.params[0].type.? == (backend.arena_plan.Error || std.mem.Allocator.Error));
    try std.testing.expect(function.return_type.? == core.error_codes.Entry);
    const errors = [_]C.ArenaPlanError{ error.EmptySchedule, error.DuplicateLogicalId, error.UnsortedBindings, error.InvalidAlignment, error.InvalidTick, error.InvalidUseOrder, error.SizeOverflow, error.BudgetExceeded, error.AliasOverlap, error.UnknownBinding, error.BindingOutOfBounds, error.NarrowAddressOverflow, error.OutOfMemory };
    try std.testing.expectEqual(@as(usize, 41), C.table.len);
    for (errors, 0..) |err, index| {
        const entry = C.fromArena(err);
        try std.testing.expectEqual(@as(u16, @intCast(0x2001 + index)), entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqualStrings("1.0.0-rc.2", entry.since);
        try std.testing.expectEqual(if (err == error.BudgetExceeded or err == error.OutOfMemory) core.error_codes.Class.resource_exhausted else .invalid_input, entry.class);
        try std.testing.expectEqualStrings(entry.tag, C.lookup(entry.code).?.tag);
    }
    for ([_]u16{ 0, 0x1001, 0x2000, 0x200e, 0x4001, 0x5002, 65535 }) |code| try std.testing.expect(C.lookup(code) == null);
}

fn build(allocator: std.mem.Allocator) !void {
    const buffers = [_]backend.arena_plan.LogicalBuffer{.{ .id = 7, .size_bytes = 64, .alignment = 16, .live_ranges = &.{.{ .first = 0, .last = 1 }} }};
    var plan = try backend.arena_plan.build(allocator, &buffers, 16 * 1024);
    defer plan.deinit();
    try plan.validate(16 * 1024);
    try std.testing.expectEqual(@as(u64, 64), (try plan.binding(7)).size_bytes);
}

test "backend coded arena refusals retain primary errors and allocation cleanup" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, build, .{});
    try std.testing.expectError(error.EmptySchedule, backend.arena_plan.build(std.testing.allocator, &.{}, 0));
    const buffers = [_]backend.arena_plan.LogicalBuffer{.{ .id = 7, .size_bytes = 64, .alignment = 16, .live_ranges = &.{.{ .first = 0, .last = 1 }} }};
    try std.testing.expectError(error.BudgetExceeded, backend.arena_plan.build(std.testing.allocator, &buffers, 16 * 1024 - 1));
    var failure = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, backend.arena_plan.build(failure.allocator(), &buffers, 16 * 1024));
    try std.testing.expectEqual(failure.allocated_bytes, failure.freed_bytes);
}

test "backend program diagnostics pin exact program and native AIR origins" {
    const C = backend.error_codes;
    try std.testing.expect(@typeInfo(@TypeOf(C.fromProofProgram)).@"fn".params[0].type.? == backend.proof_program.Error);
    try std.testing.expect(@typeInfo(@TypeOf(C.fromNativeAir)).@"fn".params[0].type.? == @import("proof_program_native_air.zig").Error);
    const program_errors = [_]backend.proof_program.Error{ error.DuplicateBuffer, error.DuplicateColumn, error.EmptyCommitmentSet, error.EmptyConstraintSet, error.EmptyExecutionGraph, error.EmptyIdentity, error.EmptyTrace, error.InvalidBuffer, error.InvalidCommitment, error.InvalidConstraint, error.InvalidDependency, error.InvalidFriSchedule, error.InvalidNode, error.InvalidNativeAir, error.InvalidQuotientSchedule, error.InvalidTranscript };
    const native_errors = [_]@import("proof_program_native_air.zig").Error{ error.EmptyIdentity, error.GeometryOverflow, error.InvalidGeometry, error.InvalidIngress, error.InvalidSampling, error.UnsupportedVersion };
    inline for (.{ program_errors, native_errors }, .{ @as(u16, 0x2201), @as(u16, 0x2301) }) |errors, first| {
        for (errors, 0..) |err, index| {
            const entry = if (first == 0x2201) C.fromProofProgram(err) else C.fromNativeAir(err);
            try std.testing.expectEqual(first + @as(u16, @intCast(index)), entry.code);
            try std.testing.expectEqualStrings(@errorName(err), entry.tag);
            try std.testing.expectEqualStrings("1.0.0-rc.3", entry.since);
            try std.testing.expectEqual(core.error_codes.Class.invalid_input, entry.class);
            try std.testing.expectEqualStrings(entry.tag, C.lookup(entry.code).?.tag);
        }
    }
    for ([_]u16{ 0x2200, 0x2211, 0x2300, 0x2307, 65535 }) |code| try std.testing.expect(C.lookup(code) == null);
}

test "recovery codes pin singleton origins and unchanged legacy error contracts" {
    const R = backend.recovery;
    const C = backend.error_codes;
    try std.testing.expect(@typeInfo(@TypeOf(C.fromRecovery)).@"fn".params[0].type.? == R.RecoveryError);
    const errors = [_]R.RecoveryError{ error.DuplicateRecipe, error.MissingRecipe, error.MissingSpillEntry, error.SpillNotMaterialized, error.SpillCorrupted, error.BindingSizeMismatch };
    for (errors, 0..) |cause, i| {
        const entry = C.fromRecovery(cause);
        try std.testing.expectEqual(@as(u16, @intCast(0x2401 + i)), entry.code);
        try std.testing.expectEqualStrings(@errorName(cause), entry.tag);
        try std.testing.expectEqualStrings("1.0.0-rc.4", entry.since);
        try std.testing.expectEqual(core.error_codes.Class.invalid_input, entry.class);
    }
    const WriteError = @typeInfo(@typeInfo(@TypeOf(std.fs.File.pwriteAll)).@"fn".return_type.?).error_union.error_set;
    const ReadError = @typeInfo(@typeInfo(@TypeOf(std.fs.File.preadAll)).@"fn".return_type.?).error_union.error_set;
    try std.testing.expect(resolvedErrorSet(@TypeOf(R.FileSpillStore.spill)) == (WriteError || error{ MissingSpillEntry, BindingSizeMismatch }));
    try std.testing.expect(resolvedErrorSet(@TypeOf(R.FileSpillStore.restore)) == (ReadError || error{ MissingSpillEntry, SpillNotMaterialized, BindingSizeMismatch, EndOfStream, SpillCorrupted }));
    try std.testing.expect(resolvedErrorSet(@TypeOf(R.RecipeRegistry.init)) == (std.mem.Allocator.Error || error{DuplicateRecipe}));
    try std.testing.expect(resolvedErrorSet(@TypeOf(R.RecoveryEngine.validatePlan)) == error{ MissingSpillEntry, MissingRecipe });
    for ([_]u16{ 0x2400, 0x2407, 65535 }) |code| try std.testing.expect(C.lookup(code) == null);
}

// Inferred sets are deferred function-specific types; resolve their members
// before comparing the exact public error contract with a concrete union.
fn resolvedErrorSet(comptime Function: type) type {
    const E = @typeInfo(@typeInfo(Function).@"fn".return_type.?).error_union.error_set;
    return @Type(.{ .error_set = @typeInfo(E).error_set.? });
}
