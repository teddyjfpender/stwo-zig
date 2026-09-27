//! Pure guard/ownership fixtures. No CUDA API, device event, stream, proof or
//! emulation is created. Host sentinels represent metadata addresses only.
const std = @import("std");
const runtime = @import("../abi/runtime.zig");
const Context = @import("context.zig").ContextFor(struct {});
pub const behavioral_test_count = 6;

fn context(handle: *u8, first: *u8, second: *u8) Context {
    var result = Context{
        .handle = handle,
        .stream = first,
        .device = 2,
        .lane_count = 2,
        .owner_thread_id = std.Thread.getCurrentId(),
        .identity = 17,
        .dependency_capacity = 2,
        .active_stage = .trace_generation,
    };
    result.lanes[0] = first;
    result.lanes[1] = second;
    return result;
}

fn dependency(owner: *const Context) Context.Dependency {
    return .{
        .owner = @intFromPtr(owner.handle.?),
        .token = .{ .context_identity = owner.identity, .generation = 3, .slot = 0, .producer_lane = 1 },
    };
}

fn admitDependencyMetadata(owner: *Context) void {
    owner.dependencies[0] = .{ .generation = 3, .producer_lane = 1, .active = true };
    owner.live_dependencies = 1;
}

test "CUDA lane ownership: exact ABI layouts and bounded construction options" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(runtime.ContextOptions));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(runtime.DependencyToken));
    try (runtime.ContextOptions{}).validate();
    try (runtime.ContextOptions{ .device_ordinal = 2, .lane_count = 4, .dependency_capacity = 64 }).validate();
    try std.testing.expectError(error.InvalidState, (runtime.ContextOptions{ .version = 0 }).validate());
    for ([_]u32{ 0, 5 }) |count| try std.testing.expectError(error.InvalidExecutionLaneCount, (runtime.ContextOptions{ .lane_count = count }).validate());
    try std.testing.expectError(error.InvalidExecutionLaneCount, (runtime.ContextOptions{ .dependency_capacity = 65 }).validate());
    const outcome = Context.openOptions(.{});
    switch (outcome) {
        .failed => |failure| {
            try std.testing.expect(failure.cause == error.InvalidState);
            try std.testing.expect(failure.teardown == null);
        },
        .ready, .released => return error.TestUnexpectedResult,
    }
    // Additional physical ownership does not widen the compiled schedule.
    try std.testing.expectEqual(@as(u8, 0), @import("execution_plan.zig").max_lane_streams);
}

test "CUDA lane ownership: borrowed lanes bind exact owner identity index and stream" {
    var handle: u8 = 0;
    var streams = [_]u8{ 0, 0 };
    var owner = context(&handle, &streams[0], &streams[1]);
    const selected = try owner.lane(1);
    try owner.validateLane(selected);
    try std.testing.expect(!owner.synchronized);
    for (0..4) |field| {
        var changed = selected;
        switch (field) {
            0 => changed.owner += 1,
            1 => changed.context_identity += 1,
            2 => changed.index = 0,
            3 => changed.stream = &streams[0],
            else => unreachable,
        }
        try std.testing.expectError(error.ContextMismatch, owner.validateLane(changed));
    }
    try std.testing.expectError(error.InvalidExecutionLaneCount, owner.lane(2));
    var changed = selected;
    changed.index = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidExecutionLaneCount, owner.validateLane(changed));
}

test "CUDA lane ownership: thread capture closed and partial teardown guards" {
    var handle: u8 = 0;
    var streams = [_]u8{ 0, 0 };
    var owner = context(&handle, &streams[0], &streams[1]);
    const selected = try owner.lane(0);
    owner.owner_thread_id = 0;
    try std.testing.expectError(error.ThreadOwnershipViolation, owner.validateLane(selected));
    owner.owner_thread_id = std.Thread.getCurrentId() ^ 1;
    try std.testing.expectError(error.ThreadOwnershipViolation, owner.validateLane(selected));
    owner.owner_thread_id = std.Thread.getCurrentId();
    owner.capture_active = true;
    try std.testing.expectError(error.InvalidState, owner.lane(0));
    owner.capture_active = false;
    owner.teardown_pending = true;
    try std.testing.expectError(error.InvalidState, owner.validateLane(selected));
    owner.teardown_pending = false;
    owner.handle = null;
    try std.testing.expectError(error.ContextClosed, owner.validateLane(selected));
}

test "CUDA lane ownership: dependency membership rejects every altered token field" {
    var handle: u8 = 0;
    var streams = [_]u8{ 0, 0 };
    var owner = context(&handle, &streams[0], &streams[1]);
    admitDependencyMetadata(&owner);
    const original = dependency(&owner);
    try owner.validateDependency(original);
    for (0..5) |field| {
        var changed = original;
        switch (field) {
            0 => changed.owner += 1,
            1 => changed.token.context_identity += 1,
            2 => changed.token.generation += 1,
            3 => changed.token.slot = 1,
            4 => changed.token.producer_lane = 0,
            else => unreachable,
        }
        try std.testing.expectError(error.ContextMismatch, owner.validateDependency(changed));
    }
    owner.capture_active = true;
    try std.testing.expectError(error.InvalidState, owner.validateDependency(original));
}

test "CUDA lane ownership: released slots new generations and reused context addresses reject stale tokens" {
    var handle: u8 = 0;
    var streams = [_]u8{ 0, 0 };
    var owner = context(&handle, &streams[0], &streams[1]);
    admitDependencyMetadata(&owner);
    const original = dependency(&owner);
    // Only metadata states are exercised. No simulated event operation runs.
    owner.dependencies[0].active = false;
    try std.testing.expectError(error.ContextMismatch, owner.validateDependency(original));
    owner.dependencies[0].active = true;
    owner.dependencies[0].generation = 4;
    try std.testing.expectError(error.ContextMismatch, owner.validateDependency(original));
    var current = original;
    current.token.generation = 4;
    try owner.validateDependency(current);
    owner.identity += 1;
    try std.testing.expectError(error.ContextMismatch, owner.validateDependency(current));
}

test "CUDA lane ownership: missing event backend state and exhausted generation remain failure atomic" {
    var handle: u8 = 0;
    var streams = [_]u8{ 0, 0 };
    var owner = context(&handle, &streams[0], &streams[1]);
    const selected = try owner.lane(1);
    const snapshot = owner.dependencies;
    try std.testing.expectError(error.InvalidState, owner.recordDependency(selected, 0));
    try std.testing.expectEqualDeep(snapshot, owner.dependencies);
    try std.testing.expectEqual(@as(usize, 0), owner.live_dependencies);
    owner.dependencies[0].generation = std.math.maxInt(u64);
    try std.testing.expectError(error.SizeOverflow, owner.recordDependency(selected, 0));
    owner.dependencies[0].generation = 0;
    owner.active_stage = null;
    try std.testing.expectError(error.StageNotActive, owner.recordDependency(selected, 0));
    owner.active_stage = .trace_generation;
    admitDependencyMetadata(&owner);
    var original = dependency(&owner);
    const before = original;
    try std.testing.expectError(error.InvalidState, owner.recordDependency(selected, 0));
    try std.testing.expectError(error.InvalidState, owner.waitDependency(selected, original));
    try std.testing.expectError(error.InvalidState, owner.releaseDependency(&original));
    try std.testing.expectEqualDeep(before, original);
    try std.testing.expect(owner.dependencies[0].active);
    try std.testing.expectEqual(@as(usize, 1), owner.live_dependencies);
}
