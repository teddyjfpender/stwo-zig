//! Pure independently expected metadata / failed-owner guards. No CUDA API,
//! emulated runtime, device stream/event, successful Session or proof is made.
const std = @import("std");
const SessionModule = @import("session.zig");
const NoApi = struct {};
const Session = SessionModule.SessionFor(NoApi, NoApi);
const Context = @import("context.zig").ContextFor(NoApi);
const Process = @import("process_runtime.zig").ProcessOwnedRuntimeFor(Session);
const Types = @import("../abi/types.zig");
pub const behavioral_test_count = 7;

fn selection() Session.Selection {
    return .{ .device_ordinal = 2, .device_uuid = [_]u8{7} ** 16 };
}
fn observed() Types.PlatformSnapshot {
    return .{ .uuid = [_]u8{7} ** 16, .driver_version = 1, .runtime_version = 1, .toolkit_version = 1, .device_ordinal = 2, .total_global_memory = 1, .multiprocessor_count = 1, .warp_size = 32, .max_threads_per_block = 1024 };
}
fn device() Types.DeviceSnapshot {
    return .{ .count = 3, .current = 2, .sm_major = 8, .sm_minor = 9 };
}
fn emptyOpening() Session.OpeningOwner {
    return .{ .context = .released, .owner_thread_id = std.Thread.getCurrentId(), .selected = selection() };
}

// Opaque addresses below are negative custody metadata only. The specialization
// has NO native APIs: cleanup cannot succeed while any address remains owned.
fn retainedOpening(handle: *u8) Session.OpeningOwner {
    var result = emptyOpening();
    result.context = .{ .failed = .{ .cause = error.OutOfMemory, .teardown = Context{ .handle = @ptrCast(handle), .stream = undefined, .device = undefined, .lane_count = 0, .owner_thread_id = std.Thread.getCurrentId(), .teardown_pending = true } } };
    return result;
}

test "CUDA selected session: expected ordinal UUID and architectures are mandatory" {
    try selection().validate(&.{89});
    var changed = selection();
    changed.device_ordinal = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidDeviceOrdinal, changed.validate(&.{89}));
    changed = selection();
    changed.device_uuid = [_]u8{0} ** 16;
    try std.testing.expectError(error.InvalidDeviceOrdinal, changed.validate(&.{89}));
    try std.testing.expectError(error.DeviceArchitectureMismatch, selection().validate(&.{}));
}

test "CUDA selected session: independent observed ordinal UUID SM and platform match exactly" {
    try selection().requireObserved(&.{89}, device(), observed());
    var d = device();
    d.count = 0;
    try std.testing.expectError(error.DeviceUnavailable, selection().requireObserved(&.{89}, d, observed()));
    d = device();
    d.current = 1;
    try std.testing.expectError(error.InvalidDeviceOrdinal, selection().requireObserved(&.{89}, d, observed()));
    d = device();
    d.sm_minor = 10;
    try std.testing.expectError(error.InvalidDeviceArchitecture, selection().requireObserved(&.{89}, d, observed()));
    try std.testing.expectError(error.DeviceArchitectureMismatch, selection().requireObserved(&.{90}, device(), observed()));
    var p = observed();
    p.uuid[0] ^= 1;
    try std.testing.expectError(error.InvalidDeviceOrdinal, selection().requireObserved(&.{89}, device(), p));
    p = observed();
    p.device_ordinal = 1;
    try std.testing.expectError(error.InvalidDeviceOrdinal, selection().requireObserved(&.{89}, device(), p));
    p = observed();
    p.reserved = 1;
    try std.testing.expectError(error.InvalidDeviceOrdinal, selection().requireObserved(&.{89}, device(), p));
}

test "CUDA selected session: unavailable native APIs and CuMetal cannot construct ready outcomes" {
    var result = Session.openSelected(&.{89}, selection());
    switch (result) {
        .failed => |failure| {
            try std.testing.expectEqual(error.InvalidState, failure.cause);
            try std.testing.expect(failure.cleanup == null);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(!result.hasResources());
    try result.deinit();
    const Metal = SessionModule.SessionForProvider(NoApi, NoApi, .cumetal);
    const rejected = Metal.openSelected(&.{89}, .{ .device_ordinal = 2, .device_uuid = [_]u8{7} ** 16 });
    switch (rejected) {
        .failed => |failure| try std.testing.expectEqual(error.ExecutionProviderMismatch, failure.cause),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u8, 0), @import("execution_plan.zig").max_lane_streams);
}

test "CUDA selected session: empty cleanup requires runtime thread and preserves cause" {
    var result: Session.Construction = .{ .failed = .{ .cause = error.OutOfMemory, .cleanup = emptyOpening() } };
    result.failed.cleanup.?.owner_thread_id = 0;
    try std.testing.expectError(error.ThreadOwnershipViolation, result.deinit());
    try std.testing.expect(result.failed.cleanup != null);
    result.failed.cleanup.?.owner_thread_id = std.Thread.getCurrentId();
    try result.deinit();
    try std.testing.expect(result.failed.cleanup == null);
    try std.testing.expectEqual(error.OutOfMemory, result.failed.cause);
    try result.deinit();
}

test "CUDA selected session: failed partial native cleanup never drops context or loader custody" {
    var sentinel: u8 = 0;
    const opaque_sentinel: *anyopaque = @ptrCast(&sentinel);
    var result: Session.Construction = .{ .failed = .{ .cause = error.OutOfMemory, .cleanup = retainedOpening(&sentinel) } };
    for (0..2) |_| {
        try std.testing.expect(result.hasResources());
        try std.testing.expectError(error.InvalidState, result.deinit());
        try std.testing.expect(result.failed.cleanup.?.context.failed.teardown.?.handle == opaque_sentinel);
    }
    result.failed.cleanup.?.aot_loader = opaque_sentinel;
    try std.testing.expectError(error.InvalidState, result.deinit());
    try std.testing.expect(result.failed.cleanup.?.aot_loader == opaque_sentinel);
    try std.testing.expect(result.failed.cleanup.?.context.failed.teardown.?.handle == opaque_sentinel);
    // Negative metadata ends here; no successful native allocation is asserted.
}

test "CUDA selected session: process outcome retains failed owner and lease thread guard" {
    var sentinel: u8 = 0;
    var result: Process.Construction = .{ .failed = .{ .cause = error.CudaFailure, .session = .{ .failed = .{ .cause = error.OutOfMemory, .cleanup = retainedOpening(&sentinel) } } } };
    try std.testing.expectError(error.InvalidState, result.deinit());
    try std.testing.expect(result.failed.session.?.hasResources());
    // Invalid lease metadata is rejected before touching registry/native state.
    result.failed.owns_registry = true;
    result.failed.owner_thread_id = 0;
    try std.testing.expectError(error.ThreadOwnershipViolation, result.deinit());
    try std.testing.expect(result.failed.owns_registry);
    try std.testing.expect(result.failed.session != null);
}

test "CUDA selected session: actual registry releases failed no-resource selected admissions" {
    for (0..3) |_| {
        var result = Process.openSelected(&.{89}, selection());
        switch (result) {
            .failed => |failure| {
                try std.testing.expectEqual(error.InvalidState, failure.cause);
                try std.testing.expect(!failure.owns_registry);
                try std.testing.expect(failure.session == null);
            },
            else => return error.TestUnexpectedResult,
        }
        try result.deinit();
    }
}
