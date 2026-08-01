//! Test-only fault injection at the backend ownership-transfer boundary.

const std = @import("std");
const builtin = @import("builtin");

var fail_after_transfer: std.atomic.Value(bool) = .init(false);
var heterogeneous_failure_point: std.atomic.Value(u8) = .init(0);
var force_heterogeneous_admission: std.atomic.Value(bool) = .init(false);

pub const HeterogeneousFailurePoint = enum(u8) {
    after_resize = 1,
    after_alias = 2,
    after_wait = 3,
    after_tree_adoption = 4,
    during_descriptor_initialization = 5,
};

pub fn arm() void {
    if (comptime !builtin.is_test) @compileError("test-only Metal failure injection");
    fail_after_transfer.store(true, .release);
}

pub fn clear() void {
    if (comptime !builtin.is_test) @compileError("test-only Metal failure injection");
    fail_after_transfer.store(false, .release);
}

pub fn failAfterTransfer() !void {
    if (comptime builtin.is_test) {
        if (fail_after_transfer.swap(false, .acq_rel))
            return error.InjectedOwnershipTransferFailure;
    }
}

pub fn armHeterogeneousFailure(point: HeterogeneousFailurePoint) void {
    if (comptime !builtin.is_test) @compileError("test-only Metal failure injection");
    heterogeneous_failure_point.store(@intFromEnum(point), .release);
}

pub fn clearHeterogeneousFailure() void {
    if (comptime !builtin.is_test) @compileError("test-only Metal failure injection");
    heterogeneous_failure_point.store(0, .release);
}

pub fn failHeterogeneousAt(point: HeterogeneousFailurePoint) !void {
    if (comptime builtin.is_test) {
        if (heterogeneous_failure_point.load(.acquire) == @intFromEnum(point)) {
            heterogeneous_failure_point.store(0, .release);
            return error.InjectedHeterogeneousCommitFailure;
        }
    }
}

pub fn setForceHeterogeneousAdmission(enabled: bool) void {
    if (comptime !builtin.is_test) @compileError("test-only Metal admission override");
    force_heterogeneous_admission.store(enabled, .release);
}

pub fn forceHeterogeneousAdmission() bool {
    return if (comptime builtin.is_test)
        force_heterogeneous_admission.load(.acquire)
    else
        false;
}
