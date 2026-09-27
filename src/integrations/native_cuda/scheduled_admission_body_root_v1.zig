//! Actual resident native bodies: SEMANTIC / OBJECT ONLY. Never execute this
//! export. An executable requires real CUDA linkage and hardware admission.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const native = @import("wide_fibonacci/mod.zig");

pub export fn stwo_cuda_scheduled_native_body_gate(
    runtime: *native.NativeRuntime,
    prepared: *native.NativeDriver.PreparedProof,
    request: *const native.request.Request,
) void {
    const driver = native.NativeDriver{ .allocator = std.heap.page_allocator };
    _ = driver.runPreparedRetained(runtime, request.*, prepared) catch return;
}

pub export fn stwo_cuda_scheduled_native_direct_body_gate(
    runtime: *native.NativeRuntime,
    prepared: *native.NativeDriver.PreparedProof,
    request: *const native.request.Request,
) void {
    const driver = native.NativeDriver{ .allocator = std.heap.page_allocator };
    _ = driver.runPreparedRetainedDirect(runtime, request.*, prepared) catch return;
}

pub export fn stwo_cuda_scheduled_session_admission_body_gate(
    session: *const cuda.runtime.NativeSession,
    stage: cuda.runtime.telemetry.Stage,
    lane: u8,
) bool {
    session.admitScheduledNode(stage, lane) catch return false;
    return true;
}
