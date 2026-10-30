//! Device-only hash witness stage. Uploading a cold plan and raw encoded input
//! is controller-owned. No numeric value is returned to the host; GPU status
//! and all outputs remain resident until the controller's terminal boundary.
const std = @import("std");
const Plan = @import("resident_parent_hash_plan_v1.zig");
pub const Device = struct {
    input: []const u8,
    sources: []const Plan.Source,
    calls: []const Plan.Call,
    level_calls: []const u32,
    phase_calls: []const u32 = &.{},
    wires: []u32,
    g_main: []u32,
    xor_main: []u32,
    status: []u32,
};
pub const Stats = struct { launches: usize, frames: usize, compressions: usize, g_rows: usize, xor_rows: usize, output_bytes: usize };
extern fn stwo_resident_parent_hash_sources_on([*]const u8, u32, [*]const Plan.Source, u32, [*]u32, u32, [*]u32, u32, [*]u32, u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_resident_parent_hash_calls_on([*]u32, u32, [*]const Plan.Call, [*]const u32, u32, [*]u32, [*]u32, u32, u32, [*]u32, ?*anyopaque) c_int;
pub fn validate(plan: *const Plan.Owned, device: Device) !void {
    const p = plan.view();
    if (device.input.len != p.input_bytes or device.sources.len != p.sources.len or device.calls.len != p.calls.len or device.level_calls.len != p.level_calls.len or device.wires.len != p.wire_count or device.g_main.len != (@as(usize, 82) << @intCast(p.g_log)) or device.xor_main.len != (@as(usize, 12) << @intCast(p.xor_log)) or device.status.len != 1) return error.InvalidResidentHashDeviceGeometry;
    // Span-address validation requires no host dereference of device memory.
    const spans = [_]struct { ptr: usize, bytes: usize }{ .{ .ptr = @intFromPtr(device.input.ptr), .bytes = device.input.len }, .{ .ptr = @intFromPtr(device.sources.ptr), .bytes = device.sources.len * @sizeOf(Plan.Source) }, .{ .ptr = @intFromPtr(device.calls.ptr), .bytes = device.calls.len * @sizeOf(Plan.Call) }, .{ .ptr = @intFromPtr(device.level_calls.ptr), .bytes = device.level_calls.len * 4 }, .{ .ptr = @intFromPtr(device.wires.ptr), .bytes = device.wires.len * 4 }, .{ .ptr = @intFromPtr(device.g_main.ptr), .bytes = device.g_main.len * 4 }, .{ .ptr = @intFromPtr(device.xor_main.ptr), .bytes = device.xor_main.len * 4 }, .{ .ptr = @intFromPtr(device.status.ptr), .bytes = 4 }, .{ .ptr = @intFromPtr(device.phase_calls.ptr), .bytes = device.phase_calls.len * 4 } };
    for (spans, 0..) |s, i| {
        if (s.bytes == 0) continue;
        if (s.ptr == 0) return error.InvalidResidentHashDeviceGeometry;
        const end = try std.math.add(usize, s.ptr, s.bytes);
        for (spans[0..i]) |prior| {
            if (prior.bytes != 0 and s.ptr < try std.math.add(usize, prior.ptr, prior.bytes) and prior.ptr < end) return error.ResidentHashDeviceAlias;
        }
    }
}
pub fn executeNative(plan: *const Plan.Owned, device: Device, stream: ?*anyopaque) !Stats {
    try validate(plan, device);
    const p = plan.view();
    if (stwo_resident_parent_hash_sources_on(device.input.ptr, @intCast(device.input.len), device.sources.ptr, @intCast(device.sources.len), device.wires.ptr, p.wire_count, device.g_main.ptr, p.g_log, device.xor_main.ptr, p.xor_log, device.status.ptr, stream) != 0) return error.ResidentHashCudaLaunch;
    var launches: usize = 1;
    for (0..p.level_offsets.len - 1) |level| {
        const first = p.level_offsets[level];
        const end = p.level_offsets[level + 1];
        if (end == first) continue;
        if (stwo_resident_parent_hash_calls_on(device.wires.ptr, p.wire_count, device.calls.ptr, device.level_calls[first..].ptr, end - first, device.g_main.ptr, device.xor_main.ptr, p.g_log, p.xor_log, device.status.ptr, stream) != 0) return error.ResidentHashCudaLaunch;
        launches += 1;
    }
    return .{ .launches = launches, .frames = p.frames.len, .compressions = p.calls.len, .g_rows = p.calls.len * 56, .xor_rows = p.calls.len * 16, .output_bytes = (device.g_main.len + device.xor_main.len) * 4 };
}

extern fn stwo_resident_parent_hash_initialize_on([*]u32, u32, [*]u32, u32, [*]u32, u32, ?*anyopaque) c_int;
extern fn stwo_resident_parent_hash_source_range_on([*]const u8, u32, [*]const Plan.Source, u32, [*]u32, u32, [*]u32, ?*anyopaque) c_int;
/// Controller owns the shared error flag; initializing witness storage MUST
/// NOT erase an earlier phase's error. This call zeroes only hash-owned slots.
pub fn initializeNative(plan: *const Plan.Owned, device: Device, stream: ?*anyopaque) !void {
    try validate(plan, device);
    const p = plan.view();
    if (device.phase_calls.len != p.phase_calls.len) return error.InvalidResidentHashDeviceGeometry;
    if (stwo_resident_parent_hash_initialize_on(device.wires.ptr, p.wire_count, device.g_main.ptr, p.g_log, device.xor_main.ptr, p.xor_log, stream) != 0) return error.ResidentHashCudaLaunch;
}
pub fn executeFrameNative(plan: *const Plan.Owned, device: Device, frame_index: usize, stream: ?*anyopaque) !Stats {
    try validate(plan, device);
    const p = plan.view();
    if (frame_index >= p.frames.len or device.phase_calls.len != p.phase_calls.len) return error.InvalidResidentHashDeviceGeometry;
    const frame = p.frames[frame_index];
    if (stwo_resident_parent_hash_source_range_on(device.input.ptr, @intCast(device.input.len), device.sources[frame.first_source..].ptr, @intCast(frame.source_count), device.wires.ptr, p.wire_count, device.status.ptr, stream) != 0) return error.ResidentHashCudaLaunch;
    var launches: usize = 1;
    for (0..frame.level_offsets.len - 1) |level| {
        const first = frame.level_offsets[level];
        const end = frame.level_offsets[level + 1];
        if (first == end) continue;
        if (stwo_resident_parent_hash_calls_on(device.wires.ptr, p.wire_count, device.calls.ptr, device.phase_calls[first..].ptr, end - first, device.g_main.ptr, device.xor_main.ptr, p.g_log, p.xor_log, device.status.ptr, stream) != 0) return error.ResidentHashCudaLaunch;
        launches += 1;
    }
    return .{ .launches = launches, .frames = 1, .compressions = frame.calls, .g_rows = frame.calls * 56, .xor_rows = frame.calls * 16, .output_bytes = (device.g_main.len + device.xor_main.len) * 4 };
}
