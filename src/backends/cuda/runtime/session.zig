//! Strict-AOT, proof-owned CUDA session admission and final residency verdict.

const std = @import("std");
const native_api = @import("../abi/runtime.zig");
const types = @import("../abi/types.zig");
const context_module = @import("context.zig");
const runtime_error = @import("error.zig");
const telemetry = @import("telemetry.zig");

pub const NativeSession = SessionFor(native_api);

pub const Verdict = struct {
    device: types.DeviceSnapshot,
    build_identity: [32]u8,
    aot_entries: usize,
    aot: types.AotStats,
    counters: telemetry.Counters,
    pool_used_bytes: usize,
    pool_reserved_bytes: usize,

    pub fn isResident(self: Verdict) bool {
        return self.aot.isStrict() and self.counters.isResident();
    }
};

pub fn SessionFor(comptime Api: type) type {
    const Context = context_module.ContextFor(Api);
    return struct {
        const Self = @This();

        context: Context,
        device: types.DeviceSnapshot,
        build_identity: [32]u8,
        aot_entries: usize,
        state: enum { open, proved, closed } = .open,

        pub fn open(accepted_sms: []const u32) runtime_error.Error!Self {
            var device = types.DeviceSnapshot{};
            try runtime_error.check(Api.stwo_cuda_device_snapshot(
                &device.count,
                &device.current,
                &device.sm_major,
                &device.sm_minor,
            ));
            if (device.count == 0) return error.DeviceUnavailable;
            if (device.current >= device.count) return error.InvalidDeviceOrdinal;
            const sm = deviceSm(device) catch return error.InvalidDeviceArchitecture;
            if (!contains(accepted_sms, sm)) return error.DeviceArchitectureMismatch;

            var build_identity = [_]u8{0} ** 32;
            try runtime_error.check(Api.stwo_static_cuda_module_build_identity(
                &build_identity,
            ));
            if (std.mem.allEqual(u8, &build_identity, 0))
                return error.BuildIdentityAbsent;
            const aot_entries = Api.stwo_zig_cuda_aot_entry_count();
            if (aot_entries == 0) return error.AotPackAbsent;

            Api.stwo_cuda_jit_set_require_aot(true);
            Api.stwo_cuda_jit_reset_aot_stats();
            return .{
                .context = try Context.open(),
                .device = device,
                .build_identity = build_identity,
                .aot_entries = aot_entries,
            };
        }

        pub fn markProofComplete(self: *Self) runtime_error.Error!void {
            if (self.state != .open) return error.InvalidState;
            if (!self.context.stagesComplete())
                return error.KernelPathUnused;
            self.state = .proved;
        }

        pub fn finish(self: *Self) runtime_error.Error!Verdict {
            if (self.state != .proved) return error.InvalidState;
            try self.context.joinLanes();
            try self.context.sync();
            if (self.context.live_buffers != 0) return error.DeviceBufferLive;
            const pool = try self.context.poolCurrent();
            var aot = types.AotStats{};
            Api.stwo_cuda_jit_get_aot_stats(&aot);
            if (!aot.isStrict()) return error.StrictAotViolation;
            const verdict = Verdict{
                .device = self.device,
                .build_identity = self.build_identity,
                .aot_entries = self.aot_entries,
                .aot = aot,
                .counters = self.context.counters,
                .pool_used_bytes = pool.used,
                .pool_reserved_bytes = pool.reserved,
            };
            if (!verdict.isResident()) return error.StrictAotViolation;
            try self.context.close();
            self.state = .closed;
            return verdict;
        }

        pub fn abort(self: *Self) runtime_error.Error!void {
            if (self.state == .closed) return error.InvalidState;
            if (self.context.live_buffers != 0) return error.DeviceBufferLive;
            try self.context.close();
            self.state = .closed;
        }
    };
}

fn deviceSm(device: types.DeviceSnapshot) !u32 {
    if (device.sm_minor > 9) return error.InvalidDeviceArchitecture;
    const major = std.math.mul(u32, device.sm_major, 10) catch
        return error.InvalidDeviceArchitecture;
    return std.math.add(u32, major, device.sm_minor) catch
        return error.InvalidDeviceArchitecture;
}

fn contains(values: []const u32, expected: u32) bool {
    for (values) |value| if (value == expected) return true;
    return false;
}

test "device architecture is encoded exactly" {
    try std.testing.expectEqual(@as(u32, 90), try deviceSm(.{
        .count = 1,
        .current = 0,
        .sm_major = 9,
        .sm_minor = 0,
    }));
    try std.testing.expectError(error.InvalidDeviceArchitecture, deviceSm(.{
        .count = 1,
        .current = 0,
        .sm_major = 9,
        .sm_minor = 10,
    }));
}

test "strict session returns a resident verdict and never exposes fallback" {
    const Fake = struct {
        var handle_word: u8 = 0;
        var stream_word: u8 = 0;
        var require_aot = false;

        pub fn stwo_cuda_device_snapshot(
            count: *u32,
            current: *u32,
            major: *u32,
            minor: *u32,
        ) c_int {
            count.* = 1;
            current.* = 0;
            major.* = 9;
            minor.* = 0;
            return 0;
        }
        pub fn stwo_static_cuda_module_build_identity(out: *[32]u8) c_int {
            out.* = [_]u8{7} ** 32;
            return 0;
        }
        pub fn stwo_zig_cuda_aot_entry_count() usize {
            return 340;
        }
        pub fn stwo_cuda_jit_set_require_aot(required: bool) void {
            require_aot = required;
        }
        pub fn stwo_cuda_jit_reset_aot_stats() void {}
        pub fn stwo_cuda_jit_get_aot_stats(out: *types.AotStats) void {
            out.* = .{ .aot_loads = 1 };
        }
        pub fn stwo_exec_context_create(out: *?*anyopaque) c_int {
            out.* = &handle_word;
            return 0;
        }
        pub fn stwo_exec_context_destroy(_: *anyopaque) c_int {
            return 0;
        }
        pub fn stwo_exec_context_stream(_: *anyopaque, out: *?*anyopaque) c_int {
            out.* = &stream_word;
            return 0;
        }
        pub fn stwo_exec_context_device(_: *anyopaque, out: *c_int) c_int {
            out.* = 0;
            return 0;
        }
        pub fn stwo_exec_context_lane_count(_: *anyopaque, out: *u32) c_int {
            out.* = 4;
            return 0;
        }
        pub fn stwo_exec_context_join_all_lanes(_: *anyopaque) c_int {
            return 0;
        }
        pub fn stwo_exec_context_sync(_: *anyopaque) c_int {
            return 0;
        }
        pub fn stwo_exec_context_pool_current(
            _: *anyopaque,
            used: *usize,
            reserved: *usize,
        ) c_int {
            used.* = 0;
            reserved.* = 1024;
            return 0;
        }
    };

    Fake.require_aot = false;
    const Session = SessionFor(Fake);
    var session = try Session.open(&.{90});
    try std.testing.expect(Fake.require_aot);
    for (telemetry.all_stages) |stage| {
        try session.context.beginStage(stage);
        if (stage.requiresKernel()) try session.context.recordKernels(1);
        try session.context.endStage(stage);
    }
    try session.markProofComplete();
    const verdict = try session.finish();
    try std.testing.expect(verdict.isResident());
    try std.testing.expectEqual(@as(u64, 0), verdict.counters.cpu_fallback_attempts);
    try std.testing.expectEqual(@as(u64, 0), verdict.counters.cpu_fallbacks_completed);
}
