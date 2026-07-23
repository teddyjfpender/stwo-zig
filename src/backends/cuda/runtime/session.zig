//! Strict-AOT, proof-owned CUDA session admission and final residency verdict.

const std = @import("std");
const native_api = @import("../abi/runtime.zig");
const native_aot = @import("../abi/aot.zig");
const types = @import("../abi/types.zig");
const context_module = @import("context.zig");
const kernel_module = @import("kernel.zig");
const runtime_error = @import("error.zig");
const telemetry = @import("telemetry.zig");

pub const NativeSession = SessionFor(native_api, native_aot);

pub const Verdict = struct {
    device: types.DeviceSnapshot,
    build_identity: [32]u8,
    aot_entries: usize,
    aot: types.NativeAotStats,
    counters: telemetry.Counters,
    pool_used_bytes: usize,
    pool_reserved_bytes: usize,

    pub fn isResident(self: Verdict) bool {
        return self.aot.isStrict() and self.counters.isResident();
    }
};

pub fn SessionFor(comptime Api: type, comptime AotApi: type) type {
    const Context = context_module.ContextFor(Api);
    return struct {
        const Self = @This();

        context: Context,
        device: types.DeviceSnapshot,
        build_identity: [32]u8,
        aot_entries: usize,
        aot_loader: ?*anyopaque,
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

            var context = try Context.open();
            errdefer context.close() catch {};
            var aot_loader: ?*anyopaque = null;
            try runtime_error.check(AotApi.stwo_native_aot_loader_create(
                context.handle.?,
                &aot_loader,
            ));
            return .{
                .context = context,
                .device = device,
                .build_identity = build_identity,
                .aot_entries = aot_entries,
                .aot_loader = aot_loader orelse return error.AotPackAbsent,
            };
        }

        pub fn markProofComplete(self: *Self) runtime_error.Error!void {
            if (self.state != .open) return error.InvalidState;
            if (!self.context.stagesComplete())
                return error.KernelPathUnused;
            self.state = .proved;
        }

        /// Binds, validates, launches, and releases one AOT function without
        /// exposing the loader or a raw CUDA function handle to proving code.
        pub fn launchKernel(
            self: *Self,
            kernel: kernel_module.Kernel,
            arguments: []const ?*anyopaque,
        ) runtime_error.Error!void {
            if (self.state != .open) return error.InvalidState;
            if (self.context.active_stage != kernel.stage)
                return error.StageOrderViolation;
            try kernel.validate();
            if (arguments.len != kernel.argument_count)
                return error.ArgumentCountMismatch;
            const loader = self.aot_loader orelse return error.InvalidState;

            var raw_function: ?*anyopaque = null;
            var receipt = types.NativeAotFunctionReceipt{};
            try runtime_error.check(AotApi.stwo_native_aot_function_bind(
                loader,
                kernel.cache_key,
                kernel.name.ptr,
                &kernel.grid,
                &kernel.block,
                kernel.dynamic_shared_bytes,
                kernel.argument_count,
                &raw_function,
                &receipt,
            ));
            const function = raw_function orelse return error.StrictAotViolation;
            errdefer runtime_error.check(
                AotApi.stwo_native_aot_function_destroy(function),
            ) catch {};

            try kernel.validateReceipt(
                receipt,
                self.device,
                self.context.stream,
            );
            try runtime_error.check(AotApi.stwo_native_aot_function_launch(
                function,
                arguments.ptr,
                @intCast(arguments.len),
            ));
            try self.context.recordKernels(1);
            try runtime_error.check(AotApi.stwo_native_aot_function_destroy(function));
        }

        pub fn finish(self: *Self) runtime_error.Error!Verdict {
            if (self.state != .proved) return error.InvalidState;
            try self.context.joinLanes();
            try self.context.sync();
            if (self.context.live_buffers != 0) return error.DeviceBufferLive;
            const pool = try self.context.poolCurrent();
            const loader = self.aot_loader orelse return error.InvalidState;
            var aot = types.NativeAotStats{};
            try runtime_error.check(AotApi.stwo_native_aot_loader_stats(loader, &aot));
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
            try runtime_error.check(AotApi.stwo_native_aot_loader_destroy(loader));
            self.aot_loader = null;
            try self.context.close();
            self.state = .closed;
            return verdict;
        }

        pub fn abort(self: *Self) runtime_error.Error!void {
            if (self.state == .closed) return error.InvalidState;
            if (self.context.live_buffers != 0) return error.DeviceBufferLive;
            if (self.aot_loader) |loader| {
                try runtime_error.check(AotApi.stwo_native_aot_loader_destroy(loader));
                self.aot_loader = null;
            }
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
        var loader_word: u8 = 0;

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
        pub fn stwo_native_aot_loader_create(
            _: *anyopaque,
            out: *?*anyopaque,
        ) c_int {
            out.* = &loader_word;
            return 0;
        }
        pub fn stwo_native_aot_loader_destroy(_: *anyopaque) c_int {
            return 0;
        }
        pub fn stwo_native_aot_loader_stats(
            _: *anyopaque,
            out: *types.NativeAotStats,
        ) c_int {
            out.* = .{ .aot_loads = 1, .launches = 7 };
            return 0;
        }
        pub fn stwo_native_aot_function_bind(
            _: *anyopaque,
            cache_key: u64,
            _: [*:0]const u8,
            grid: *const [3]u32,
            block: *const [3]u32,
            dynamic_shared_bytes: u32,
            argument_count: u32,
            out: *?*anyopaque,
            receipt: *types.NativeAotFunctionReceipt,
        ) c_int {
            out.* = &loader_word;
            receipt.* = .{
                .abi_version = kernel_module.receipt_abi_version,
                .device_ordinal = 0,
                .sm_major = 9,
                .sm_minor = 0,
                .argument_count = argument_count,
                .grid = grid.*,
                .block = block.*,
                .dynamic_shared_bytes = dynamic_shared_bytes,
                .registers_per_thread = 32,
                .max_threads_per_block = 1024,
                .binary_version = 90,
                .cache_key = cache_key,
                .context_token = 1,
                .module_token = 2,
                .function_token = 3,
                .stream_token = @intFromPtr(&stream_word),
            };
            return 0;
        }
        pub fn stwo_native_aot_function_launch(
            _: *anyopaque,
            _: [*]const ?*anyopaque,
            _: u32,
        ) c_int {
            return 0;
        }
        pub fn stwo_native_aot_function_destroy(_: *anyopaque) c_int {
            return 0;
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

    const Session = SessionFor(Fake, Fake);
    var session = try Session.open(&.{90});
    for (telemetry.all_stages) |stage| {
        try session.context.beginStage(stage);
        if (stage.requiresKernel()) {
            var argument: u32 = 7;
            const arguments = [_]?*anyopaque{@ptrCast(&argument)};
            try session.launchKernel(.{
                .stage = stage,
                .cache_key = 0x1234,
                .name = "resident_kernel",
                .grid = .{ 1, 1, 1 },
                .block = .{ 32, 1, 1 },
                .argument_count = 1,
            }, &arguments);
        }
        try session.context.endStage(stage);
    }
    try session.markProofComplete();
    const verdict = try session.finish();
    try std.testing.expect(verdict.isResident());
    try std.testing.expectEqual(@as(u64, 0), verdict.counters.cpu_fallback_attempts);
    try std.testing.expectEqual(@as(u64, 0), verdict.counters.cpu_fallbacks_completed);
}
