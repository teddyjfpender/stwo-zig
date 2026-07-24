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
const function_cache_allocator = std.heap.page_allocator;

const FunctionKey = struct {
    cache_key: u64,
    abi_schema: u32,
    name: []const u8,
    grid: [3]u32,
    block: [3]u32,
    dynamic_shared_bytes: u32,
    argument_count: u32,

    fn fromKernel(kernel: kernel_module.Kernel) FunctionKey {
        return .{
            .cache_key = kernel.cache_key,
            .abi_schema = @intFromEnum(kernel.abi_schema),
            .name = kernel.name,
            .grid = kernel.grid,
            .block = kernel.block,
            .dynamic_shared_bytes = kernel.dynamic_shared_bytes,
            .argument_count = kernel.argument_count,
        };
    }
};

const FunctionKeyContext = struct {
    pub fn hash(_: FunctionKeyContext, key: FunctionKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(std.mem.asBytes(&key.cache_key));
        hasher.update(std.mem.asBytes(&key.abi_schema));
        hasher.update(key.name);
        hasher.update(std.mem.asBytes(&key.grid));
        hasher.update(std.mem.asBytes(&key.block));
        hasher.update(std.mem.asBytes(&key.dynamic_shared_bytes));
        hasher.update(std.mem.asBytes(&key.argument_count));
        return hasher.final();
    }

    pub fn eql(_: FunctionKeyContext, left: FunctionKey, right: FunctionKey) bool {
        return left.cache_key == right.cache_key and
            left.abi_schema == right.abi_schema and
            std.mem.eql(u8, left.name, right.name) and
            std.mem.eql(u32, &left.grid, &right.grid) and
            std.mem.eql(u32, &left.block, &right.block) and
            left.dynamic_shared_bytes == right.dynamic_shared_bytes and
            left.argument_count == right.argument_count;
    }
};

const CachedFunction = struct {
    handle: *anyopaque,
    receipt: types.NativeAotFunctionReceipt,
};

const FunctionCache = std.HashMapUnmanaged(
    FunctionKey,
    CachedFunction,
    FunctionKeyContext,
    std.hash_map.default_max_load_percentage,
);

pub const Verdict = struct {
    device: types.DeviceSnapshot,
    platform: types.PlatformSnapshot,
    build_identity: [32]u8,
    aot_entries: usize,
    aot: types.NativeAotStats,
    lane_count: u32,
    counters: telemetry.Counters,
    pool_used_bytes: usize,
    pool_reserved_bytes: usize,
    runtime_proof_index: u64,

    pub fn isResident(self: Verdict) bool {
        return self.aot.isStrict() and
            self.lane_count != 0 and
            self.runtime_proof_index != 0 and
            self.counters.lane_joins == self.lane_count and
            self.counters.isResident();
    }
};

pub fn SessionFor(comptime Api: type, comptime AotApi: type) type {
    const Context = context_module.ContextFor(Api);
    return struct {
        const Self = @This();
        pub const FinishVerdict = Verdict;

        context: Context,
        device: types.DeviceSnapshot,
        platform: types.PlatformSnapshot,
        build_identity: [32]u8,
        aot_entries: usize,
        aot_loader: ?*anyopaque,
        function_cache: FunctionCache = .empty,
        owner_thread_id: std.Thread.Id,
        function_cache_hits: u64 = 0,
        completed_proofs: u64 = 0,
        state: enum { idle, open, proved, closed } = .idle,

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
            var platform = types.PlatformSnapshot{};
            try runtime_error.check(Api.stwo_cuda_platform_snapshot(&platform));
            if (!platform.isSane() or platform.device_ordinal != device.current)
                return error.InvalidDeviceOrdinal;

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
                .platform = platform,
                .build_identity = build_identity,
                .aot_entries = aot_entries,
                .aot_loader = aot_loader orelse return error.AotPackAbsent,
                .owner_thread_id = std.Thread.getCurrentId(),
            };
        }

        pub fn beginProof(self: *Self) runtime_error.Error!void {
            if (self.state != .idle) return error.InvalidState;
            try self.context.beginProof();
            self.state = .open;
        }

        pub fn markProofComplete(self: *Self) runtime_error.Error!void {
            if (self.state != .open) return error.InvalidState;
            if (!self.context.stagesComplete())
                return error.KernelPathUnused;
            self.state = .proved;
        }

        pub fn beginStage(
            self: *Self,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            if (self.state != .open) return error.InvalidState;
            try self.context.beginStage(stage);
        }

        pub fn endStage(
            self: *Self,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            if (self.state != .open) return error.InvalidState;
            try self.context.endStage(stage);
        }

        pub fn recordOrdinaryKernel(
            self: *Self,
            stage: telemetry.Stage,
            status: c_int,
        ) runtime_error.Error!void {
            try self.recordOrdinaryKernels(stage, status, 1);
        }

        pub fn recordOrdinaryKernels(
            self: *Self,
            stage: telemetry.Stage,
            status: c_int,
            count: u64,
        ) runtime_error.Error!void {
            if (self.state != .open) return error.InvalidState;
            if (self.context.active_stage != stage) return error.StageOrderViolation;
            try runtime_error.check(status);
            try self.context.recordKernels(count);
        }

        /// Zeroes one validated resident slice without allocating or waiting.
        pub fn zeroResidentSlice(
            self: *Self,
            comptime F: type,
            stage: telemetry.Stage,
            destination: anytype,
        ) runtime_error.Error!void {
            if (self.state != .open) return error.InvalidState;
            const active = self.context.active_stage orelse
                return error.StageNotActive;
            if (active != stage) return error.StageOrderViolation;
            try self.context.zeroDeviceSlice(F, destination);
        }

        /// Binds and validates each exact AOT launch shape once, then reuses it
        /// without exposing the loader or raw CUDA handles to proving code.
        pub fn launchKernel(
            self: *Self,
            kernel: kernel_module.Kernel,
            arguments: []const ?*anyopaque,
        ) runtime_error.Error!void {
            try self.requireOwner();
            if (self.state != .open) return error.InvalidState;
            if (self.context.active_stage != kernel.stage)
                return error.StageOrderViolation;
            try kernel.validate();
            if (arguments.len != kernel.argument_count)
                return error.ArgumentCountMismatch;
            const loader = self.aot_loader orelse return error.InvalidState;

            const lookup_key = FunctionKey.fromKernel(kernel);
            if (self.function_cache.getPtr(lookup_key)) |cached| {
                try kernel.validateReceipt(
                    cached.receipt,
                    self.device,
                    self.context.stream,
                );
                self.function_cache_hits = std.math.add(
                    u64,
                    self.function_cache_hits,
                    1,
                ) catch return error.InvalidState;
                try runtime_error.check(AotApi.stwo_native_aot_function_launch(
                    cached.handle,
                    arguments.ptr,
                    @intCast(arguments.len),
                ));
                try self.context.recordKernels(1);
                return;
            }

            var raw_function: ?*anyopaque = null;
            var receipt = types.NativeAotFunctionReceipt{};
            try runtime_error.check(AotApi.stwo_native_aot_function_bind(
                loader,
                kernel.cache_key,
                @intFromEnum(kernel.abi_schema),
                kernel.name.ptr,
                &kernel.grid,
                &kernel.block,
                kernel.dynamic_shared_bytes,
                kernel.argument_count,
                &raw_function,
                &receipt,
            ));
            const function = raw_function orelse return error.StrictAotViolation;
            var function_owned = true;
            errdefer if (function_owned) runtime_error.check(
                AotApi.stwo_native_aot_function_destroy(function),
            ) catch {};
            try kernel.validateReceipt(
                receipt,
                self.device,
                self.context.stream,
            );

            const owned_name = function_cache_allocator.dupe(
                u8,
                kernel.name,
            ) catch return error.OutOfMemory;
            var name_owned = true;
            errdefer if (name_owned) function_cache_allocator.free(owned_name);
            const owned_key = FunctionKey{
                .cache_key = lookup_key.cache_key,
                .abi_schema = lookup_key.abi_schema,
                .name = owned_name,
                .grid = lookup_key.grid,
                .block = lookup_key.block,
                .dynamic_shared_bytes = lookup_key.dynamic_shared_bytes,
                .argument_count = lookup_key.argument_count,
            };
            self.function_cache.putNoClobber(
                function_cache_allocator,
                owned_key,
                .{ .handle = function, .receipt = receipt },
            ) catch return error.OutOfMemory;
            name_owned = false;
            function_owned = false;

            try runtime_error.check(AotApi.stwo_native_aot_function_launch(
                function,
                arguments.ptr,
                @intCast(arguments.len),
            ));
            try self.context.recordKernels(1);
        }

        fn collectVerdict(self: *Self) runtime_error.Error!Verdict {
            if (self.state != .proved) return error.InvalidState;
            try self.context.joinLanes();
            if (self.context.live_buffers != 0) return error.DeviceBufferLive;
            const pool = try self.context.poolCurrent();
            const loader = self.aot_loader orelse return error.InvalidState;
            var aot = types.NativeAotStats{};
            try runtime_error.check(AotApi.stwo_native_aot_loader_stats(loader, &aot));
            aot.aot_cache_hits = std.math.add(
                u64,
                aot.aot_cache_hits,
                self.function_cache_hits,
            ) catch return error.InvalidState;
            if (!aot.isStrict()) return error.StrictAotViolation;
            const proof_index = std.math.add(
                u64,
                self.completed_proofs,
                1,
            ) catch return error.InvalidState;
            const verdict = Verdict{
                .device = self.device,
                .platform = self.platform,
                .build_identity = self.build_identity,
                .aot_entries = self.aot_entries,
                .aot = aot,
                .lane_count = self.context.lane_count,
                .counters = self.context.counters,
                .pool_used_bytes = pool.used,
                .pool_reserved_bytes = pool.reserved,
                .runtime_proof_index = proof_index,
            };
            if (!verdict.isResident()) return error.StrictAotViolation;
            self.completed_proofs = proof_index;
            return verdict;
        }

        pub fn finishRetained(self: *Self) runtime_error.Error!Verdict {
            const verdict = try self.collectVerdict();
            self.state = .idle;
            return verdict;
        }

        pub fn finish(self: *Self) runtime_error.Error!Verdict {
            const verdict = try self.collectVerdict();
            try self.releaseCachedFunctions();
            const loader = self.aot_loader orelse return error.InvalidState;
            try runtime_error.check(AotApi.stwo_native_aot_loader_destroy(loader));
            self.aot_loader = null;
            try self.context.close();
            self.state = .closed;
            return verdict;
        }

        pub fn abortRetained(self: *Self) runtime_error.Error!void {
            if (self.state == .idle or self.state == .closed)
                return error.InvalidState;
            self.context.abortProof() catch |err| {
                self.abort() catch {};
                return err;
            };
            self.state = .idle;
        }

        pub fn close(self: *Self) runtime_error.Error!void {
            try self.requireOwner();
            if (self.state != .idle) return error.InvalidState;
            try self.releaseCachedFunctions();
            const loader = self.aot_loader orelse return error.InvalidState;
            try runtime_error.check(AotApi.stwo_native_aot_loader_destroy(loader));
            self.aot_loader = null;
            try self.context.close();
            self.state = .closed;
        }

        pub fn abort(self: *Self) runtime_error.Error!void {
            try self.requireOwner();
            if (self.state == .closed) return error.InvalidState;
            var first_error: ?runtime_error.Error = null;
            self.releaseCachedFunctions() catch |err| {
                first_error = err;
            };
            if (self.aot_loader) |loader| {
                runtime_error.check(AotApi.stwo_native_aot_loader_destroy(loader)) catch |err| {
                    if (first_error == null) first_error = err;
                };
                self.aot_loader = null;
            }
            self.context.abort() catch |err| {
                if (first_error == null) first_error = err;
            };
            self.state = .closed;
            if (first_error) |err| return err;
        }

        fn requireOwner(self: *const Self) runtime_error.Error!void {
            if (self.owner_thread_id != std.Thread.getCurrentId())
                return error.ThreadOwnershipViolation;
        }

        fn releaseCachedFunctions(self: *Self) runtime_error.Error!void {
            try self.requireOwner();
            while (self.function_cache.count() != 0) {
                var iterator = self.function_cache.iterator();
                const entry = iterator.next() orelse unreachable;
                try runtime_error.check(
                    AotApi.stwo_native_aot_function_destroy(
                        entry.value_ptr.handle,
                    ),
                );
                const removed = self.function_cache.fetchRemove(
                    entry.key_ptr.*,
                ) orelse unreachable;
                function_cache_allocator.free(removed.key.name);
            }
            self.function_cache.deinit(function_cache_allocator);
            self.function_cache = .empty;
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
        var lane_join_calls: usize = 0;
        var direct_sync_calls: usize = 0;
        var context_destroy_calls: usize = 0;
        var loader_destroy_calls: usize = 0;
        var function_bind_calls: usize = 0;
        var function_launch_attempts: usize = 0;
        var function_launch_calls: usize = 0;
        var function_destroy_calls: usize = 0;
        var live_functions: usize = 0;
        var corrupt_next_receipt = false;
        var fail_next_launch = false;
        var loader_destroy_saw_live_function = false;

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
        pub fn stwo_cuda_platform_snapshot(
            out: *types.PlatformSnapshot,
        ) c_int {
            out.* = .{
                .uuid = [_]u8{3} ** 16,
                .driver_version = 12080,
                .runtime_version = 12080,
                .toolkit_version = 12080,
                .total_global_memory = 24 * 1024 * 1024 * 1024,
                .multiprocessor_count = 128,
                .warp_size = 32,
                .max_threads_per_block = 1024,
            };
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
            loader_destroy_calls += 1;
            if (live_functions != 0) {
                loader_destroy_saw_live_function = true;
                return 1;
            }
            return 0;
        }
        pub fn stwo_native_aot_loader_stats(
            _: *anyopaque,
            out: *types.NativeAotStats,
        ) c_int {
            out.* = .{
                .aot_loads = 1,
                .aot_cache_hits = 2,
                .launches = function_launch_calls,
            };
            return 0;
        }
        pub fn stwo_native_aot_function_bind(
            _: *anyopaque,
            cache_key: u64,
            abi_schema: u32,
            _: [*:0]const u8,
            grid: *const [3]u32,
            block: *const [3]u32,
            dynamic_shared_bytes: u32,
            argument_count: u32,
            out: *?*anyopaque,
            receipt: *types.NativeAotFunctionReceipt,
        ) c_int {
            function_bind_calls += 1;
            live_functions += 1;
            out.* = &loader_word;
            receipt.* = .{
                .abi_version = kernel_module.receipt_abi_version,
                .abi_schema = abi_schema,
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
            if (corrupt_next_receipt) {
                receipt.cache_key +%= 1;
                corrupt_next_receipt = false;
            }
            return 0;
        }
        pub fn stwo_native_aot_function_launch(
            _: *anyopaque,
            _: [*]const ?*anyopaque,
            _: u32,
        ) c_int {
            function_launch_attempts += 1;
            if (fail_next_launch) {
                fail_next_launch = false;
                return 1;
            }
            function_launch_calls += 1;
            return 0;
        }
        pub fn stwo_native_aot_function_destroy(_: *anyopaque) c_int {
            if (live_functions == 0) return 1;
            function_destroy_calls += 1;
            live_functions -= 1;
            return 0;
        }
        pub fn stwo_exec_context_create(out: *?*anyopaque) c_int {
            out.* = &handle_word;
            return 0;
        }
        pub fn stwo_exec_context_destroy(_: *anyopaque) c_int {
            context_destroy_calls += 1;
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
            out.* = 1;
            return 0;
        }
        pub fn stwo_exec_context_join_all_lanes(_: *anyopaque) c_int {
            lane_join_calls += 1;
            return 0;
        }
        pub fn stwo_exec_context_sync(_: *anyopaque) c_int {
            direct_sync_calls += 1;
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
    Fake.lane_join_calls = 0;
    Fake.direct_sync_calls = 0;
    Fake.context_destroy_calls = 0;
    Fake.loader_destroy_calls = 0;
    Fake.function_bind_calls = 0;
    Fake.function_launch_attempts = 0;
    Fake.function_launch_calls = 0;
    Fake.function_destroy_calls = 0;
    Fake.live_functions = 0;
    Fake.corrupt_next_receipt = false;
    Fake.fail_next_launch = false;
    Fake.loader_destroy_saw_live_function = false;

    var session = try Session.open(&.{90});
    try session.beginProof();
    var off_owner_error: ?runtime_error.Error = null;
    const off_owner = try std.Thread.spawn(.{}, struct {
        fn run(target: *Session, result: *?runtime_error.Error) void {
            var argument: u32 = 5;
            const arguments = [_]?*anyopaque{@ptrCast(&argument)};
            target.launchKernel(.{
                .stage = .ingress,
                .abi_schema = .ordinary_constraint_v1,
                .cache_key = 0x1234,
                .name = "resident_kernel",
                .grid = .{ 1, 1, 1 },
                .block = .{ 32, 1, 1 },
                .argument_count = 1,
            }, &arguments) catch |err| {
                result.* = err;
                return;
            };
        }
    }.run, .{ &session, &off_owner_error });
    off_owner.join();
    try std.testing.expectEqual(
        error.ThreadOwnershipViolation,
        off_owner_error.?,
    );
    try std.testing.expectEqual(@as(usize, 0), Fake.function_bind_calls);

    for (telemetry.all_stages) |stage| {
        try session.context.beginStage(stage);
        if (stage.requiresKernel()) {
            var argument: u32 = 7;
            const arguments = [_]?*anyopaque{@ptrCast(&argument)};
            try session.launchKernel(.{
                .stage = stage,
                .abi_schema = .ordinary_constraint_v1,
                .cache_key = 0x1234,
                .name = "resident_kernel",
                .grid = .{ 1, 1, 1 },
                .block = .{ 32, 1, 1 },
                .argument_count = 1,
            }, &arguments);
            if (stage == .constraint_evaluation) {
                const geometry_variant = kernel_module.Kernel{
                    .stage = stage,
                    .abi_schema = .ordinary_constraint_v1,
                    .cache_key = 0x1234,
                    .name = "resident_kernel",
                    .grid = .{ 1, 1, 1 },
                    .block = .{ 64, 1, 1 },
                    .argument_count = 1,
                };
                try session.launchKernel(geometry_variant, &arguments);
                try session.launchKernel(geometry_variant, &arguments);
                try session.launchKernel(.{
                    .stage = stage,
                    .abi_schema = .ordinary_constraint_v1,
                    .cache_key = 0x1234,
                    .name = "different_name",
                    .grid = .{ 1, 1, 1 },
                    .block = .{ 32, 1, 1 },
                    .argument_count = 1,
                }, &arguments);
                try session.launchKernel(.{
                    .stage = stage,
                    .abi_schema = .ordinary_constraint_v1,
                    .cache_key = 0x5678,
                    .name = "resident_kernel",
                    .grid = .{ 1, 1, 1 },
                    .block = .{ 32, 1, 1 },
                    .argument_count = 1,
                }, &arguments);
                try session.launchKernel(.{
                    .stage = stage,
                    .abi_schema = .composition_wave_v2,
                    .cache_key = 0x1234,
                    .name = "resident_kernel",
                    .grid = .{ 1, 1, 1 },
                    .block = .{ 32, 1, 1 },
                    .argument_count = 1,
                }, &arguments);

                const receipt_failure = kernel_module.Kernel{
                    .stage = stage,
                    .abi_schema = .composition_wave_v2,
                    .cache_key = 0x9abc,
                    .name = "receipt_failure",
                    .grid = .{ 1, 1, 1 },
                    .block = .{ 32, 1, 1 },
                    .argument_count = 1,
                };
                Fake.corrupt_next_receipt = true;
                try std.testing.expectError(
                    error.AotReceiptMismatch,
                    session.launchKernel(receipt_failure, &arguments),
                );
                try std.testing.expectEqual(
                    @as(usize, 1),
                    Fake.function_destroy_calls,
                );
                try session.launchKernel(receipt_failure, &arguments);
                Fake.fail_next_launch = true;
                try std.testing.expectError(
                    error.CudaFailure,
                    session.launchKernel(receipt_failure, &arguments),
                );
                try std.testing.expectEqual(
                    @as(usize, 7),
                    Fake.function_bind_calls,
                );
                try session.launchKernel(receipt_failure, &arguments);
            }
        } else if (stage == .proof_assembly) {
            session.context.counters.proofRead(stage, @sizeOf(u32));
        }
        try session.context.endStage(stage);
    }
    try session.markProofComplete();
    const expected_first_cache_hits = session.function_cache_hits + 2;
    const verdict = try session.finishRetained();
    try std.testing.expect(verdict.isResident());
    try std.testing.expectEqual(@as(u64, 0), verdict.counters.cpu_fallback_attempts);
    try std.testing.expectEqual(@as(u64, 0), verdict.counters.cpu_fallbacks_completed);
    try std.testing.expectEqual(@as(u32, 1), verdict.lane_count);
    try std.testing.expectEqual(@as(u64, 1), verdict.counters.lane_joins);
    try std.testing.expectEqual(@as(u64, 1), verdict.counters.sync_calls);
    try std.testing.expectEqual(@as(u64, 1), verdict.counters.d2h_proof_operations);
    try std.testing.expectEqual(@as(u64, 1), verdict.runtime_proof_index);
    try std.testing.expectEqual(
        expected_first_cache_hits,
        verdict.aot.aot_cache_hits,
    );
    try std.testing.expectEqual(@as(usize, 1), Fake.lane_join_calls);
    try std.testing.expectEqual(@as(usize, 0), Fake.direct_sync_calls);
    try std.testing.expectEqual(@as(usize, 7), Fake.function_bind_calls);
    try std.testing.expectEqual(
        Fake.function_launch_calls + 1,
        Fake.function_launch_attempts,
    );
    try std.testing.expect(Fake.function_launch_calls > Fake.function_bind_calls);
    try std.testing.expectEqual(@as(usize, 6), Fake.live_functions);

    try session.beginProof();
    for (telemetry.all_stages) |stage| {
        try session.context.beginStage(stage);
        if (stage.requiresKernel()) {
            var argument: u32 = 11;
            const arguments = [_]?*anyopaque{@ptrCast(&argument)};
            try session.launchKernel(.{
                .stage = stage,
                .abi_schema = .ordinary_constraint_v1,
                .cache_key = 0x1234,
                .name = "resident_kernel",
                .grid = .{ 1, 1, 1 },
                .block = .{ 32, 1, 1 },
                .argument_count = 1,
            }, &arguments);
        } else if (stage == .proof_assembly) {
            session.context.counters.proofRead(stage, @sizeOf(u32));
        }
        try session.context.endStage(stage);
    }
    try session.markProofComplete();
    const expected_repeated_cache_hits = session.function_cache_hits + 2;
    const repeated = try session.finishRetained();
    try std.testing.expectEqual(@as(u64, 2), repeated.runtime_proof_index);
    try std.testing.expectEqual(@as(u64, 1), repeated.counters.lane_joins);
    try std.testing.expectEqual(
        expected_repeated_cache_hits,
        repeated.aot.aot_cache_hits,
    );
    try std.testing.expect(
        repeated.aot.aot_cache_hits > verdict.aot.aot_cache_hits,
    );
    try std.testing.expectEqual(@as(usize, 0), Fake.context_destroy_calls);
    try std.testing.expectEqual(@as(usize, 0), Fake.loader_destroy_calls);
    try std.testing.expectEqual(@as(usize, 7), Fake.function_bind_calls);
    try std.testing.expectEqual(@as(usize, 1), Fake.function_destroy_calls);
    try session.close();
    try std.testing.expectEqual(@as(usize, 1), Fake.context_destroy_calls);
    try std.testing.expectEqual(@as(usize, 1), Fake.loader_destroy_calls);
    try std.testing.expectEqual(@as(usize, 7), Fake.function_destroy_calls);
    try std.testing.expectEqual(@as(usize, 0), Fake.live_functions);
    try std.testing.expect(!Fake.loader_destroy_saw_live_function);
}
