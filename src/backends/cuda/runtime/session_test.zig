const std = @import("std");
const runtime_error = @import("error.zig");
const kernel_module = @import("kernel.zig");
const telemetry = @import("telemetry.zig");
const types = @import("../abi/types.zig");
const SessionFor = @import("session.zig").SessionFor;

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
                .local_bytes = 0,
                .static_shared_bytes = 0,
                .cache_key = cache_key,
                .context_token = 1,
                .module_token = 2,
                .function_token = 3,
                .stream_token = @intFromPtr(&stream_word),
                .verification = .{
                    .abi_version = types.aot_verification_abi_version,
                    .verified = types.aot_verification_verified,
                    .cubin_bytes = 4096,
                    .expected_sha256 = [_]u8{7} ** 32,
                    .observed_sha256 = [_]u8{7} ** 32,
                },
            };
            if (corrupt_next_receipt) {
                receipt.cache_key +%= 1;
                corrupt_next_receipt = false;
            }
            return 0;
        }
        pub fn stwo_native_aot_function_bind_with_globals(
            loader: *anyopaque,
            cache_key: u64,
            abi_schema: u32,
            expected_module_globals: u32,
            name: [*:0]const u8,
            grid: *const [3]u32,
            block: *const [3]u32,
            dynamic_shared_bytes: u32,
            argument_count: u32,
            out: *?*anyopaque,
            receipt: *types.NativeAotFunctionReceipt,
        ) c_int {
            if (expected_module_globals != 0) return 1;
            return stwo_native_aot_function_bind(
                loader,
                cache_key,
                abi_schema,
                name,
                grid,
                block,
                dynamic_shared_bytes,
                argument_count,
                out,
                receipt,
            );
        }
        pub fn stwo_native_aot_function_publish_pedersen_w18(
            _: *anyopaque,
            _: *const [56]u64,
            _: u32,
            _: *const [32]u8,
            _: *types.NativeAotModuleGlobalsReceipt,
        ) c_int {
            return 1;
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
        pub fn stwo_exec_context_free_u32(_: *anyopaque, _: [*]u32) c_int {
            return 0;
        }
        pub fn stwo_graph_destroy(_: *anyopaque) c_int {
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
    try std.testing.expect(session.isReady());
    try std.testing.expectEqual(@as(u32, 1), session.executionLaneCount());
    try std.testing.expect(
        !session.hasPreparedExecution([_]u8{0xa5} ** 32),
    );
    try session.beginProof();
    try std.testing.expect(!session.isReady());
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
    try std.testing.expect(session.isReady());
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
