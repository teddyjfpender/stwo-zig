//! Strict-AOT, proof-owned CUDA session admission and final residency verdict.
const std = @import("std");
const native_api = @import("../abi/runtime.zig");
const native_aot = @import("../abi/aot.zig");
const types = @import("../abi/types.zig");
const arena_module = @import("arena.zig");
const context_module = @import("context.zig");
const device_admission = @import("device_admission.zig");
const execution_cache_module = @import("execution_cache.zig");
const function_cache_module = @import("function_cache.zig");
const kernel_module = @import("kernel.zig");
const provider_module = @import("provider.zig");
const runtime_error = @import("error.zig");
const telemetry = @import("telemetry.zig");
const verdict_module = @import("verdict.zig");
pub const NativeSession = SessionFor(native_api, native_aot);
pub const CuMetalSession = SessionForProvider(
    native_api,
    native_aot,
    .cumetal,
);
const FunctionKey = function_cache_module.Key;
const FunctionCache = function_cache_module.Map;
const function_cache_allocator = function_cache_module.allocator;
pub const Verdict = verdict_module.Verdict;

pub fn SessionFor(
    comptime Api: type,
    comptime AotApi: type,
) type {
    return SessionForProvider(Api, AotApi, .nvidia_cuda);
}

pub fn SessionForProvider(
    comptime Api: type,
    comptime AotApi: type,
    comptime provider: provider_module.Kind,
) type {
    const Context = context_module.ContextFor(Api);
    const Arena = arena_module.ArenaFor(Context);
    const ExecutionCache = execution_cache_module.CacheFor(Api, Context);
    return struct {
        const Self = @This();
        pub const FinishVerdict = Verdict;
        pub const execution_provider = provider;

        context: Context,
        device: types.DeviceSnapshot,
        platform: types.PlatformSnapshot,
        build_identity: [32]u8,
        aot_entries: usize,
        aot_loader: ?*anyopaque,
        function_cache: FunctionCache = .empty,
        owner_thread_id: std.Thread.Id,
        function_cache_hits: u64 = 0,
        execution_cache: ExecutionCache = .{},
        active_execution_key: ?[32]u8 = null,
        completed_proofs: u64 = 0,
        state: enum { idle, open, proved, closed } = .idle,

        pub fn open(accepted_sms: []const u32) runtime_error.Error!Self {
            if (Api.stwo_cuda_execution_provider() != @intFromEnum(provider))
                return error.ExecutionProviderMismatch;
            var device = types.DeviceSnapshot{};
            try runtime_error.check(Api.stwo_cuda_device_snapshot(
                &device.count,
                &device.current,
                &device.sm_major,
                &device.sm_minor,
            ));
            if (device.count == 0) return error.DeviceUnavailable;
            if (device.current >= device.count) return error.InvalidDeviceOrdinal;
            const sm = device_admission.sm(device) catch
                return error.InvalidDeviceArchitecture;
            if (!device_admission.contains(accepted_sms, sm))
                return error.DeviceArchitectureMismatch;
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
            try self.requireOwner();
            if (self.state != .idle or self.active_execution_key != null)
                return error.InvalidState;
            try self.context.beginProof();
            self.state = .open;
        }

        /// Process-service observations. These expose lifecycle and cache
        /// facts without granting access to CUDA handles or mutating LRU age.
        pub fn isReady(self: *const Self) bool {
            return self.owner_thread_id == std.Thread.getCurrentId() and
                self.state == .idle and
                self.active_execution_key == null and
                self.context.active_stage == null and
                self.context.synchronized;
        }

        pub fn executionLaneCount(self: *const Self) u32 {
            return self.context.lane_count;
        }

        pub fn hasPreparedExecution(
            self: *const Self,
            cache_key: [32]u8,
        ) bool {
            return self.state == .idle and
                self.execution_cache.contains(cache_key);
        }

        /// Installs one full-plan-keyed, fixed-address execution arena in the
        /// bounded process cache. Re-preparing the same key is a cache hit.
        pub fn prepareExecution(
            self: *Self,
            allocator: std.mem.Allocator,
            cache_key: [32]u8,
            owned_plan: arena_module.Plan,
        ) runtime_error.Error!void {
            try self.requireOwner();
            if (self.state != .idle) return error.InvalidState;
            try self.execution_cache.prepare(
                &self.context,
                allocator,
                cache_key,
                owned_plan,
            );
        }
        pub fn acquirePreparedArena(
            self: *Self,
            cache_key: [32]u8,
        ) runtime_error.Error!*Arena {
            try self.requireOwner();
            if (self.state != .open or self.active_execution_key != null)
                return error.InvalidState;
            const arena = try self.execution_cache.acquireArena(cache_key);
            self.active_execution_key = cache_key;
            return arena;
        }

        pub fn hasStageGraph(
            self: *Self,
            cache_key: [32]u8,
            stage: telemetry.Stage,
        ) runtime_error.Error!bool {
            try self.requireOwner();
            if (self.state != .open) return error.InvalidState;
            return self.execution_cache.hasGraph(cache_key, stage);
        }

        pub fn beginStageGraphCapture(
            self: *Self,
            cache_key: [32]u8,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            try self.requireOwner();
            if (self.state != .open) return error.InvalidState;
            try self.execution_cache.beginCapture(
                &self.context,
                cache_key,
                stage,
            );
        }

        pub fn finishStageGraphCaptureAndLaunch(
            self: *Self,
            cache_key: [32]u8,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            try self.requireOwner();
            if (self.state != .open) return error.InvalidState;
            try self.execution_cache.finishCaptureAndLaunch(
                &self.context,
                cache_key,
                stage,
            );
        }

        pub fn launchStageGraph(
            self: *Self,
            cache_key: [32]u8,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            try self.requireOwner();
            if (self.state != .open) return error.InvalidState;
            try self.execution_cache.launch(
                &self.context,
                cache_key,
                stage,
            );
        }

        pub fn abortStageGraphCapture(self: *Self) runtime_error.Error!void {
            try self.requireOwner();
            if (self.state != .open) return error.InvalidState;
            try self.execution_cache.abortCapture(&self.context);
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
            return self.launchKernelWithGlobals(kernel, arguments, null);
        }

        pub fn launchKernelWithPedersenW18(
            self: *Self,
            kernel: kernel_module.Kernel,
            arguments: []const ?*anyopaque,
            publication: kernel_module.PedersenW18Publication,
        ) runtime_error.Error!void {
            try publication.validate();
            if (kernel.module_globals != .pedersen_w18_columns_rows_v1)
                return error.InvalidKernelDescriptor;
            return self.launchKernelWithGlobals(
                kernel,
                arguments,
                publication,
            );
        }

        fn launchKernelWithGlobals(
            self: *Self,
            kernel: kernel_module.Kernel,
            arguments: []const ?*anyopaque,
            publication: ?kernel_module.PedersenW18Publication,
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
                try self.publishModuleGlobals(
                    kernel,
                    cached.*,
                    publication,
                );
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
            try runtime_error.check(AotApi.stwo_native_aot_function_bind_with_globals(
                loader,
                kernel.cache_key,
                @intFromEnum(kernel.abi_schema),
                @intFromEnum(kernel.module_globals),
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
                .module_globals = lookup_key.module_globals,
            };
            self.function_cache.putNoClobber(
                function_cache_allocator,
                owned_key,
                .{ .handle = function, .receipt = receipt },
            ) catch return error.OutOfMemory;
            name_owned = false;
            function_owned = false;

            try self.publishModuleGlobals(
                kernel,
                .{ .handle = function, .receipt = receipt },
                publication,
            );
            try runtime_error.check(AotApi.stwo_native_aot_function_launch(
                function,
                arguments.ptr,
                @intCast(arguments.len),
            ));
            try self.context.recordKernels(1);
        }

        fn publishModuleGlobals(
            self: *Self,
            kernel: kernel_module.Kernel,
            function: function_cache_module.Value,
            publication: ?kernel_module.PedersenW18Publication,
        ) runtime_error.Error!void {
            switch (kernel.module_globals) {
                .none => {
                    if (publication != null)
                        return error.InvalidKernelDescriptor;
                },
                .pedersen_w18_columns_rows_v1 => {
                    const pedersen = publication orelse
                        return error.StrictAotViolation;
                    var receipt = types.NativeAotModuleGlobalsReceipt{};
                    try runtime_error.check(
                        AotApi.stwo_native_aot_function_publish_pedersen_w18(
                            function.handle,
                            &pedersen.columns,
                            pedersen.row_count,
                            &pedersen.table_identity,
                            &receipt,
                        ),
                    );
                    if (receipt.abi_version !=
                        types.aot_module_globals_receipt_abi_version or
                        receipt.verified != 1 or
                        receipt.module_globals !=
                            @intFromEnum(kernel.module_globals) or
                        receipt.column_count != pedersen.columns.len or
                        receipt.row_count != pedersen.row_count or
                        receipt.reserved != 0 or
                        receipt.columns_symbol_bytes !=
                            pedersen.columns.len * @sizeOf(u64) or
                        receipt.row_count_symbol_bytes != @sizeOf(u32) or
                        receipt.module_token !=
                            function.receipt.module_token or
                        receipt.stream_token !=
                            @intFromPtr(self.context.stream) or
                        !std.mem.eql(
                            u8,
                            &receipt.table_identity,
                            &pedersen.table_identity,
                        ))
                    {
                        return error.AotReceiptMismatch;
                    }
                },
            }
        }

        fn collectVerdict(self: *Self) runtime_error.Error!Verdict {
            if (self.state != .proved) return error.InvalidState;
            try self.context.joinLanes();
            if (self.context.live_buffers != self.context.persistent_buffers)
                return error.DeviceBufferLive;
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
                .provider = provider,
                .device = self.device,
                .platform = self.platform,
                .build_identity = self.build_identity,
                .aot_entries = self.aot_entries,
                .aot = aot,
                .lane_count = self.context.lane_count,
                .counters = self.context.counters,
                .pool_used_bytes = pool.used,
                .pool_reserved_bytes = pool.reserved,
                .graph_cache_hits_total = self.execution_cache.hits,
                .graph_cache_misses_total = self.execution_cache.misses,
                .prepared_cache_hits_total = self.execution_cache.prepared_hits,
                .prepared_cache_misses_total = self.execution_cache.prepared_misses,
                .prepared_cache_evictions_total = self.execution_cache.evictions,
                .runtime_proof_index = proof_index,
            };
            if (!verdict.isResident()) return error.StrictAotViolation;
            self.completed_proofs = proof_index;
            return verdict;
        }

        pub fn finishRetained(self: *Self) runtime_error.Error!Verdict {
            const verdict = try self.collectVerdict();
            try self.releaseActiveExecution();
            self.state = .idle;
            return verdict;
        }

        pub fn finish(self: *Self) runtime_error.Error!Verdict {
            const verdict = try self.collectVerdict();
            try self.releaseActiveExecution();
            self.state = .idle;
            try self.releasePreparedExecution();
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
            try self.releaseActiveExecution();
            self.state = .idle;
        }

        pub fn close(self: *Self) runtime_error.Error!void {
            try self.requireOwner();
            if (self.state != .idle) return error.InvalidState;
            try self.releasePreparedExecution();
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
            if (self.state != .idle) {
                self.context.abortProof() catch |err| {
                    first_error = err;
                };
                self.releaseActiveExecution() catch |err| {
                    if (first_error == null) first_error = err;
                };
                self.state = .idle;
            }
            self.releasePreparedExecution() catch |err| {
                if (first_error == null) first_error = err;
            };
            self.releaseCachedFunctions() catch |err| {
                if (first_error == null) first_error = err;
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

        fn releasePreparedExecution(self: *Self) runtime_error.Error!void {
            try self.requireOwner();
            if (self.state != .idle) return error.InvalidState;
            try self.execution_cache.deinit(&self.context);
        }

        fn releaseActiveExecution(self: *Self) runtime_error.Error!void {
            const key = self.active_execution_key orelse return;
            try self.execution_cache.releaseArena(key);
            self.active_execution_key = null;
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
