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
        pub const supports_selected_construction = provider == .nvidia_cuda and
            @hasDecl(Api, "stwo_exec_context_create_options") and
            @hasDecl(Api, "stwo_cuda_execution_provider") and
            @hasDecl(AotApi, "stwo_native_aot_loader_create") and
            @hasDecl(Api, "stwo_exec_context_destroy") and
            @hasDecl(AotApi, "stwo_native_aot_loader_destroy");

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
        teardown_pending: bool = false,

        pub const Selection = struct {
            device_ordinal: u32,
            device_uuid: [16]u8,

            pub fn validate(self: Selection, accepted_sms: []const u32) runtime_error.Error!void {
                if (self.device_ordinal == std.math.maxInt(u32) or std.mem.allEqual(u8, &self.device_uuid, 0)) return error.InvalidDeviceOrdinal;
                if (accepted_sms.len == 0) return error.DeviceArchitectureMismatch;
            }

            /// Metadata admission only. A session is constructed separately
            /// from genuine selected Context and original AOT loader calls.
            pub fn requireObserved(self: Selection, accepted_sms: []const u32, device: types.DeviceSnapshot, platform: types.PlatformSnapshot) runtime_error.Error!void {
                try self.validate(accepted_sms);
                try validateObserved(accepted_sms, self, device, platform);
            }
        };

        pub const OpeningOwner = struct {
            context: Context.Construction,
            aot_loader: ?*anyopaque = null,
            owner_thread_id: std.Thread.Id,
            selected: Selection,

            pub fn hasResources(self: *const OpeningOwner) bool {
                return self.aot_loader != null or switch (self.context) {
                    .ready => |owner| owner.handle != null,
                    .failed => |failure| failure.teardown != null,
                    .released => false,
                };
            }

            pub fn requireOwner(self: *const OpeningOwner) runtime_error.Error!void {
                if (self.owner_thread_id == 0 or self.owner_thread_id != std.Thread.getCurrentId()) return error.ThreadOwnershipViolation;
            }

            pub fn deinit(self: *OpeningOwner) runtime_error.Error!void {
                try self.requireOwner();
                if (self.aot_loader) |loader| {
                    if (comptime @hasDecl(AotApi, "stwo_native_aot_loader_destroy")) {
                        try runtime_error.check(AotApi.stwo_native_aot_loader_destroy(loader));
                        self.aot_loader = null;
                    } else return error.InvalidState;
                }
                if (comptime @hasDecl(Api, "stwo_exec_context_destroy")) {
                    try self.context.deinit();
                } else if (self.hasResources()) return error.InvalidState;
            }
        };

        pub const Construction = union(enum) {
            ready: Self,
            failed: struct { cause: runtime_error.Error, cleanup: ?OpeningOwner = null },
            released: void,

            pub fn hasResources(self: *const Construction) bool {
                return switch (self.*) {
                    .ready => |owner| owner.context.handle != null or owner.aot_loader != null,
                    .failed => |failure| if (failure.cleanup) |*cleanup| cleanup.hasResources() else false,
                    .released => false,
                };
            }

            pub fn deinit(self: *Construction) runtime_error.Error!void {
                switch (self.*) {
                    .ready => |*owner| {
                        if (comptime supports_selected_construction) {
                            try owner.abort();
                            self.* = .released;
                        } else return error.InvalidState;
                    },
                    .failed => |*failure| if (failure.cleanup) |*cleanup| {
                        try cleanup.deinit();
                        failure.cleanup = null;
                    },
                    .released => {},
                }
            }
        };

        const Admission = struct {
            device: types.DeviceSnapshot,
            platform: types.PlatformSnapshot,
            build_identity: [32]u8,
            aot_entries: usize,
        };

        fn validateDevice(accepted_sms: []const u32, selected: ?Selection, device: types.DeviceSnapshot) runtime_error.Error!void {
            if (device.count == 0) return error.DeviceUnavailable;
            if (device.current >= device.count) return error.InvalidDeviceOrdinal;
            if (selected) |expected| if (device.current != expected.device_ordinal) return error.InvalidDeviceOrdinal;
            const sm = device_admission.sm(device) catch return error.InvalidDeviceArchitecture;
            if (!device_admission.contains(accepted_sms, sm)) return error.DeviceArchitectureMismatch;
        }

        fn validateObserved(accepted_sms: []const u32, selected: ?Selection, device: types.DeviceSnapshot, platform: types.PlatformSnapshot) runtime_error.Error!void {
            try validateDevice(accepted_sms, selected, device);
            if (!platform.isSane() or platform.device_ordinal != device.current) return error.InvalidDeviceOrdinal;
            if (selected) |expected| if (!std.mem.eql(u8, &platform.uuid, &expected.device_uuid)) return error.InvalidDeviceOrdinal;
        }

        fn admitCurrent(accepted_sms: []const u32, selected: ?Selection) runtime_error.Error!Admission {
            if (Api.stwo_cuda_execution_provider() != @intFromEnum(provider))
                return error.ExecutionProviderMismatch;
            var device = types.DeviceSnapshot{};
            try runtime_error.check(Api.stwo_cuda_device_snapshot(
                &device.count,
                &device.current,
                &device.sm_major,
                &device.sm_minor,
            ));
            // Preserve original device/architecture rejection before probing
            // platform metadata. The selected path adds exact ordinal/UUID pins.
            try validateDevice(accepted_sms, selected, device);
            var platform = types.PlatformSnapshot{};
            try runtime_error.check(Api.stwo_cuda_platform_snapshot(&platform));
            try validateObserved(accepted_sms, selected, device, platform);

            var build_identity = [_]u8{0} ** 32;
            try runtime_error.check(Api.stwo_static_cuda_module_build_identity(
                &build_identity,
            ));
            if (std.mem.allEqual(u8, &build_identity, 0))
                return error.BuildIdentityAbsent;
            const aot_entries = Api.stwo_zig_cuda_aot_entry_count();
            if (aot_entries == 0) return error.AotPackAbsent;

            return .{ .device = device, .platform = platform, .build_identity = build_identity, .aot_entries = aot_entries };
        }

        pub fn open(accepted_sms: []const u32) runtime_error.Error!Self {
            const admitted = try admitCurrent(accepted_sms, null);
            var context = try Context.open();
            errdefer context.close() catch {};
            var aot_loader: ?*anyopaque = null;
            try runtime_error.check(AotApi.stwo_native_aot_loader_create(context.handle.?, &aot_loader));
            return .{
                .context = context,
                .device = admitted.device,
                .platform = admitted.platform,
                .build_identity = admitted.build_identity,
                .aot_entries = admitted.aot_entries,
                .aot_loader = aot_loader orelse return error.AotPackAbsent,
                .owner_thread_id = std.Thread.getCurrentId(),
            };
        }

        /// Independent selected-device pins; one physical proof lane only.
        /// Cleanup ownership is returned even after repeated native failure.
        pub fn openSelected(accepted_sms: []const u32, selected: Selection) Construction {
            selected.validate(accepted_sms) catch |err| return .{ .failed = .{ .cause = err } };
            if (comptime provider != .nvidia_cuda) return .{ .failed = .{ .cause = error.ExecutionProviderMismatch } };
            if (comptime supports_selected_construction) {
                return openSelectedWithApis(accepted_sms, selected);
            } else return .{ .failed = .{ .cause = error.InvalidState } };
        }

        fn failedOpening(cause: runtime_error.Error, opening: OpeningOwner) Construction {
            return .{ .failed = .{ .cause = cause, .cleanup = if (opening.hasResources()) opening else null } };
        }

        fn openSelectedWithApis(accepted_sms: []const u32, selected: Selection) Construction {
            if (Api.stwo_cuda_execution_provider() != @intFromEnum(provider)) return .{ .failed = .{ .cause = error.ExecutionProviderMismatch } };
            var opening = OpeningOwner{
                .context = Context.openOptions(.{ .device_ordinal = selected.device_ordinal, .lane_count = 1, .dependency_capacity = 0 }),
                .owner_thread_id = std.Thread.getCurrentId(),
                .selected = selected,
            };
            switch (opening.context) {
                .failed => |failure| return failedOpening(failure.cause, opening),
                .released => return failedOpening(error.InvalidState, opening),
                .ready => |*context| {
                    if (context.device != selected.device_ordinal or context.lane_count != 1 or context.identity == 0 or context.teardown_pending or context.owner_thread_id != opening.owner_thread_id) return failedOpening(error.InvalidDeviceOrdinal, opening);
                    const admitted = admitCurrent(accepted_sms, selected) catch |err| return failedOpening(err, opening);
                    runtime_error.check(AotApi.stwo_native_aot_loader_create(context.handle.?, &opening.aot_loader)) catch |err| return failedOpening(err, opening);
                    const loader = opening.aot_loader orelse return failedOpening(error.AotPackAbsent, opening);
                    const result = Self{
                        .context = context.*,
                        .device = admitted.device,
                        .platform = admitted.platform,
                        .build_identity = admitted.build_identity,
                        .aot_entries = admitted.aot_entries,
                        .aot_loader = loader,
                        .owner_thread_id = opening.owner_thread_id,
                    };
                    opening.context = .released;
                    opening.aot_loader = null;
                    return .{ .ready = result };
                },
            }
        }

        pub fn beginProof(self: *Self) runtime_error.Error!void {
            try self.requireOwner();
            if (self.state != .idle or self.teardown_pending or self.active_execution_key != null)
                return error.InvalidState;
            try self.context.beginProof();
            self.state = .open;
        }

        /// Process-service observations. These expose lifecycle and cache
        /// facts without granting access to CUDA handles or mutating LRU age.
        pub fn isReady(self: *const Self) bool {
            return self.owner_thread_id == std.Thread.getCurrentId() and
                self.state == .idle and !self.teardown_pending and
                self.active_execution_key == null and
                self.context.active_stage == null and
                self.context.synchronized;
        }

        pub fn isClosed(self: *const Self) bool {
            return self.owner_thread_id == std.Thread.getCurrentId() and self.state == .closed and self.context.handle == null and self.aot_loader == null;
        }

        pub fn executionLaneCount(self: *const Self) u32 {
            return self.context.lane_count;
        }

        pub fn hasPreparedExecution(
            self: *const Self,
            cache_key: [32]u8,
        ) bool {
            return self.state == .idle and !self.teardown_pending and
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
            if (self.state != .idle or self.teardown_pending) return error.InvalidState;
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

        /// Dispatch admission for the physically owned coordination stream.
        /// Additional planned lanes stay rejected until handles, dependency
        /// events and AOT/graph routing are actually admitted end to end.
        pub fn admitScheduledNode(self: *const Self, stage: telemetry.Stage, stream_index: u8) runtime_error.Error!void {
            try self.requireOwner();
            if (self.state != .open) return error.InvalidState;
            if (self.context.handle == null) return error.ContextClosed;
            if (self.context.active_stage != stage) return error.StageOrderViolation;
            if (self.context.lane_count != 1 or stream_index != 0 or stream_index >= self.context.lane_count) return error.InvalidExecutionLaneCount;
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
            try self.close();
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
            self.teardown_pending = true;
            try self.releasePreparedExecution();
            try self.releaseCachedFunctions();
            if (self.aot_loader) |loader| {
                try runtime_error.check(AotApi.stwo_native_aot_loader_destroy(loader));
                self.aot_loader = null;
            }
            try self.context.close();
            self.state = .closed;
        }

        pub fn abort(self: *Self) runtime_error.Error!void {
            try self.requireOwner();
            if (self.state == .closed) return error.InvalidState;
            if (self.state != .idle) {
                try self.context.abortProof();
                try self.releaseActiveExecution();
                self.state = .idle;
            }
            self.teardown_pending = true;
            try self.releasePreparedExecution();
            try self.releaseCachedFunctions();
            if (self.aot_loader) |loader| {
                try runtime_error.check(AotApi.stwo_native_aot_loader_destroy(loader));
                self.aot_loader = null;
            }
            try self.context.abort();
            self.state = .closed;
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
